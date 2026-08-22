from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.core.security import get_current_user_optional
from app.db.session import Base, get_db
from app.models.user import User


TLS_HEADERS = {"X-Rdesk-Client-TLS": "verified"}
NODE_ID = "relay-ap-east-1"


class AsyncSessionShim:
    def __init__(self, session: Session) -> None:
        self.session = session

    def add(self, instance: object) -> None:
        self.session.add(instance)

    def add_all(self, instances: list[object]) -> None:
        self.session.add_all(instances)

    async def get(self, *args: object, **kwargs: object) -> object:
        return self.session.get(*args, **kwargs)

    async def scalar(self, *args: object, **kwargs: object) -> object:
        return self.session.scalar(*args, **kwargs)

    async def scalars(self, *args: object, **kwargs: object) -> object:
        return self.session.scalars(*args, **kwargs)

    async def execute(self, *args: object, **kwargs: object) -> object:
        return self.session.execute(*args, **kwargs)

    async def flush(self) -> None:
        self.session.flush()

    async def commit(self) -> None:
        self.session.commit()

    async def rollback(self) -> None:
        self.session.rollback()

    async def refresh(self, instance: object) -> None:
        self.session.refresh(instance)


def _ca_material(
    *,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    key_cert_sign: bool | None = None,
) -> tuple[str, str, x509.Certificate, ed25519.Ed25519PrivateKey]:
    key = ed25519.Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MRD test CA")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - timedelta(minutes=1))
        .not_valid_after(not_after or now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    )
    if key_cert_sign is not None:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=key_cert_sign,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    certificate = builder.sign(key, algorithm=None)
    return (
        certificate.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
        certificate,
        key,
    )


def _csr(
    node_id: str,
    *,
    key: ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey | None = None,
) -> tuple[str, ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey]:
    signing_key = key or ed25519.Ed25519PrivateKey.generate()
    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)]))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(f"urn:mrd:relay:{node_id}")]
            ),
            critical=False,
        )
    )
    algorithm = None if isinstance(signing_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    csr = builder.sign(signing_key, algorithm)
    return csr.public_bytes(serialization.Encoding.PEM).decode(), signing_key


def _canonical_request(
    method: str,
    path: str,
    node_id: str,
    timestamp: int,
    sequence: int,
    body: bytes,
) -> bytes:
    values = [
        method.upper().encode("ascii"),
        path.encode("ascii"),
        node_id.encode("ascii"),
        str(timestamp).encode("ascii"),
        str(sequence).encode("ascii"),
        hashlib.sha256(body).digest(),
    ]
    encoded = bytearray(b"MRD_RELAY_REQUEST_V1\x00")
    for value in values:
        encoded.extend(len(value).to_bytes(4, "big"))
        encoded.extend(value)
    return bytes(encoded)


def _heartbeat_request(
    key: ed25519.Ed25519PrivateKey,
    fingerprint: str,
    *,
    node_id: str = NODE_ID,
    sequence: int = 1,
    timestamp: int | None = None,
    payload: dict[str, object] | None = None,
    path: str | None = None,
    method: str = "POST",
) -> tuple[bytes, dict[str, str]]:
    timestamp = timestamp or int(time.time())
    route_path = path or f"/api/v1/relays/{node_id}/heartbeat"
    body = json.dumps(
        payload
        or {
            "active_allocations": 1,
            "current_egress_bps": 1024,
            "endpoints": ["turn:relay.example.test:3478?transport=udp"],
        },
        separators=(",", ":"),
    ).encode()
    signature = key.sign(
        _canonical_request(method, route_path, node_id, timestamp, sequence, body)
    )
    headers = {
        **TLS_HEADERS,
        "X-Rdesk-Client-Cert-Sha256": fingerprint,
        "X-Relay-Node-Id": node_id,
        "X-Relay-Timestamp": str(timestamp),
        "X-Relay-Sequence": str(sequence),
        "X-Relay-Signature": base64.b64encode(signature).decode(),
        "Content-Type": "application/json",
    }
    return body, headers


def _error_code(response: object) -> str:
    return response.json()["detail"]["code"]  # type: ignore[attr-defined,no-any-return]


@pytest.fixture
def api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, object]:
    database = tmp_path / "relay-api.sqlite3"
    engine = create_engine(
        f"sqlite:///{database}",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)

    ca_certificate, ca_key, _, _ = _ca_material()
    monkeypatch.setitem(settings.__dict__, "trusted_mtls_proxy", "127.0.0.1,::1")
    monkeypatch.setitem(settings.__dict__, "relay_ca_certificate_pem", ca_certificate)
    monkeypatch.setitem(settings.__dict__, "relay_ca_private_key_pem", ca_key)
    monkeypatch.setitem(
        settings.__dict__, "relay_enrollment_token_pepper", "22" * 32
    )
    monkeypatch.setitem(settings.__dict__, "relay_max_clock_skew_seconds", 30)

    admin = User(
        id="admin-id",
        username="admin",
        email="admin@example.test",
        password_hash="unused",
        role="admin",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    async def override_db():
        with Session(engine, expire_on_commit=False) as session:
            yield AsyncSessionShim(session)

    async def override_user() -> User:
        return admin

    app = FastAPI()
    try:
        from app.api.v1.relays import router as relay_router
    except ModuleNotFoundError:
        relay_router = None
    if relay_router is not None:
        app.include_router(relay_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user_optional] = override_user
    client = TestClient(app, client=("127.0.0.1", 41000))
    with client:
        yield client, engine
    engine.dispose()


def _issue_token(client: TestClient) -> str:
    response = client.post(
        "/api/v1/relays/enrollment-tokens", json={"ttl_seconds": 300}
    )
    assert response.status_code == 201, response.text
    token = response.json()["token"]
    assert len(token) >= 40
    return token


def _enroll(
    client: TestClient,
    *,
    node_id: str = NODE_ID,
    csr_pem: str | None = None,
) -> tuple[ed25519.Ed25519PrivateKey, str]:
    token = _issue_token(client)
    if csr_pem is None:
        csr_pem, key = _csr(node_id)
        assert isinstance(key, ed25519.Ed25519PrivateKey)
    else:
        key = ed25519.Ed25519PrivateKey.generate()
    response = client.post(
        "/api/v1/relays/enroll",
        headers=TLS_HEADERS,
        json={
            "token": token,
            "node_id": node_id,
            "region": "ap-east",
            "failure_domain": "rack-a",
            "endpoints": ["turn:relay.example.test:3478?transport=udp"],
            "max_allocations": 100,
            "max_egress_bps": 1_000_000,
            "csr_pem": csr_pem,
        },
    )
    assert response.status_code == 202, response.text
    assert response.json() == {"node_id": node_id, "status": "pending"}
    return key, token


def _approve(client: TestClient, node_id: str = NODE_ID) -> tuple[str, str]:
    response = client.post(f"/api/v1/relays/{node_id}/approve")
    assert response.status_code == 200, response.text
    return response.json()["certificate_pem"], response.json()["fingerprint"]


def test_relay_routes_are_registered(api: tuple[TestClient, object]) -> None:
    client, _ = api
    response = client.post(
        "/api/v1/relays/enroll", headers=TLS_HEADERS, json={}
    )
    assert response.status_code != 404


def test_enrollment_is_tls_proxy_bound_one_use_pending_and_csr_bound(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    token = _issue_token(client)
    csr_pem, _ = _csr(NODE_ID)
    payload = {
        "token": token,
        "node_id": NODE_ID,
        "region": "ap-east",
        "failure_domain": "rack-a",
        "endpoints": ["turn:relay.example.test:3478?transport=udp"],
        "max_allocations": 100,
        "max_egress_bps": 1_000_000,
        "csr_pem": csr_pem,
    }

    missing_tls = client.post("/api/v1/relays/enroll", json=payload)
    assert missing_tls.status_code == 403
    assert _error_code(missing_tls) == "relay_proxy_required"

    accepted = client.post(
        "/api/v1/relays/enroll", headers=TLS_HEADERS, json=payload
    )
    assert accepted.status_code == 202
    assert accepted.json()["status"] == "pending"
    assert "certificate_pem" not in accepted.json()

    reused = client.post(
        "/api/v1/relays/enroll",
        headers=TLS_HEADERS,
        json=payload,
    )
    assert reused.status_code == 409
    assert _error_code(reused) == "relay_enrollment_already_used"


@pytest.mark.parametrize("kind", ["wrong_identity", "rsa_key", "tampered"])
def test_enrollment_rejects_invalid_csr_pop_identity_and_key(
    api: tuple[TestClient, object], kind: str
) -> None:
    client, _ = api
    token = _issue_token(client)
    if kind == "wrong_identity":
        csr_pem, _ = _csr("some-other-node")
    elif kind == "rsa_key":
        csr_pem, _ = _csr(NODE_ID, key=rsa.generate_private_key(65537, 2048))
    else:
        csr_pem, _ = _csr(NODE_ID)
        csr_pem = csr_pem.replace("A", "B", 1)
    response = client.post(
        "/api/v1/relays/enroll",
        headers=TLS_HEADERS,
        json={
            "token": token,
            "node_id": NODE_ID,
            "region": "ap-east",
            "failure_domain": "rack-a",
            "endpoints": ["turn:relay.example.test:3478?transport=udp"],
            "max_allocations": 100,
            "max_egress_bps": 1_000_000,
            "csr_pem": csr_pem,
        },
    )
    assert response.status_code == 400
    assert _error_code(response) == "relay_enrollment_invalid"


def test_approval_issues_node_bound_short_lived_client_certificate(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    key, _ = _enroll(client)
    approval = client.post(f"/api/v1/relays/{NODE_ID}/approve")
    assert approval.status_code == 200, approval.text
    certificate_pem = approval.json()["certificate_pem"]
    fingerprint = approval.json()["fingerprint"]

    certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
    ca_certificate = x509.load_pem_x509_certificate(
        approval.json()["ca_certificate_pem"].encode()
    )
    assert certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == NODE_ID
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.UniformResourceIdentifier) == [
        f"urn:mrd:relay:{NODE_ID}"
    ]
    eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    assert certificate.serial_number > 0
    assert certificate.not_valid_after_utc - certificate.not_valid_before_utc <= timedelta(hours=2)
    assert certificate.not_valid_before_utc >= ca_certificate.not_valid_before_utc
    assert certificate.not_valid_after_utc <= ca_certificate.not_valid_after_utc
    assert certificate.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ) == key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert fingerprint == "sha256:" + hashlib.sha256(
        certificate.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def test_approval_fails_closed_without_or_with_mismatched_ca(
    api: tuple[TestClient, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = api
    _enroll(client)
    monkeypatch.setattr(settings, "relay_ca_private_key_pem", "")
    absent = client.post(f"/api/v1/relays/{NODE_ID}/approve")
    assert absent.status_code == 503
    assert _error_code(absent) == "relay_ca_unavailable"

    _, other_key, _, _ = _ca_material()
    monkeypatch.setattr(settings, "relay_ca_private_key_pem", other_key)
    mismatch = client.post(f"/api/v1/relays/{NODE_ID}/approve")
    assert mismatch.status_code == 503
    assert _error_code(mismatch) == "relay_ca_unavailable"


@pytest.mark.parametrize(
    "ca_kind", ["expired", "not_yet_valid", "no_key_cert_sign", "near_expiry"]
)
def test_approval_rejects_invalid_ca_time_usage_and_remaining_lifetime(
    api: tuple[TestClient, object],
    monkeypatch: pytest.MonkeyPatch,
    ca_kind: str,
) -> None:
    client, _ = api
    _enroll(client)
    now = datetime.now(UTC)
    if ca_kind == "expired":
        material = _ca_material(
            not_before=now - timedelta(days=2),
            not_after=now - timedelta(days=1),
            key_cert_sign=True,
        )
    elif ca_kind == "not_yet_valid":
        material = _ca_material(
            not_before=now + timedelta(hours=1),
            not_after=now + timedelta(days=1),
            key_cert_sign=True,
        )
    elif ca_kind == "no_key_cert_sign":
        material = _ca_material(key_cert_sign=False)
    else:
        material = _ca_material(
            not_before=now - timedelta(minutes=1),
            not_after=now + timedelta(minutes=30),
            key_cert_sign=True,
        )
    monkeypatch.setattr(settings, "relay_ca_certificate_pem", material[0])
    monkeypatch.setattr(settings, "relay_ca_private_key_pem", material[1])
    response = client.post(f"/api/v1/relays/{NODE_ID}/approve")
    assert response.status_code == 503
    assert _error_code(response) == "relay_ca_unavailable"


def test_heartbeat_requires_proxy_certificate_and_ed25519_signature(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    key, _ = _enroll(client)
    _, fingerprint = _approve(client)
    body, headers = _heartbeat_request(key, fingerprint)

    accepted = client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat", content=body, headers=headers
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["sequence"] == 1
    assert accepted.json()["state"] == "available"

    replay = client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat", content=body, headers=headers
    )
    assert replay.status_code == 409
    assert _error_code(replay) == "relay_heartbeat_replayed"

    without_cert = {k: v for k, v in headers.items() if k.lower() != "x-rdesk-client-cert-sha256"}
    no_cert = client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat", content=body, headers=without_cert
    )
    assert no_cert.status_code == 401
    assert _error_code(no_cert) == "relay_certificate_invalid"


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("wrong_body", "relay_signature_invalid"),
        ("wrong_path", "relay_signature_invalid"),
        ("wrong_node", "relay_signature_invalid"),
        ("bad_signature", "relay_signature_invalid"),
        ("stale", "relay_clock_stale"),
    ],
)
def test_heartbeat_signature_binds_method_path_node_time_sequence_and_body(
    api: tuple[TestClient, object], mutation: str, expected: str
) -> None:
    client, _ = api
    key, _ = _enroll(client)
    _, fingerprint = _approve(client)
    if mutation == "wrong_path":
        body, headers = _heartbeat_request(key, fingerprint, path="/wrong")
    elif mutation == "wrong_node":
        body, headers = _heartbeat_request(key, fingerprint, node_id="relay-other")
        headers["X-Relay-Node-Id"] = "relay-other"
    elif mutation == "stale":
        body, headers = _heartbeat_request(
            key, fingerprint, timestamp=int(time.time()) - 120
        )
    else:
        body, headers = _heartbeat_request(key, fingerprint)
    if mutation == "wrong_body":
        body += b" "
    if mutation == "bad_signature":
        headers["X-Relay-Signature"] = base64.b64encode(b"x" * 64).decode()

    response = client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat", content=body, headers=headers
    )
    assert response.status_code in {400, 401}
    assert _error_code(response) == expected


@pytest.mark.parametrize(
    "payload",
    [
        {
            "active_allocations": -1,
            "current_egress_bps": 0,
            "endpoints": ["turn:relay.example.test:3478"],
        },
        {
            "active_allocations": 2**31,
            "current_egress_bps": 0,
            "endpoints": ["turn:relay.example.test:3478"],
        },
        {
            "active_allocations": 0,
            "current_egress_bps": -1,
            "endpoints": ["turn:relay.example.test:3478"],
        },
        {
            "active_allocations": 0,
            "current_egress_bps": 2**63,
            "endpoints": ["turn:relay.example.test:3478"],
        },
        {
            "active_allocations": True,
            "current_egress_bps": 0,
            "endpoints": ["turn:relay.example.test:3478"],
        },
        {
            "active_allocations": 0,
            "current_egress_bps": "100",
            "endpoints": ["turn:relay.example.test:3478"],
        },
        {
            "active_allocations": 0,
            "current_egress_bps": 0,
            "endpoints": ["http://not-turn.example.test"],
        },
        {
            "active_allocations": 0,
            "current_egress_bps": 0,
            "endpoints": ["turn:relay.example.test:3478"] * 5,
        },
    ],
)
def test_heartbeat_rejects_metrics_and_endpoints_with_stable_code(
    api: tuple[TestClient, object], payload: dict[str, object]
) -> None:
    client, _ = api
    key, _ = _enroll(client)
    _, fingerprint = _approve(client)
    body, headers = _heartbeat_request(key, fingerprint, payload=payload)
    response = client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat", content=body, headers=headers
    )
    assert response.status_code == 400
    assert _error_code(response) == "relay_metrics_invalid"
    assert "sql" not in response.text.lower()


def test_concurrent_identical_heartbeats_allow_exactly_one(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    key, _ = _enroll(client)
    _, fingerprint = _approve(client)
    body, headers = _heartbeat_request(key, fingerprint)
    barrier = threading.Barrier(2)

    def send() -> int:
        barrier.wait()
        return client.post(
            f"/api/v1/relays/{NODE_ID}/heartbeat", content=body, headers=headers
        ).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(send) for _ in range(2)]
        statuses = sorted(future.result() for future in futures)
    assert statuses == [200, 409]


def test_revoked_node_cannot_heartbeat_or_resume(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    key, _ = _enroll(client)
    _, fingerprint = _approve(client)
    assert client.post(f"/api/v1/relays/{NODE_ID}/revoke").status_code == 200
    body, headers = _heartbeat_request(key, fingerprint)
    heartbeat = client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat", content=body, headers=headers
    )
    assert heartbeat.status_code == 403
    assert _error_code(heartbeat) == "relay_node_revoked"
    resume = client.post(f"/api/v1/relays/{NODE_ID}/resume")
    assert resume.status_code == 409
    assert _error_code(resume) == "relay_node_revoked"


@pytest.mark.parametrize(
    ("auth_kind", "status_code", "reason_code"),
    [
        ("wrong_fingerprint", 401, "relay_certificate_invalid"),
        ("wrong_signature", 401, "relay_signature_invalid"),
        ("fully_valid", 403, "relay_node_revoked"),
    ],
)
def test_revoked_state_is_disclosed_only_after_full_authentication(
    api: tuple[TestClient, object],
    auth_kind: str,
    status_code: int,
    reason_code: str,
) -> None:
    from app.models.relay_audit_event import RelayAuditEvent
    from app.models.relay_node import RelayNode

    client, engine = api
    key, _ = _enroll(client)
    _, fingerprint = _approve(client)
    assert client.post(f"/api/v1/relays/{NODE_ID}/revoke").status_code == 200
    body, headers = _heartbeat_request(key, fingerprint)
    if auth_kind == "wrong_fingerprint":
        headers["X-Rdesk-Client-Cert-Sha256"] = "sha256:" + "ab" * 32
    elif auth_kind == "wrong_signature":
        headers["X-Relay-Signature"] = base64.b64encode(b"x" * 64).decode()
    response = client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat", content=body, headers=headers
    )
    assert response.status_code == status_code
    assert _error_code(response) == reason_code
    with Session(engine) as session:
        node = session.get(RelayNode, NODE_ID)
        assert node is not None
        assert node.heartbeat_sequence == 0
        heartbeat_events = list(
            session.scalars(
                select(RelayAuditEvent).where(
                    RelayAuditEvent.action == "relay_heartbeat_recorded"
                )
            )
        )
    assert heartbeat_events == []


def test_expired_node_certificate_is_rejected(
    api: tuple[TestClient, object],
) -> None:
    from app.models.relay_node_registration import RelayNodeRegistration

    client, engine = api
    key, _ = _enroll(client)
    _, fingerprint = _approve(client)
    with Session(engine) as session:
        registration = session.get(RelayNodeRegistration, NODE_ID)
        assert registration is not None
        registration.certificate_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    body, headers = _heartbeat_request(key, fingerprint)
    response = client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat", content=body, headers=headers
    )
    assert response.status_code == 401
    assert _error_code(response) == "relay_certificate_invalid"


def test_untrusted_direct_peer_cannot_spoof_proxy_headers(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    token = _issue_token(client)
    csr_pem, _ = _csr(NODE_ID)
    app = client.app
    with TestClient(app, client=("203.0.113.7", 41000)) as public_client:
        response = public_client.post(
            "/api/v1/relays/enroll",
            headers={
                **TLS_HEADERS,
                "X-Forwarded-For": "127.0.0.1",
                "X-Rdesk-Client-Cert-Sha256": "sha256:" + "aa" * 32,
            },
            json={
                "token": token,
                "node_id": NODE_ID,
                "region": "ap-east",
                "failure_domain": "rack-a",
                "endpoints": ["turn:relay.example.test:3478"],
                "max_allocations": 100,
                "max_egress_bps": 1_000_000,
                "csr_pem": csr_pem,
            },
        )
    assert response.status_code == 403
    assert _error_code(response) == "relay_proxy_required"


def test_openapi_documents_relay_authentication_headers_and_stable_errors(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    schema = client.get("/openapi.json").json()
    heartbeat = schema["paths"][f"/api/v1/relays/{{node_id}}/heartbeat"]["post"]
    header_names = {
        parameter["name"]
        for parameter in heartbeat.get("parameters", [])
        if parameter["in"] == "header"
    }
    assert {
        "X-Rdesk-Client-Cert-Sha256",
        "X-Relay-Node-Id",
        "X-Relay-Signature",
        "X-Relay-Timestamp",
        "X-Relay-Sequence",
    }.issubset(header_names)
    security_schemes = schema["components"]["securitySchemes"]
    assert security_schemes["TrustedMTLSProxy"]["in"] == "header"
    assert security_schemes["RelayEd25519"]["in"] == "header"
    assert heartbeat["security"] == [
        {"TrustedMTLSProxy": [], "RelayEd25519": []}
    ]

    enrollment = schema["paths"]["/api/v1/relays/enroll"]["post"]
    assert enrollment["security"] == [{"TrustedMTLSProxy": []}]
    assert "proxy-only" in enrollment["description"].lower()
    assert "X-Rdesk-Client-TLS" in enrollment["description"]

    stable_responses = {"400", "401", "403", "409", "503"}
    for path, operations in schema["paths"].items():
        if not path.startswith("/api/v1/relays"):
            continue
        for method, operation in operations.items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            assert stable_responses.issubset(operation["responses"])
            for code in stable_responses:
                response_schema = operation["responses"][code]["content"][
                    "application/json"
                ]["schema"]
                assert response_schema["$ref"].endswith("/RelayErrorResponse")
