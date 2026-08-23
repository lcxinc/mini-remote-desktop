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
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.core.response_security import SensitiveResponseCacheMiddleware
from app.core.security import get_current_user_optional
from app.db.session import Base, get_db
from app.models.user import User
from app.middleware.relay_node_boundary import RelayNodeBoundaryMiddleware
from app.schemas.relay import (
    RelayEnrollmentRequest,
    RelayHeartbeatResponse,
    RelayNodeResponse,
)


TLS_HEADERS = {"X-Rdesk-Client-TLS": "verified"}
NODE_ID = "relay-ap-east-1"
NODE_TURN_SECRET = base64.urlsafe_b64encode(b"node-held-turn-secret-material!!").rstrip(
    b"="
).decode("ascii")


def _approval_body(node_id: str = NODE_ID) -> dict[str, str]:
    return {
        "failure_domain": "rack-a",
        "physical_host_id": f"host-{node_id}",
    }


def test_new_enrollment_rejects_colon_node_id_but_legacy_outputs_remain_valid() -> None:
    with pytest.raises(ValidationError):
        RelayEnrollmentRequest(
            token="x" * 40,
            node_id="relay:new",
            region="ap-east",
            failure_domain="rack-a",
            endpoints=["turn:relay.example.test:3478?transport=udp"],
            max_allocations=10,
            max_egress_bps=1_000,
            csr_pem="x" * 100,
        )

    heartbeat = RelayHeartbeatResponse(
        node_id="relay:legacy",
        state="available",
        sequence=1,
        lease_expires_at=datetime.now(UTC),
    )
    node = RelayNodeResponse(
        node_id="relay:legacy",
        region="ap-east",
        failure_domain="rack:a",
        state="available",
        endpoints=["turn:relay.example.test:3478?transport=udp"],
        max_allocations=10,
        active_allocations=0,
        max_egress_bps=1_000,
        current_egress_bps=0,
        lease_expires_at=datetime.now(UTC),
        revoked_at=None,
    )

    assert heartbeat.node_id == "relay:legacy"
    assert node.node_id == "relay:legacy"
    assert node.failure_domain == "rack:a"


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
    monkeypatch.setitem(
        settings.__dict__,
        "relay_turn_secret_encryption_key",
        base64.b64encode(bytes.fromhex("33" * 32)).decode(),
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
    app.add_middleware(SensitiveResponseCacheMiddleware)
    app.add_middleware(
        RelayNodeBoundaryMiddleware, trusted_proxy=settings.trusted_mtls_proxy
    )
    try:
        from app.api.v1 import relays as relay_module
    except ModuleNotFoundError:
        relay_module = None
    if relay_module is not None:
        app.include_router(relay_module.router, prefix="/api/v1")
        relay_module.install_relay_openapi(app)
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
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"
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
            "turn_rest_secret": NODE_TURN_SECRET,
        },
    )
    assert response.status_code == 202, response.text
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"
    assert response.json()["node_id"] == node_id
    assert response.json()["status"] == "pending"
    assert len(response.json()["enrollment_id"]) == 36
    assert len(response.json()["receipt"]) >= 40
    setattr(
        client,
        "_relay_enrollment_delivery",
        (response.json()["enrollment_id"], response.json()["receipt"]),
    )
    return key, token


def _approve(client: TestClient, node_id: str = NODE_ID) -> tuple[str, str]:
    response = client.post(
        f"/api/v1/relays/{node_id}/approve", json=_approval_body(node_id)
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"node_id": node_id, "status": "approved"}
    enrollment_id, receipt = getattr(client, "_relay_enrollment_delivery")
    pickup = client.post(
        f"/api/v1/relays/enrollments/{enrollment_id}/pickup",
        headers={**TLS_HEADERS, "X-Relay-Enrollment-Receipt": receipt},
    )
    assert pickup.status_code == 200, pickup.text
    assert pickup.headers["cache-control"] == "no-store, private"
    assert pickup.headers["pragma"] == "no-cache"
    certificate_pem = pickup.json()["certificate_pem"]
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
    fingerprint = "sha256:" + hashlib.sha256(
        certificate.public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    return certificate_pem, fingerprint


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
        "turn_rest_secret": NODE_TURN_SECRET,
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
    assert reused.status_code == 202
    assert reused.json() == accepted.json()

    changed = dict(payload)
    changed["failure_domain"] = "rack-b"
    conflict = client.post(
        "/api/v1/relays/enroll", headers=TLS_HEADERS, json=changed
    )
    assert conflict.status_code == 409
    assert _error_code(conflict) == "relay_enrollment_already_used"


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
            "turn_rest_secret": NODE_TURN_SECRET,
        },
    )
    assert response.status_code == 400
    assert _error_code(response) == "relay_enrollment_invalid"


def test_approval_issues_node_bound_short_lived_client_certificate(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    key, _ = _enroll(client)
    certificate_pem, fingerprint = _approve(client)

    certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
    ca_certificate = x509.load_pem_x509_certificate(
        settings.relay_ca_certificate_pem.encode()
    )
    assert certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == NODE_ID
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.UniformResourceIdentifier) == [
        f"urn:mrd:relay:{NODE_ID}"
    ]
    eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert key_usage.digital_signature is True
    assert key_usage.key_cert_sign is False
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
    approval = client.post(
        f"/api/v1/relays/{NODE_ID}/approve", json=_approval_body()
    )
    assert approval.status_code == 200
    enrollment_id, receipt = getattr(client, "_relay_enrollment_delivery")
    monkeypatch.setattr(settings, "relay_ca_private_key_pem", "")
    absent = client.post(
        f"/api/v1/relays/enrollments/{enrollment_id}/pickup",
        headers={**TLS_HEADERS, "X-Relay-Enrollment-Receipt": receipt},
    )
    assert absent.status_code == 503
    assert _error_code(absent) == "relay_ca_unavailable"

    _, other_key, _, _ = _ca_material()
    monkeypatch.setattr(settings, "relay_ca_private_key_pem", other_key)
    mismatch = client.post(
        f"/api/v1/relays/enrollments/{enrollment_id}/pickup",
        headers={**TLS_HEADERS, "X-Relay-Enrollment-Receipt": receipt},
    )
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
    approval = client.post(
        f"/api/v1/relays/{NODE_ID}/approve", json=_approval_body()
    )
    assert approval.status_code == 200
    enrollment_id, receipt = getattr(client, "_relay_enrollment_delivery")
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
    response = client.post(
        f"/api/v1/relays/enrollments/{enrollment_id}/pickup",
        headers={**TLS_HEADERS, "X-Relay-Enrollment-Receipt": receipt},
    )
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
    assert accepted.json()["state"] == "unavailable"

    replay = client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat", content=body, headers=headers
    )
    assert replay.status_code == 409
    assert _error_code(replay) == "relay_heartbeat_replayed"


def test_node_requires_three_consecutive_healthy_heartbeats_to_recover(
    api: tuple[TestClient, object],
) -> None:
    from app.models.relay_node import RelayNode

    client, engine = api
    key, _ = _enroll(client)
    _, fingerprint = _approve(client)
    states: list[str] = []
    for sequence in (1, 2, 3, 4):
        body, headers = _heartbeat_request(
            key, fingerprint, sequence=sequence
        )
        response = client.post(
            f"/api/v1/relays/{NODE_ID}/heartbeat",
            content=body,
            headers=headers,
        )
        assert response.status_code == 200, response.text
        states.append(response.json()["state"])
    assert states == ["unavailable", "unavailable", "available", "available"]
    with Session(engine) as session:
        node = session.get(RelayNode, NODE_ID)
        assert node is not None
        assert node.healthy_heartbeat_streak == 3


def test_authenticated_heartbeat_persists_selection_metrics(
    api: tuple[TestClient, object],
) -> None:
    from app.models.relay_node import RelayNode

    client, engine = api
    key, _ = _enroll(client)
    _, fingerprint = _approve(client)
    body, headers = _heartbeat_request(
        key,
        fingerprint,
        payload={
            "active_allocations": 1,
            "current_egress_bps": 1024,
            "measured_rtt_ms": 37,
            "recent_failure_bps": 1250,
            "endpoints": ["turn:relay.example.test:3478?transport=udp"],
        },
    )
    response = client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat", content=body, headers=headers
    )
    assert response.status_code == 200, response.text
    with Session(engine) as session:
        node = session.get(RelayNode, NODE_ID)
        assert node is not None
        assert node.measured_rtt_ms == 37
        assert node.recent_failure_bps == 1250


def test_expired_lease_resume_and_drain_have_explicit_recovery_semantics(
    api: tuple[TestClient, object],
) -> None:
    from app.models.relay_node import RelayNode

    client, engine = api
    key, _ = _enroll(client)
    _, fingerprint = _approve(client)
    for sequence in (1, 2, 3):
        body, headers = _heartbeat_request(key, fingerprint, sequence=sequence)
        assert client.post(
            f"/api/v1/relays/{NODE_ID}/heartbeat",
            content=body,
            headers=headers,
        ).status_code == 200
    with Session(engine) as session:
        node = session.get(RelayNode, NODE_ID)
        assert node is not None
        node.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    body, headers = _heartbeat_request(key, fingerprint, sequence=4)
    expired = client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat", content=body, headers=headers
    )
    assert expired.json()["state"] == "unavailable"

    assert client.post(f"/api/v1/relays/{NODE_ID}/resume").status_code == 200
    with Session(engine) as session:
        node = session.get(RelayNode, NODE_ID)
        assert node is not None
        assert node.healthy_heartbeat_streak == 0
    assert client.post(f"/api/v1/relays/{NODE_ID}/drain").status_code == 200
    for sequence in (5, 6, 7):
        body, headers = _heartbeat_request(key, fingerprint, sequence=sequence)
        response = client.post(
            f"/api/v1/relays/{NODE_ID}/heartbeat",
            content=body,
            headers=headers,
        )
        assert response.json()["state"] == "draining"



@pytest.mark.parametrize(
    ("missing_header", "status_code", "reason_code"),
    [
        (
            "X-Rdesk-Client-Cert-Sha256",
            401,
            "relay_certificate_invalid",
        ),
        ("X-Relay-Node-Id", 401, "relay_signature_invalid"),
        ("X-Relay-Signature", 401, "relay_signature_invalid"),
        ("X-Relay-Timestamp", 401, "relay_signature_invalid"),
        ("X-Relay-Sequence", 401, "relay_signature_invalid"),
    ],
)
def test_missing_heartbeat_auth_header_has_stable_authentication_error(
    api: tuple[TestClient, object],
    missing_header: str,
    status_code: int,
    reason_code: str,
) -> None:
    client, _ = api
    key, _ = _enroll(client)
    _, fingerprint = _approve(client)
    body, headers = _heartbeat_request(key, fingerprint)
    headers = {
        name: value
        for name, value in headers.items()
        if name.lower() != missing_header.lower()
    }
    response = client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat", content=body, headers=headers
    )
    assert response.status_code == status_code
    assert _error_code(response) == reason_code


def test_missing_heartbeat_body_fields_return_stable_validation_error(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    key, _ = _enroll(client)
    _, fingerprint = _approve(client)
    body, headers = _heartbeat_request(
        key, fingerprint, payload={"active_allocations": 0}
    )
    response = client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat", content=body, headers=headers
    )
    assert response.status_code == 400
    assert _error_code(response) == "relay_metrics_invalid"


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
            "measured_rtt_ms": 2**32,
            "endpoints": ["turn:relay.example.test:3478"],
        },
        {
            "active_allocations": 0,
            "current_egress_bps": 0,
            "recent_failure_bps": 10_001,
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
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"
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


def test_untrusted_direct_peer_without_auth_headers_still_fails_proxy_boundary(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    with TestClient(
        client.app, client=("203.0.113.7", 41000)
    ) as public_client:
        response = public_client.post(
            f"/api/v1/relays/{NODE_ID}/heartbeat",
            json={
                "active_allocations": 0,
                "current_egress_bps": 0,
                "endpoints": ["turn:relay.example.test:3478"],
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
    expected_authentication_headers = {
        "X-Rdesk-Client-Cert-Sha256",
        "X-Relay-Node-Id",
        "X-Relay-Signature",
        "X-Relay-Timestamp",
        "X-Relay-Sequence",
    }
    header_names = {
        parameter["name"]
        for parameter in heartbeat.get("parameters", [])
        if parameter["in"] == "header"
    }
    assert expected_authentication_headers.issubset(header_names)
    authentication_headers = {
        parameter["name"]: parameter
        for parameter in heartbeat["parameters"]
        if parameter["in"] == "header"
        and parameter["name"] in expected_authentication_headers
    }
    for name in expected_authentication_headers:
        assert authentication_headers[name]["required"] is True
    security_schemes = schema["components"]["securitySchemes"]
    assert security_schemes["TrustedMTLSProxy"]["in"] == "header"
    assert security_schemes["RelayEd25519"]["in"] == "header"
    assert heartbeat["security"] == [
        {"TrustedMTLSProxy": [], "RelayEd25519": []}
    ]

    renewal = schema["paths"]["/api/v1/relays/{node_id}/renew"]["post"]
    renewal_headers = {
        parameter["name"]: parameter
        for parameter in renewal["parameters"]
        if parameter.get("in") == "header"
    }
    for name in (*authentication_headers, "X-Relay-Renewal-Id"):
        assert renewal_headers[name]["required"] is True
    assert renewal["security"] == [
        {"TrustedMTLSProxy": [], "RelayEd25519": []}
    ]

    pickup = schema["paths"][
        "/api/v1/relays/enrollments/{enrollment_id}/pickup"
    ]["post"]
    pickup_headers = {
        parameter["name"]: parameter
        for parameter in pickup["parameters"]
        if parameter.get("in") == "header"
    }
    for name in ("X-Rdesk-Client-TLS", "X-Relay-Enrollment-Receipt"):
        assert pickup_headers[name]["required"] is True
    assert pickup["security"] == [{"TrustedMTLSProxy": []}]

    enrollment = schema["paths"]["/api/v1/relays/enroll"]["post"]
    assert enrollment["security"] == [{"TrustedMTLSProxy": []}]
    assert "proxy-only" in enrollment["description"].lower()
    assert "X-Rdesk-Client-TLS" in enrollment["description"]

    stable_responses = {"400", "401", "403", "409", "413", "503"}
    for path, operations in schema["paths"].items():
        if not path.startswith("/api/v1/relays"):
            continue
        for method, operation in operations.items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            assert stable_responses.issubset(operation["responses"])
            assert "422" not in operation["responses"]
            for code in stable_responses:
                response_schema = operation["responses"][code]["content"][
                    "application/json"
                ]["schema"]
                assert response_schema["$ref"].endswith("/RelayErrorResponse")

    for action in ("drain", "resume", "revoke"):
        operation = schema["paths"][
            f"/api/v1/relays/{{node_id}}/{action}"
        ]["post"]
        error_schema = operation["responses"]["404"]["content"][
            "application/json"
        ]["schema"]
        assert error_schema["$ref"].endswith("/RelayErrorResponse")


def test_relay_openapi_filter_is_idempotent_and_scoped() -> None:
    from app.api.v1 import relays as relay_module

    install_openapi = relay_module.install_relay_openapi

    app = FastAPI()
    app.include_router(relay_module.router, prefix="/api/v1")

    @app.get("/outside/{count}")
    async def outside(count: int) -> dict[str, int]:
        return {"count": count}

    install_openapi(app)
    installed = app.openapi
    install_openapi(app)
    assert app.openapi is installed

    schema = app.openapi()
    assert "422" in schema["paths"]["/outside/{count}"]["get"]["responses"]
    for path, operations in schema["paths"].items():
        if not path.startswith("/api/v1/relays"):
            continue
        for method, operation in operations.items():
            if method in {"get", "post", "put", "patch", "delete"}:
                assert "422" not in operation["responses"]
    assert schema["components"]["securitySchemes"]["TrustedMTLSProxy"]
    heartbeat = schema["paths"][
        "/api/v1/relays/{node_id}/heartbeat"
    ]["post"]
    assert heartbeat["security"] == [
        {"TrustedMTLSProxy": [], "RelayEd25519": []}
    ]


def test_relay_openapi_filter_marks_exact_node_auth_headers_required() -> None:
    from app.api.v1.relays import install_relay_openapi

    authentication_headers = {
        "X-Rdesk-Client-Cert-Sha256",
        "X-Relay-Node-Id",
        "X-Relay-Signature",
        "X-Relay-Timestamp",
        "X-Relay-Sequence",
    }
    heartbeat_parameters = [
        {"name": name, "in": "header", "required": False}
        for name in authentication_headers
    ]
    heartbeat_parameters.append(
        {"name": "X-Unrelated", "in": "header", "required": False}
    )
    schema = {
        "paths": {
            "/api/v1/relays/{node_id}/heartbeat": {
                "post": {
                    "parameters": heartbeat_parameters,
                    "responses": {"200": {}, "422": {}},
                }
            },
            "/api/v1/relays/{node_id}/other": {
                "post": {
                    "parameters": [
                        {
                            "name": "X-Relay-Signature",
                            "in": "header",
                            "required": False,
                        }
                    ],
                    "responses": {"200": {}, "422": {}},
                }
            },
            "/api/v1/relays/{node_id}/renew": {
                "post": {
                    "parameters": [
                        *[
                            {"name": name, "in": "header", "required": False}
                            for name in authentication_headers
                        ],
                        {
                            "name": "X-Relay-Renewal-Id",
                            "in": "header",
                            "required": False,
                        },
                    ],
                    "responses": {"200": {}, "422": {}},
                }
            },
            "/api/v1/relays/enrollments/{enrollment_id}/pickup": {
                "post": {
                    "parameters": [
                        {
                            "name": "X-Rdesk-Client-TLS",
                            "in": "header",
                            "required": False,
                        },
                        {
                            "name": "X-Relay-Enrollment-Receipt",
                            "in": "header",
                            "required": False,
                        },
                    ],
                    "responses": {"200": {}, "422": {}},
                }
            },
        },
        "components": {"schemas": {"Preserved": {"type": "object"}}},
    }
    app = FastAPI()
    app.openapi = lambda: schema  # type: ignore[method-assign]
    install_relay_openapi(app)

    filtered = app.openapi()
    heartbeat = filtered["paths"][
        "/api/v1/relays/{node_id}/heartbeat"
    ]["post"]
    documented = {
        parameter["name"]: parameter
        for parameter in heartbeat["parameters"]
    }
    for name in authentication_headers:
        assert documented[name]["required"] is True
    assert documented["X-Unrelated"]["required"] is False
    other_signature = filtered["paths"][
        "/api/v1/relays/{node_id}/other"
    ]["post"]["parameters"][0]
    assert other_signature["required"] is False
    renewal_parameters = filtered["paths"][
        "/api/v1/relays/{node_id}/renew"
    ]["post"]["parameters"]
    assert all(parameter["required"] for parameter in renewal_parameters)
    pickup_parameters = filtered["paths"][
        "/api/v1/relays/enrollments/{enrollment_id}/pickup"
    ]["post"]["parameters"]
    assert all(parameter["required"] for parameter in pickup_parameters)
    assert filtered["components"] == schema["components"]
