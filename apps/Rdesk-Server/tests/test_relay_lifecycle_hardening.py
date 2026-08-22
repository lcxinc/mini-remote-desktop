from __future__ import annotations

import base64
import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy.orm import Session
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from app.core.config import settings
from app.models.relay_node import RelayNode
from app.models.relay_node_registration import RelayNodeRegistration
from test_relay_node_api import (
    NODE_ID,
    TLS_HEADERS,
    _approve,
    _canonical_request,
    _csr,
    _enroll,
    _error_code,
    _heartbeat_request,
    _issue_token,
    api,
)


def _enrollment_payload(token: str, csr_pem: str) -> dict[str, object]:
    return {
        "token": token,
        "node_id": NODE_ID,
        "region": "ap-east",
        "failure_domain": "rack-a",
        "endpoints": ["turn:relay.example.test:3478?transport=udp"],
        "max_allocations": 100,
        "max_egress_bps": 1_000_000,
        "csr_pem": csr_pem,
    }


def _enroll_with_receipt(
    client: TestClient,
) -> tuple[ed25519.Ed25519PrivateKey, str, str]:
    token = _issue_token(client)
    csr_pem, key = _csr(NODE_ID)
    assert isinstance(key, ed25519.Ed25519PrivateKey)
    response = client.post(
        "/api/v1/relays/enroll",
        headers=TLS_HEADERS,
        json=_enrollment_payload(token, csr_pem),
    )
    assert response.status_code == 202, response.text
    enrollment_id = response.json()["enrollment_id"]
    receipt = response.json()["receipt"]
    assert len(enrollment_id) == 36
    assert len(receipt) >= 40
    return key, enrollment_id, receipt


def _pickup(
    client: TestClient, enrollment_id: str, receipt: str
):
    return client.post(
        f"/api/v1/relays/enrollments/{enrollment_id}/pickup",
        headers={**TLS_HEADERS, "X-Relay-Enrollment-Receipt": receipt},
    )


def _renewal_request(
    key: ed25519.Ed25519PrivateKey,
    fingerprint: str,
    *,
    renewal_id: str,
    csr_pem: str,
    sequence: int = 1,
) -> tuple[bytes, dict[str, str]]:
    path = f"/api/v1/relays/{NODE_ID}/renew"
    body, headers = _heartbeat_request(
        key,
        fingerprint,
        path=path,
        sequence=sequence,
        payload={"renewal_id": renewal_id, "csr_pem": csr_pem},
    )
    headers["X-Relay-Renewal-Id"] = renewal_id
    return body, headers


def test_enrollment_returns_once_only_receipt_and_stores_only_digest(
    api: tuple[TestClient, object], caplog: pytest.LogCaptureFixture
) -> None:
    client, engine = api
    caplog.set_level(logging.DEBUG)
    _, enrollment_id, receipt = _enroll_with_receipt(client)
    with Session(engine) as session:
        registration = session.get(RelayNodeRegistration, NODE_ID)
        assert registration is not None
        assert registration.enrollment_id == enrollment_id
        assert registration.receipt_digest != receipt
        assert len(registration.receipt_digest) == 64
    assert receipt not in caplog.text
    assert receipt not in repr(registration)


def test_pickup_is_pending_then_idempotently_delivers_approved_certificate(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    _, enrollment_id, receipt = _enroll_with_receipt(client)
    pending = _pickup(client, enrollment_id, receipt)
    assert pending.status_code == 200
    assert pending.json() == {
        "enrollment_id": enrollment_id,
        "node_id": NODE_ID,
        "status": "pending",
        "certificate_pem": None,
        "ca_certificate_pem": None,
        "expires_at": None,
    }

    _approve(client)
    delivered = _pickup(client, enrollment_id, receipt)
    retried = _pickup(client, enrollment_id, receipt)
    assert delivered.status_code == retried.status_code == 200
    assert delivered.json() == retried.json()
    assert delivered.json()["status"] == "approved"
    assert "BEGIN CERTIFICATE" in delivered.json()["certificate_pem"]
    assert "BEGIN CERTIFICATE" in delivered.json()["ca_certificate_pem"]


def test_pickup_wrong_receipt_unknown_revoked_and_expired_do_not_enumerate(
    api: tuple[TestClient, object],
) -> None:
    client, engine = api
    _, enrollment_id, receipt = _enroll_with_receipt(client)
    wrong = _pickup(client, enrollment_id, "wrong-" + receipt)
    unknown = _pickup(client, str(uuid4()), receipt)
    assert (wrong.status_code, _error_code(wrong)) == (
        unknown.status_code,
        _error_code(unknown),
    ) == (401, "relay_enrollment_invalid")

    _approve(client)
    assert client.post(f"/api/v1/relays/{NODE_ID}/revoke").status_code == 200
    revoked = _pickup(client, enrollment_id, receipt)
    assert revoked.status_code == 401
    assert _error_code(revoked) == "relay_enrollment_invalid"

    with Session(engine) as session:
        registration = session.get(RelayNodeRegistration, NODE_ID)
        assert registration is not None
        registration.status = "approved"
        registration.certificate_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    expired = _pickup(client, enrollment_id, receipt)
    assert expired.status_code == 401
    assert _error_code(expired) == "relay_enrollment_invalid"


def test_renewal_lost_response_retry_rotates_once_and_old_cert_is_renew_only(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    old_key, _, _ = _enroll_with_receipt(client)
    _, old_fingerprint = _approve(client)
    csr_pem, new_key = _csr(NODE_ID)
    assert isinstance(new_key, ed25519.Ed25519PrivateKey)
    renewal_id = str(uuid4())
    body, headers = _renewal_request(
        old_key,
        old_fingerprint,
        renewal_id=renewal_id,
        csr_pem=csr_pem,
        sequence=21,
    )
    first = client.post(
        f"/api/v1/relays/{NODE_ID}/renew", content=body, headers=headers
    )
    retry = client.post(
        f"/api/v1/relays/{NODE_ID}/renew", content=body, headers=headers
    )
    assert first.status_code == retry.status_code == 200
    assert first.json() == retry.json()
    new_fingerprint = first.json()["fingerprint"]
    assert new_fingerprint != old_fingerprint

    old_body, old_headers = _heartbeat_request(
        old_key, old_fingerprint, sequence=1
    )
    old_heartbeat = client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat",
        content=old_body,
        headers=old_headers,
    )
    assert old_heartbeat.status_code == 401
    assert _error_code(old_heartbeat) == "relay_certificate_invalid"

    new_body, new_headers = _heartbeat_request(
        new_key, new_fingerprint, sequence=1
    )
    new_heartbeat = client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat",
        content=new_body,
        headers=new_headers,
    )
    assert new_heartbeat.status_code == 200, new_heartbeat.text


def test_renewal_revoke_conflict_and_concurrent_idempotency(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    old_key, _, _ = _enroll_with_receipt(client)
    _, fingerprint = _approve(client)
    csr_pem, _ = _csr(NODE_ID)
    renewal_id = str(uuid4())
    body, headers = _renewal_request(
        old_key,
        fingerprint,
        renewal_id=renewal_id,
        csr_pem=csr_pem,
        sequence=22,
    )
    barrier = threading.Barrier(2)

    def renew():
        barrier.wait()
        return client.post(
            f"/api/v1/relays/{NODE_ID}/renew", content=body, headers=headers
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = [future.result() for future in [executor.submit(renew) for _ in range(2)]]
    assert [response.status_code for response in responses] == [200, 200]
    assert responses[0].json()["fingerprint"] == responses[1].json()["fingerprint"]

    different_csr, _ = _csr(NODE_ID)
    conflict_body, conflict_headers = _renewal_request(
        old_key,
        fingerprint,
        renewal_id=str(uuid4()),
        csr_pem=different_csr,
        sequence=23,
    )
    conflict = client.post(
        f"/api/v1/relays/{NODE_ID}/renew",
        content=conflict_body,
        headers=conflict_headers,
    )
    assert conflict.status_code == 409
    assert _error_code(conflict) == "relay_renewal_conflict"

    assert client.post(f"/api/v1/relays/{NODE_ID}/revoke").status_code == 200
    revoked_csr, _ = _csr(NODE_ID)
    revoked_body, revoked_headers = _renewal_request(
        old_key,
        fingerprint,
        renewal_id=str(uuid4()),
        csr_pem=revoked_csr,
        sequence=24,
    )
    revoked = client.post(
        f"/api/v1/relays/{NODE_ID}/renew",
        content=revoked_body,
        headers=revoked_headers,
    )
    assert revoked.status_code == 403
    assert _error_code(revoked) == "relay_node_revoked"


def test_untrusted_malformed_body_is_rejected_before_json_parsing(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    with TestClient(client.app, client=("203.0.113.7", 41000)) as public:
        response = public.post(
            f"/api/v1/relays/{NODE_ID}/heartbeat",
            content=b"{",
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 403
    assert _error_code(response) == "relay_proxy_required"


def test_trusted_oversized_body_is_rejected_before_route_validation(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    response = client.post(
        "/api/v1/relays/enroll",
        content=b"x" * 65_537,
        headers={**TLS_HEADERS, "Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert _error_code(response) == "relay_request_too_large"


@pytest.mark.parametrize(
    ("path", "header", "code"),
    [
        (f"/api/v1/relays/{NODE_ID}/heartbeat", "X-Relay-Signature", "relay_signature_invalid"),
        (f"/api/v1/relays/{NODE_ID}/heartbeat", "X-Rdesk-Client-Cert-Sha256", "relay_certificate_invalid"),
        ("/api/v1/relays/enrollments/missing/pickup", "X-Relay-Enrollment-Receipt", "relay_enrollment_invalid"),
        (f"/api/v1/relays/{NODE_ID}/renew", "X-Relay-Renewal-Id", "relay_signature_invalid"),
    ],
)
def test_duplicate_and_comma_joined_security_headers_fail_closed(
    api: tuple[TestClient, object], path: str, header: str, code: str
) -> None:
    client, _ = api
    for raw_headers in (
        [(header, "value-a"), (header, "value-b")],
        [(header, "value-a,value-b")],
    ):
        response = client.post(
            path,
            content=b"{}",
            headers=[*TLS_HEADERS.items(), *raw_headers, ("Content-Type", "application/json")],
        )
        assert response.status_code == 401
        assert _error_code(response) == code


def test_forwarded_headers_are_rejected_after_proxy_scope_rewrite(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    wrapped = ProxyHeadersMiddleware(client.app, trusted_hosts="*")
    with TestClient(wrapped, client=("203.0.113.7", 41000)) as public:
        response = public.post(
            "/api/v1/relays/enroll",
            content=b"{}",
            headers={
                **TLS_HEADERS,
                "X-Forwarded-For": "127.0.0.1",
                "Content-Type": "application/json",
            },
        )
    assert response.status_code == 403
    assert _error_code(response) == "relay_proxy_required"


def test_ipv4_mapped_ipv6_direct_peer_matches_ipv4_allowlist(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    token = _issue_token(client)
    csr_pem, _ = _csr(NODE_ID)
    with TestClient(client.app, client=("::ffff:127.0.0.1", 41000)) as mapped:
        response = mapped.post(
            "/api/v1/relays/enroll",
            headers=TLS_HEADERS,
            json=_enrollment_payload(token, csr_pem),
        )
    assert response.status_code == 202, response.text


def test_duplicate_content_length_is_rejected_stably(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    response = client.post(
        "/api/v1/relays/enroll",
        content=b"{}",
        headers=[
            *TLS_HEADERS.items(),
            ("Content-Length", "2"),
            ("Content-Length", "2"),
            ("Content-Type", "application/json"),
        ],
    )
    assert response.status_code == 400
    assert _error_code(response) == "relay_request_invalid"


@pytest.mark.parametrize("content_length", ["+2", "02", " 2", "-1", "nope"])
def test_noncanonical_content_length_is_rejected_stably(
    api: tuple[TestClient, object], content_length: str
) -> None:
    client, _ = api
    response = client.post(
        "/api/v1/relays/enroll",
        content=b"{}",
        headers=[
            *TLS_HEADERS.items(),
            ("Content-Length", content_length),
            ("Content-Type", "application/json"),
        ],
    )
    assert response.status_code == 400
    assert _error_code(response) == "relay_request_invalid"


def test_admin_routes_are_not_blocked_by_relay_node_boundary(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    response = client.post(
        "/api/v1/relays/enrollment-tokens",
        json={"ttl_seconds": 300},
    )
    assert response.status_code == 201


def test_v3_models_persist_receipt_renewal_and_health_state() -> None:
    node_columns = RelayNode.__table__.c
    registration_columns = RelayNodeRegistration.__table__.c
    assert node_columns.healthy_heartbeat_streak.server_default is not None
    for name in (
        "receipt_digest",
        "receipt_expires_at",
        "ca_certificate_pem",
        "previous_certificate_fingerprint",
        "previous_signing_public_key",
        "previous_auth_expires_at",
        "renewal_request_id",
        "renewal_csr_sha256",
        "renewal_certificate_pem",
        "renewal_certificate_expires_at",
    ):
        assert name in registration_columns


def test_openapi_install_invalidates_stale_cache_and_composes_custom_schema() -> None:
    from fastapi import FastAPI

    from app.api.v1.relays import install_relay_openapi, router

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    original = app.openapi
    calls = 0

    def custom_openapi():
        nonlocal calls
        calls += 1
        schema = original()
        schema["x-custom-openapi"] = "preserved"
        return schema

    app.openapi = custom_openapi  # type: ignore[method-assign]
    app.openapi_schema = {"stale": True}
    install_relay_openapi(app)
    schema = app.openapi()
    install_relay_openapi(app)
    assert app.openapi() is schema
    assert calls == 1
    assert schema["x-custom-openapi"] == "preserved"
    assert "paths" in schema and "stale" not in schema


def _rsa_ca_material(key_size: int) -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RSA test CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    )


def test_ca_policy_rejects_rsa_below_3072_bits(
    api: tuple[TestClient, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = api
    certificate, private_key = _rsa_ca_material(2048)
    monkeypatch.setitem(settings.__dict__, "relay_ca_certificate_pem", certificate)
    monkeypatch.setitem(
        settings.__dict__, "relay_ca_private_key_pem", SecretStr(private_key)
    )
    _enroll(client)
    response = client.post(f"/api/v1/relays/{NODE_ID}/approve")
    assert response.status_code == 503
    assert _error_code(response) == "relay_ca_unavailable"


@pytest.mark.parametrize("password_kind", ["correct", "wrong", "missing"])
def test_encrypted_ca_private_key_password_is_supported_and_fail_closed(
    api: tuple[TestClient, object],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    password_kind: str,
) -> None:
    client, _ = api
    caplog.set_level(logging.DEBUG)
    from test_relay_node_api import _ca_material

    certificate, _, _, key = _ca_material(key_cert_sign=True)
    password = b"S3cure-CA-Key-Password!"
    encrypted_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    ).decode()
    monkeypatch.setitem(settings.__dict__, "relay_ca_certificate_pem", certificate)
    monkeypatch.setitem(
        settings.__dict__, "relay_ca_private_key_pem", SecretStr(encrypted_key)
    )
    configured_password = {
        "correct": password.decode(),
        "wrong": "wrong-password",
        "missing": "",
    }[password_kind]
    monkeypatch.setitem(
        settings.__dict__,
        "relay_ca_private_key_password",
        SecretStr(configured_password),
    )
    _enroll(client)
    response = client.post(f"/api/v1/relays/{NODE_ID}/approve")
    if password_kind == "correct":
        assert response.status_code == 200, response.text
    else:
        assert response.status_code == 503
        assert _error_code(response) == "relay_ca_unavailable"
    assert encrypted_key not in caplog.text
    if configured_password:
        assert configured_password not in caplog.text
