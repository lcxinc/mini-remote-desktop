# ruff: noqa: F811

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import threading
import asyncio
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
from app.api.v1.relays import _relay_turn_secret_cipher
from app.models.relay_node import RelayNode
from app.models.relay_node_registration import RelayNodeRegistration
from app.models.relay_audit_event import RelayAuditEvent
from app.middleware.relay_node_boundary import RelayNodeBoundaryMiddleware
from app.services.turn_credentials import NodeTurnCredentialService
from test_relay_node_api import (
    NODE_ID,
    TLS_HEADERS,
    _approval_body,
    _approve,
    _csr,
    _enroll,
    _error_code,
    _heartbeat_request,
    _issue_token,
    api,  # noqa: F401 - pytest fixture re-export
)


NODE_TURN_SECRET = base64.urlsafe_b64encode(b"node-held-turn-secret-material!!").rstrip(
    b"="
).decode("ascii")


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
        "turn_rest_secret": NODE_TURN_SECRET,
    }


def test_node_generated_turn_secret_is_bound_encrypted_and_never_picked_up(
    api: tuple[TestClient, object], caplog: pytest.LogCaptureFixture
) -> None:
    client, engine = api
    caplog.set_level(logging.DEBUG)
    token = _issue_token(client)
    csr_pem, _ = _csr(NODE_ID)
    payload = {
        **_enrollment_payload(token, csr_pem),
        "turn_rest_secret": NODE_TURN_SECRET,
    }
    enrolled = client.post(
        "/api/v1/relays/enroll", headers=TLS_HEADERS, json=payload
    )
    assert enrolled.status_code == 202, enrolled.text
    enrollment_id = enrolled.json()["enrollment_id"]
    receipt = enrolled.json()["receipt"]
    with Session(engine) as session:
        registration = session.get(RelayNodeRegistration, NODE_ID)
        assert registration.encrypted_turn_secret is not None
        assert NODE_TURN_SECRET.encode() not in registration.encrypted_turn_secret
        stored_ciphertext = bytes(registration.encrypted_turn_secret)

    approved = client.post(
        f"/api/v1/relays/{NODE_ID}/approve",
        json={"failure_domain": "rack-admin", "physical_host_id": "host-admin"},
    )
    assert approved.status_code == 200, approved.text
    pickup = _pickup(client, enrollment_id, receipt)
    assert pickup.status_code == 200, pickup.text
    assert "turn_rest_secret" not in pickup.json()
    assert NODE_TURN_SECRET not in pickup.text
    assert NODE_TURN_SECRET not in caplog.text
    with Session(engine) as session:
        node = session.get(RelayNode, NODE_ID)
        registration = session.get(RelayNodeRegistration, NODE_ID)
        assert bytes(node.encrypted_turn_secret) == stored_ciphertext
        cipher = _relay_turn_secret_cipher()
        assert cipher.decrypt(
            bytes(node.encrypted_turn_secret),
            associated_data=NODE_ID.encode("ascii"),
        ) == NODE_TURN_SECRET.encode("ascii")
        now_seconds = int(datetime.now(UTC).timestamp())
        issued = NodeTurnCredentialService(
            cipher=cipher, now=lambda: now_seconds
        ).issue(
            user_id="user-protocol",
            session_id="session-protocol",
            node_id=NODE_ID,
            urls=list(node.endpoints),
            encrypted_secret=bytes(node.encrypted_turn_secret),
            grant_deadline_unix_seconds=now_seconds + 300,
            directory_deadline_unix_seconds=now_seconds + 300,
            policy_deadline_unix_seconds=now_seconds + 300,
            node_deadline_unix_seconds=now_seconds + 300,
        )
        coturn_credential = base64.b64encode(
            hmac.new(
                NODE_TURN_SECRET.encode("ascii"),
                issued.username.encode("utf-8"),
                hashlib.sha1,
            ).digest()
        ).decode("ascii")
        assert hmac.compare_digest(issued.credential, coturn_credential)
        assert node.failure_domain == "rack-admin"
        assert node.physical_host_id == "host-admin"
        assert registration.topology_approved_at is not None


def test_same_enrollment_token_with_different_turn_secret_conflicts(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    token = _issue_token(client)
    csr_pem, _ = _csr(NODE_ID)
    payload = {
        **_enrollment_payload(token, csr_pem),
        "turn_rest_secret": NODE_TURN_SECRET,
    }
    first = client.post("/api/v1/relays/enroll", headers=TLS_HEADERS, json=payload)
    assert first.status_code == 202, first.text
    changed = dict(payload)
    changed["turn_rest_secret"] = base64.urlsafe_b64encode(
        hashlib.sha256(b"different-valid-turn-secret").digest()
    ).rstrip(b"=").decode("ascii")
    conflict = client.post(
        "/api/v1/relays/enroll", headers=TLS_HEADERS, json=changed
    )
    assert conflict.status_code == 409
    assert _error_code(conflict) == "relay_enrollment_already_used"


def test_relay_enrollment_rejects_repeated_placeholder_turn_secret(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    token = _issue_token(client)
    csr_pem, _ = _csr(NODE_ID)
    response = client.post(
        "/api/v1/relays/enroll",
        headers=TLS_HEADERS,
        json={
            **_enrollment_payload(token, csr_pem),
            "turn_rest_secret": base64.urlsafe_b64encode(b"x" * 32)
            .rstrip(b"=")
            .decode("ascii"),
        },
    )
    assert response.status_code == 400
    assert _error_code(response) == "relay_enrollment_invalid"


def test_admin_approval_requires_explicit_trusted_topology(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    token = _issue_token(client)
    csr_pem, _ = _csr(NODE_ID)
    enrolled = client.post(
        "/api/v1/relays/enroll",
        headers=TLS_HEADERS,
        json={
            **_enrollment_payload(token, csr_pem),
            "turn_rest_secret": NODE_TURN_SECRET,
        },
    )
    assert enrolled.status_code == 202, enrolled.text
    missing = client.post(f"/api/v1/relays/{NODE_ID}/approve", json={})
    assert missing.status_code == 400
    assigned = client.post(
        f"/api/v1/relays/{NODE_ID}/approve",
        json={"failure_domain": "rack-admin", "physical_host_id": "host-admin"},
    )
    assert assigned.status_code == 200, assigned.text


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
    setattr(client, "_relay_enrollment_delivery", (enrollment_id, receipt))
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
        replace_payload=True,
    )
    headers["X-Relay-Renewal-Id"] = renewal_id
    return body, headers


def test_renewal_fails_closed_without_consuming_rotation_state_or_sequence(
    api: tuple[TestClient, object],
) -> None:
    client, engine = api
    old_key, _, _ = _enroll_with_receipt(client)
    _, old_fingerprint = _approve(client)
    rotated = client.post(
        f"/api/v1/relays/{NODE_ID}/rotate-secret",
        json={"credential_ttl_seconds": 300},
    )
    assert rotated.status_code == 202, rotated.text

    with Session(engine) as session:
        before = session.get(RelayNode, NODE_ID)
        assert before is not None
        invariant = (
            before.identity_epoch,
            before.heartbeat_sequence,
            before.desired_secret_version,
            before.desired_draining,
            before.state,
            before.rotation_challenge,
            before.secret_not_before,
            before.old_credential_deadline,
        )
        audit_count = session.query(RelayAuditEvent).count()

    csr_pem, _ = _csr(NODE_ID)
    body, headers = _renewal_request(
        old_key,
        old_fingerprint,
        renewal_id=str(uuid4()),
        csr_pem=csr_pem,
        sequence=21,
    )
    rejected = client.post(
        f"/api/v1/relays/{NODE_ID}/renew", content=body, headers=headers
    )
    assert (rejected.status_code, _error_code(rejected)) == (
        409,
        "relay_renewal_conflict",
    )

    with Session(engine) as session:
        after = session.get(RelayNode, NODE_ID)
        assert after is not None
        assert (
            after.identity_epoch,
            after.heartbeat_sequence,
            after.desired_secret_version,
            after.desired_draining,
            after.state,
            after.rotation_challenge,
            after.secret_not_before,
            after.old_credential_deadline,
        ) == invariant
        assert session.query(RelayAuditEvent).count() == audit_count


def test_admin_drain_survives_renewal_and_remains_authoritative_on_heartbeat(
    api: tuple[TestClient, object],
) -> None:
    client, engine = api
    old_key, _, _ = _enroll_with_receipt(client)
    _, old_fingerprint = _approve(client)
    drained = client.post(f"/api/v1/relays/{NODE_ID}/drain")
    assert drained.status_code == 200, drained.text

    csr_pem, new_key = _csr(NODE_ID)
    renewal_id = str(uuid4())
    body, headers = _renewal_request(
        old_key,
        old_fingerprint,
        renewal_id=renewal_id,
        csr_pem=csr_pem,
        sequence=21,
    )
    renewed = client.post(
        f"/api/v1/relays/{NODE_ID}/renew", content=body, headers=headers
    )
    assert renewed.status_code == 200, renewed.text
    assert isinstance(new_key, ed25519.Ed25519PrivateKey)

    with Session(engine) as session:
        node = session.get(RelayNode, NODE_ID)
        assert node is not None
        assert node.identity_epoch == 2
        assert node.desired_draining is True
        assert node.state == "draining"

    heartbeat_body, heartbeat_headers = _heartbeat_request(
        new_key,
        renewed.json()["fingerprint"],
        sequence=1,
        payload={"identity_epoch": 2},
    )
    heartbeat = client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat",
        content=heartbeat_body,
        headers=heartbeat_headers,
    )
    assert heartbeat.status_code == 200, heartbeat.text
    assert heartbeat.json()["state"] == "draining"
    assert heartbeat.json()["desired"]["draining"] is True


def test_exact_previous_epoch_renewal_retry_preserves_later_rotation_state(
    api: tuple[TestClient, object],
) -> None:
    client, engine = api
    old_key, _, _ = _enroll_with_receipt(client)
    _, old_fingerprint = _approve(client)
    csr_pem, new_key = _csr(NODE_ID)
    renewal_id = str(uuid4())
    first_body, first_headers = _renewal_request(
        old_key,
        old_fingerprint,
        renewal_id=renewal_id,
        csr_pem=csr_pem,
        sequence=21,
    )
    first = client.post(
        f"/api/v1/relays/{NODE_ID}/renew",
        content=first_body,
        headers=first_headers,
    )
    assert first.status_code == 200, first.text
    with Session(engine) as session:
        ordinary = session.get(RelayNode, NODE_ID)
        assert ordinary is not None
        assert ordinary.state == "unavailable"
        assert ordinary.desired_draining is False
        assert ordinary.desired_secret_version == ordinary.active_secret_version

    rotated = client.post(
        f"/api/v1/relays/{NODE_ID}/rotate-secret",
        json={"credential_ttl_seconds": 300},
    )
    assert rotated.status_code == 202, rotated.text
    with Session(engine) as session:
        before = session.get(RelayNode, NODE_ID)
        assert before is not None
        rotation_invariant = (
            before.heartbeat_sequence,
            before.desired_draining,
            before.desired_secret_version,
            before.state,
            before.secret_not_before,
            before.old_credential_deadline,
            before.pending_secret_version,
            before.rotation_challenge,
        )
        updated_at = before.updated_at
        audit_count = session.query(RelayAuditEvent).count()

    retry_body, retry_headers = _renewal_request(
        old_key,
        old_fingerprint,
        renewal_id=renewal_id,
        csr_pem=csr_pem,
        sequence=22,
    )
    retried = client.post(
        f"/api/v1/relays/{NODE_ID}/renew",
        content=retry_body,
        headers=retry_headers,
    )
    assert retried.status_code == 200, retried.text
    assert retried.json() == first.json()

    with Session(engine) as session:
        after = session.get(RelayNode, NODE_ID)
        assert after is not None
        assert after.previous_identity_sequence == 22
        assert (
            after.heartbeat_sequence,
            after.desired_draining,
            after.desired_secret_version,
            after.state,
            after.secret_not_before,
            after.old_credential_deadline,
            after.pending_secret_version,
            after.rotation_challenge,
        ) == rotation_invariant
        assert after.updated_at == updated_at
        assert session.query(RelayAuditEvent).count() == audit_count

    current_body, current_headers = _renewal_request(
        new_key,
        first.json()["fingerprint"],
        renewal_id=renewal_id,
        csr_pem=csr_pem,
        sequence=1,
    )
    current_retry = client.post(
        f"/api/v1/relays/{NODE_ID}/renew",
        content=current_body,
        headers=current_headers,
    )
    assert current_retry.status_code == 409, current_retry.text
    assert _error_code(current_retry) == "relay_renewal_conflict"

    with Session(engine) as session:
        after_current_retry = session.get(RelayNode, NODE_ID)
        assert after_current_retry is not None
        assert after_current_retry.previous_identity_sequence == 22
        assert (
            after_current_retry.heartbeat_sequence,
            after_current_retry.desired_draining,
            after_current_retry.desired_secret_version,
            after_current_retry.state,
            after_current_retry.secret_not_before,
            after_current_retry.old_credential_deadline,
            after_current_retry.pending_secret_version,
            after_current_retry.rotation_challenge,
        ) == rotation_invariant
        assert after_current_retry.updated_at == updated_at
        assert session.query(RelayAuditEvent).count() == audit_count


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
        assert len(registration.request_digest) == 64
    assert receipt not in caplog.text
    assert receipt not in repr(registration)


def test_lost_enrollment_response_is_deterministically_recoverable_only_for_exact_request(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    token = _issue_token(client)
    csr_pem, _ = _csr(NODE_ID)
    payload = _enrollment_payload(token, csr_pem)
    first = client.post("/api/v1/relays/enroll", headers=TLS_HEADERS, json=payload)
    retry = client.post("/api/v1/relays/enroll", headers=TLS_HEADERS, json=payload)
    assert first.status_code == retry.status_code == 202
    assert first.json() == retry.json()

    changed = dict(payload)
    changed["failure_domain"] = "rack-b"
    conflict = client.post(
        "/api/v1/relays/enroll", headers=TLS_HEADERS, json=changed
    )
    assert conflict.status_code == 409
    assert _error_code(conflict) == "relay_enrollment_already_used"


def test_concurrent_identical_enrollment_requests_return_one_identity(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    token = _issue_token(client)
    csr_pem, _ = _csr(NODE_ID)
    payload = _enrollment_payload(token, csr_pem)
    barrier = threading.Barrier(2)

    def enroll() -> object:
        barrier.wait()
        return client.post(
            "/api/v1/relays/enroll", headers=TLS_HEADERS, json=payload
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = [future.result() for future in [executor.submit(enroll) for _ in range(2)]]
    assert [response.status_code for response in responses] == [202, 202]
    assert responses[0].json() == responses[1].json()


def test_sqlite_node_lock_is_held_until_api_transaction_finishes(
    api: tuple[TestClient, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.api.v1 import relays as relay_api

    client, _ = api
    first_token = _issue_token(client)
    second_token = _issue_token(client)
    first_csr, _ = _csr(NODE_ID)
    second_csr, _ = _csr(NODE_ID)
    payloads = (
        _enrollment_payload(first_token, first_csr),
        _enrollment_payload(second_token, second_csr),
    )
    original_commit = relay_api._commit
    commit_entered = threading.Event()
    release_commit = threading.Event()

    async def delayed_commit(db: object) -> None:
        commit_entered.set()
        await asyncio.to_thread(release_commit.wait)
        await original_commit(db)  # type: ignore[arg-type]

    monkeypatch.setattr(relay_api, "_commit", delayed_commit)
    start = threading.Barrier(2)

    def enroll(payload: dict[str, object]) -> object:
        start.wait()
        return client.post(
            "/api/v1/relays/enroll", headers=TLS_HEADERS, json=payload
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(enroll, payload) for payload in payloads]
        assert commit_entered.wait(timeout=5)
        # The loser must still be waiting on the process transaction lock; it
        # cannot return based on a pre-commit snapshot.
        assert all(not future.done() for future in futures)
        release_commit.set()
        responses = [future.result(timeout=5) for future in futures]
    assert sorted(response.status_code for response in responses) == [202, 409]
    rejected = next(response for response in responses if response.status_code == 409)
    assert _error_code(rejected) == "relay_enrollment_pending"


def test_pickup_is_pending_then_idempotently_delivers_approved_certificate(
    api: tuple[TestClient, object],
) -> None:
    client, engine = api
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

    approved = client.post(
        f"/api/v1/relays/{NODE_ID}/approve", json=_approval_body()
    )
    assert approved.status_code == 200
    assert approved.json() == {"node_id": NODE_ID, "status": "approved"}
    delivered = _pickup(client, enrollment_id, receipt)
    retried = _pickup(client, enrollment_id, receipt)
    assert delivered.status_code == retried.status_code == 200
    assert delivered.json() == retried.json()
    assert delivered.json()["status"] == "approved"
    assert "BEGIN CERTIFICATE" in delivered.json()["certificate_pem"]
    assert "BEGIN CERTIFICATE" in delivered.json()["ca_certificate_pem"]
    assert "turn_rest_secret" not in delivered.json()
    assert NODE_TURN_SECRET not in delivered.text
    with Session(engine) as session:
        node = session.get(RelayNode, NODE_ID)
        registration = session.get(RelayNodeRegistration, NODE_ID)
        assert node is not None
        assert registration is not None
        assert bytes(node.encrypted_turn_secret) == bytes(
            registration.encrypted_turn_secret
        )


def test_approval_does_not_issue_until_first_pickup_and_concurrent_pickup_signs_once(
    api: tuple[TestClient, object],
) -> None:
    client, engine = api
    _, enrollment_id, receipt = _enroll_with_receipt(client)
    with Session(engine) as session:
        before_approval = session.get(RelayNodeRegistration, NODE_ID)
        assert before_approval is not None
        immutable_receipt_expiry = before_approval.receipt_expires_at
    approved = client.post(
        f"/api/v1/relays/{NODE_ID}/approve", json=_approval_body()
    )
    assert approved.status_code == 200
    with Session(engine) as session:
        registration = session.get(RelayNodeRegistration, NODE_ID)
        assert registration is not None
        assert registration.certificate_pem is None
        assert registration.receipt_expires_at == immutable_receipt_expiry
        assert session.get(RelayNode, NODE_ID) is None

    barrier = threading.Barrier(2)

    def pickup():
        barrier.wait()
        return _pickup(client, enrollment_id, receipt)

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = [future.result() for future in [executor.submit(pickup) for _ in range(2)]]
    assert [response.status_code for response in responses] == [200, 200]
    assert responses[0].json() == responses[1].json()
    with Session(engine) as session:
        registration = session.get(RelayNodeRegistration, NODE_ID)
        assert registration is not None
        assert registration.receipt_expires_at == immutable_receipt_expiry


def test_approved_registration_can_be_irreversibly_revoked_before_pickup(
    api: tuple[TestClient, object],
) -> None:
    client, engine = api
    token = _issue_token(client)
    csr_pem, _ = _csr(NODE_ID)
    payload = _enrollment_payload(token, csr_pem)
    enrolled = client.post(
        "/api/v1/relays/enroll", headers=TLS_HEADERS, json=payload
    )
    assert enrolled.status_code == 202
    enrollment_id = enrolled.json()["enrollment_id"]
    receipt = enrolled.json()["receipt"]
    assert client.post(
        f"/api/v1/relays/{NODE_ID}/approve", json=_approval_body()
    ).status_code == 200

    revoked = client.post(f"/api/v1/relays/{NODE_ID}/revoke")
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["state"] == "revoked"
    revoked_again = client.post(f"/api/v1/relays/{NODE_ID}/revoke")
    assert revoked_again.status_code == 200
    assert revoked_again.json() == revoked.json()
    exact_retry = client.post(
        "/api/v1/relays/enroll", headers=TLS_HEADERS, json=payload
    )
    assert (exact_retry.status_code, _error_code(exact_retry)) == (
        403,
        "relay_node_revoked",
    )
    pickup = _pickup(client, enrollment_id, receipt)
    assert (pickup.status_code, _error_code(pickup)) == (
        401,
        "relay_enrollment_invalid",
    )
    with Session(engine) as session:
        registration = session.get(RelayNodeRegistration, NODE_ID)
        assert registration is not None
        assert registration.status == "revoked"
        assert registration.certificate_pem is None
        assert session.get(RelayNode, NODE_ID) is None

    approve_again = client.post(
        f"/api/v1/relays/{NODE_ID}/approve", json=_approval_body()
    )
    assert (approve_again.status_code, _error_code(approve_again)) == (
        403,
        "relay_node_revoked",
    )
    replacement_token = _issue_token(client)
    replacement_csr, _ = _csr(NODE_ID)
    reenroll = client.post(
        "/api/v1/relays/enroll",
        headers=TLS_HEADERS,
        json=_enrollment_payload(replacement_token, replacement_csr),
    )
    assert (reenroll.status_code, _error_code(reenroll)) == (
        403,
        "relay_node_revoked",
    )


def test_expired_receipt_cannot_be_revived_by_approval_and_new_token_recovers(
    api: tuple[TestClient, object],
) -> None:
    client, engine = api
    _, enrollment_id, receipt = _enroll_with_receipt(client)
    with Session(engine) as session:
        registration = session.get(RelayNodeRegistration, NODE_ID)
        assert registration is not None
        registration.receipt_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    before = _pickup(client, enrollment_id, receipt)
    assert (before.status_code, _error_code(before)) == (
        401,
        "relay_enrollment_invalid",
    )
    approval = client.post(
        f"/api/v1/relays/{NODE_ID}/approve", json=_approval_body()
    )
    assert approval.status_code == 409
    assert _error_code(approval) == "relay_enrollment_invalid"
    after = _pickup(client, enrollment_id, receipt)
    assert (after.status_code, _error_code(after)) == (
        401,
        "relay_enrollment_invalid",
    )

    replacement_token = _issue_token(client)
    replacement_csr, _ = _csr(NODE_ID)
    replacement = client.post(
        "/api/v1/relays/enroll",
        headers=TLS_HEADERS,
        json=_enrollment_payload(replacement_token, replacement_csr),
    )
    assert replacement.status_code == 202, replacement.text
    assert replacement.json()["enrollment_id"] != enrollment_id
    assert client.post(
        f"/api/v1/relays/{NODE_ID}/approve", json=_approval_body()
    ).status_code == 200
    delivered = _pickup(
        client,
        replacement.json()["enrollment_id"],
        replacement.json()["receipt"],
    )
    assert delivered.status_code == 200
    assert delivered.json()["status"] == "approved"


def test_valid_certificate_blocks_reenrollment_but_expiry_recovers_and_revoke_denies(
    api: tuple[TestClient, object],
) -> None:
    client, engine = api
    _enroll_with_receipt(client)
    _approve(client)

    valid_token = _issue_token(client)
    valid_csr, _ = _csr(NODE_ID)
    while_valid = client.post(
        "/api/v1/relays/enroll",
        headers=TLS_HEADERS,
        json=_enrollment_payload(valid_token, valid_csr),
    )
    assert (while_valid.status_code, _error_code(while_valid)) == (
        409,
        "relay_enrollment_pending",
    )

    with Session(engine) as session:
        registration = session.get(RelayNodeRegistration, NODE_ID)
        node = session.get(RelayNode, NODE_ID)
        assert registration is not None
        assert node is not None
        registration.certificate_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        node.state = "available"
        node.healthy_heartbeat_streak = 3
        node.lease_expires_at = datetime.now(UTC) + timedelta(seconds=15)
        session.commit()
    recovery_token = _issue_token(client)
    recovery_csr, _ = _csr(NODE_ID)
    recovered = client.post(
        "/api/v1/relays/enroll",
        headers=TLS_HEADERS,
        json=_enrollment_payload(recovery_token, recovery_csr),
    )
    assert recovered.status_code == 202, recovered.text
    with Session(engine) as session:
        quarantined = session.get(RelayNode, NODE_ID)
        assert quarantined is not None
        assert quarantined.state == "unavailable"
        assert quarantined.healthy_heartbeat_streak == 0
        assert quarantined.lease_expires_at is None

    assert client.post(f"/api/v1/relays/{NODE_ID}/revoke").status_code == 200
    revoked_token = _issue_token(client)
    revoked_csr, _ = _csr(NODE_ID)
    revoked = client.post(
        "/api/v1/relays/enroll",
        headers=TLS_HEADERS,
        json=_enrollment_payload(revoked_token, revoked_csr),
    )
    assert (revoked.status_code, _error_code(revoked)) == (
        403,
        "relay_node_revoked",
    )


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
    client, engine = api
    old_key, _, _ = _enroll_with_receipt(client)
    old_certificate_pem, old_fingerprint = _approve(client)
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
    retry_body, retry_headers = _renewal_request(
        old_key,
        old_fingerprint,
        renewal_id=renewal_id,
        csr_pem=csr_pem,
        sequence=22,
    )
    retry = client.post(
        f"/api/v1/relays/{NODE_ID}/renew",
        content=retry_body,
        headers=retry_headers,
    )
    assert first.status_code == retry.status_code == 200
    assert first.headers["cache-control"] == "no-store, private"
    assert first.headers["pragma"] == "no-cache"
    assert first.json() == retry.json()
    new_fingerprint = first.json()["fingerprint"]
    assert new_fingerprint != old_fingerprint
    old_not_after = x509.load_pem_x509_certificate(
        old_certificate_pem.encode()
    ).not_valid_after_utc
    with Session(engine) as session:
        registration = session.get(RelayNodeRegistration, NODE_ID)
        node = session.get(RelayNode, NODE_ID)
        assert registration is not None
        assert node is not None
        assert node.identity_epoch == 2
        assert node.heartbeat_sequence == 0
        assert node.previous_identity_sequence == 22
        assert registration.previous_certificate_expires_at is not None
        assert registration.renewal_record_expires_at is not None
        assert (
            registration.previous_certificate_expires_at.replace(tzinfo=UTC)
            == old_not_after
        )
        assert (
            registration.renewal_record_expires_at
            >= registration.previous_certificate_expires_at
        )

    # Cached renewal and previous-certificate retry are not limited by the old
    # operational five-minute grace setting.
    with Session(engine) as session:
        registration = session.get(RelayNodeRegistration, NODE_ID)
        assert registration is not None
        registration.previous_auth_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    old_retry_body, old_retry_headers = _renewal_request(
        old_key,
        old_fingerprint,
        renewal_id=renewal_id,
        csr_pem=csr_pem,
        sequence=23,
    )
    old_retry = client.post(
        f"/api/v1/relays/{NODE_ID}/renew",
        content=old_retry_body,
        headers=old_retry_headers,
    )
    assert old_retry.status_code == 200
    assert old_retry.json() == first.json()

    current_retry_body, current_retry_headers = _renewal_request(
        new_key,
        new_fingerprint,
        renewal_id=renewal_id,
        csr_pem=csr_pem,
        sequence=1,
    )
    current_retry = client.post(
        f"/api/v1/relays/{NODE_ID}/renew",
        content=current_retry_body,
        headers=current_retry_headers,
    )
    assert current_retry.status_code == 200
    assert current_retry.json() == first.json()

    different_csr, _ = _csr(NODE_ID)
    conflicting_body, conflicting_headers = _renewal_request(
        new_key,
        new_fingerprint,
        renewal_id=renewal_id,
        csr_pem=different_csr,
        sequence=2,
    )
    conflicting = client.post(
        f"/api/v1/relays/{NODE_ID}/renew",
        content=conflicting_body,
        headers=conflicting_headers,
    )
    assert (conflicting.status_code, _error_code(conflicting)) == (
        409,
        "relay_renewal_conflict",
    )

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
        new_key,
        new_fingerprint,
        sequence=3,
        payload={"identity_epoch": 2},
    )
    new_heartbeat = client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat",
        content=new_body,
        headers=new_headers,
    )
    assert new_heartbeat.status_code == 200, new_heartbeat.text

    with Session(engine) as session:
        registration = session.get(RelayNodeRegistration, NODE_ID)
        assert registration is not None
        registration.previous_certificate_expires_at = datetime.now(UTC) - timedelta(
            seconds=1
        )
        session.commit()
    expired_old_body, expired_old_headers = _renewal_request(
        old_key,
        old_fingerprint,
        renewal_id=renewal_id,
        csr_pem=csr_pem,
        sequence=24,
    )
    expired_old_retry = client.post(
        f"/api/v1/relays/{NODE_ID}/renew",
        content=expired_old_body,
        headers=expired_old_headers,
    )
    assert (expired_old_retry.status_code, _error_code(expired_old_retry)) == (
        401,
        "relay_certificate_invalid",
    )


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
    assert sorted(response.status_code for response in responses) == [200, 409]
    successful = next(response for response in responses if response.status_code == 200)
    replayed = next(response for response in responses if response.status_code == 409)
    assert successful.json()["fingerprint"]
    assert _error_code(replayed) == "relay_heartbeat_replayed"

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


async def _run_boundary_asgi(
    *,
    headers: list[tuple[bytes, bytes]],
    messages: list[dict[str, object]],
    path: str = "/api/v1/relays/enroll",
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    downstream_messages: list[dict[str, object]] = []
    sent: list[dict[str, object]] = []
    queue = list(messages)

    async def receive() -> dict[str, object]:
        if queue:
            return queue.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    async def downstream(scope, downstream_receive, downstream_send) -> None:
        downstream_messages.append(await downstream_receive())
        downstream_messages.append(await downstream_receive())
        await downstream_send(
            {"type": "http.response.start", "status": 204, "headers": []}
        )
        await downstream_send({"type": "http.response.body", "body": b""})

    middleware = RelayNodeBoundaryMiddleware(
        downstream, trusted_proxy="127.0.0.1"
    )
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": [(b"x-rdesk-client-tls", b"verified"), *headers],
            "client": ("127.0.0.1", 41000),
            "state": {},
        },
        receive,
        send,
    )
    return sent, downstream_messages


_ROTATION_BOUNDARY_PATHS = tuple(
    f"/api/v1/relays/{NODE_ID}/secret-rotation/{suffix}"
    for suffix in ("upload", "commit", "status")
)


@pytest.mark.anyio
@pytest.mark.parametrize("path", _ROTATION_BOUNDARY_PATHS)
async def test_every_secret_rotation_path_replays_an_exact_64k_stream(path: str) -> None:
    sent, downstream = await _run_boundary_asgi(
        path=path,
        headers=[(b"transfer-encoding", b"chunked")],
        messages=[
            {"type": "http.request", "body": b"a" * 32_768, "more_body": True},
            {"type": "http.request", "body": b"b" * 32_768, "more_body": False},
            {"type": "http.disconnect"},
        ],
    )
    assert sent[0]["status"] == 204
    assert downstream == [
        {
            "type": "http.request",
            "body": b"a" * 32_768 + b"b" * 32_768,
            "more_body": False,
        },
        {"type": "http.disconnect"},
    ]


@pytest.mark.anyio
@pytest.mark.parametrize("path", _ROTATION_BOUNDARY_PATHS)
@pytest.mark.parametrize(
    "headers",
    [
        [(b"x-relay-signature", b"one"), (b"x-relay-signature", b"two")],
        [(b"x-rdesk-client-tls", b"unverified")],
        [(b"content-length", b"2"), (b"content-length", b"2")],
        [(b"content-length", b"2"), (b"transfer-encoding", b"chunked")],
    ],
)
async def test_every_secret_rotation_path_rejects_ambiguous_headers(
    path: str, headers: list[tuple[bytes, bytes]]
) -> None:
    sent, downstream = await _run_boundary_asgi(
        path=path,
        headers=headers,
        messages=[{"type": "http.request", "body": b"{}", "more_body": False}],
    )
    assert sent[0]["status"] in {400, 401, 403}
    assert downstream == []


@pytest.mark.anyio
@pytest.mark.parametrize("path", _ROTATION_BOUNDARY_PATHS)
async def test_every_secret_rotation_path_rejects_streamed_body_over_64k(
    path: str,
) -> None:
    sent, downstream = await _run_boundary_asgi(
        path=path,
        headers=[(b"transfer-encoding", b"chunked")],
        messages=[
            {"type": "http.request", "body": b"a" * 32_768, "more_body": True},
            {"type": "http.request", "body": b"b" * 32_769, "more_body": False},
        ],
    )
    assert sent[0]["status"] == 413
    assert downstream == []


@pytest.mark.anyio
async def test_request_accumulator_is_zeroized_when_downstream_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.middleware import relay_node_boundary as boundary_module

    accumulator = bytearray()
    monkeypatch.setattr(
        boundary_module, "_new_request_body_buffer", lambda: accumulator
    )

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"secret-json", "more_body": False}

    async def send(_: dict[str, object]) -> None:
        raise AssertionError("downstream should raise before sending")

    async def downstream(*_: object) -> None:
        raise RuntimeError("injected downstream failure")

    middleware = RelayNodeBoundaryMiddleware(downstream, trusted_proxy="127.0.0.1")
    with pytest.raises(RuntimeError, match="injected downstream failure"):
        await middleware(
            {
                "type": "http",
                "method": "POST",
                "path": _ROTATION_BOUNDARY_PATHS[0],
                "headers": [(b"x-rdesk-client-tls", b"verified")],
                "client": ("127.0.0.1", 41000),
                "state": {},
            },
            receive,
            send,
        )
    assert accumulator == bytearray(len(b"secret-json"))


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("declared", "body"),
    [(b"3", b"{}"), (b"1", b"{}"), (b"0", b"x")],
)
async def test_content_length_must_exactly_match_cached_body(
    declared: bytes, body: bytes
) -> None:
    sent, downstream = await _run_boundary_asgi(
        headers=[(b"content-length", declared)],
        messages=[{"type": "http.request", "body": body, "more_body": False}],
    )
    assert sent[0]["status"] == 400
    assert b"relay_request_invalid" in sent[1]["body"]
    assert downstream == []


@pytest.mark.anyio
async def test_content_length_and_transfer_encoding_are_rejected() -> None:
    sent, downstream = await _run_boundary_asgi(
        headers=[(b"content-length", b"2"), (b"transfer-encoding", b"chunked")],
        messages=[{"type": "http.request", "body": b"{}", "more_body": False}],
    )
    assert sent[0]["status"] == 400
    assert b"relay_request_invalid" in sent[1]["body"]
    assert downstream == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "headers",
    [[], [(b"transfer-encoding", b"chunked")]],
)
async def test_no_content_length_chunks_replay_exact_body_then_original_disconnect(
    headers: list[tuple[bytes, bytes]],
) -> None:
    sent, downstream = await _run_boundary_asgi(
        headers=headers,
        messages=[
            {"type": "http.request", "body": b"{", "more_body": True},
            {"type": "http.request", "body": b"}", "more_body": False},
            {"type": "http.disconnect"},
        ],
    )
    assert sent[0]["status"] == 204
    assert downstream == [
        {"type": "http.request", "body": b"{}", "more_body": False},
        {"type": "http.disconnect"},
    ]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "headers",
    [
        [(b"transfer-encoding", b"chunked,gzip")],
        [
            (b"transfer-encoding", b"chunked"),
            (b"transfer-encoding", b"chunked"),
        ],
    ],
)
async def test_ambiguous_transfer_encoding_is_rejected(
    headers: list[tuple[bytes, bytes]],
) -> None:
    sent, downstream = await _run_boundary_asgi(
        headers=headers,
        messages=[{"type": "http.request", "body": b"{}", "more_body": False}],
    )
    assert sent[0]["status"] == 400
    assert b"relay_request_invalid" in sent[1]["body"]
    assert downstream == []


@pytest.mark.anyio
async def test_stream_without_content_length_is_cumulatively_bounded() -> None:
    sent, downstream = await _run_boundary_asgi(
        headers=[(b"transfer-encoding", b"chunked")],
        messages=[
            {"type": "http.request", "body": b"x" * 40_000, "more_body": True},
            {"type": "http.request", "body": b"x" * 25_537, "more_body": False},
        ],
    )
    assert sent[0]["status"] == 413
    assert b"relay_request_too_large" in sent[1]["body"]
    assert downstream == []


@pytest.mark.anyio
async def test_empty_zero_length_body_replays_once_then_disconnect() -> None:
    sent, downstream = await _run_boundary_asgi(
        headers=[(b"content-length", b"0")],
        messages=[
            {"type": "http.request", "body": b"", "more_body": False},
            {"type": "http.disconnect"},
        ],
    )
    assert sent[0]["status"] == 204
    assert downstream == [
        {"type": "http.request", "body": b"", "more_body": False},
        {"type": "http.disconnect"},
    ]


@pytest.mark.anyio
async def test_disconnect_midstream_returns_stable_error_without_downstream() -> None:
    sent, downstream = await _run_boundary_asgi(
        headers=[],
        messages=[
            {"type": "http.request", "body": b"{", "more_body": True},
            {"type": "http.disconnect"},
        ],
    )
    assert sent == []
    assert downstream == []


@pytest.mark.anyio
async def test_disconnect_midstream_never_sends_on_closed_transport() -> None:
    receive_calls = 0

    async def receive() -> dict[str, object]:
        nonlocal receive_calls
        receive_calls += 1
        if receive_calls == 1:
            return {"type": "http.request", "body": b"{", "more_body": True}
        return {"type": "http.disconnect"}

    async def closed_send(_: dict[str, object]) -> None:
        raise OSError("transport is closed")

    async def downstream(*_: object) -> None:
        raise AssertionError("disconnected request reached downstream")

    middleware = RelayNodeBoundaryMiddleware(
        downstream, trusted_proxy="127.0.0.1"
    )
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/relays/enroll",
            "headers": [(b"x-rdesk-client-tls", b"verified")],
            "client": ("127.0.0.1", 41000),
            "state": {},
        },
        receive,
        closed_send,
    )


def test_admin_routes_are_not_blocked_by_relay_node_boundary(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    response = client.post(
        "/api/v1/relays/enrollment-tokens",
        json={"ttl_seconds": 300},
    )
    assert response.status_code == 201


def test_v4_models_persist_receipt_renewal_and_health_state() -> None:
    node_columns = RelayNode.__table__.c
    registration_columns = RelayNodeRegistration.__table__.c
    assert node_columns.healthy_heartbeat_streak.server_default is not None
    for name in (
        "request_digest",
        "receipt_digest",
        "receipt_expires_at",
        "ca_certificate_pem",
        "previous_certificate_fingerprint",
        "previous_signing_public_key",
        "previous_auth_expires_at",
        "previous_certificate_expires_at",
        "renewal_request_id",
        "renewal_csr_sha256",
        "renewal_certificate_pem",
        "renewal_certificate_expires_at",
        "renewal_record_expires_at",
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
    assert client.post(
        f"/api/v1/relays/{NODE_ID}/approve", json=_approval_body()
    ).status_code == 200
    enrollment_id, receipt = getattr(client, "_relay_enrollment_delivery")
    response = _pickup(client, enrollment_id, receipt)
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
    assert client.post(
        f"/api/v1/relays/{NODE_ID}/approve", json=_approval_body()
    ).status_code == 200
    enrollment_id, receipt = getattr(client, "_relay_enrollment_delivery")
    response = _pickup(client, enrollment_id, receipt)
    if password_kind == "correct":
        assert response.status_code == 200, response.text
    else:
        assert response.status_code == 503
        assert _error_code(response) == "relay_ca_unavailable"
    assert encrypted_key not in caplog.text
    if configured_password:
        assert configured_password not in caplog.text
