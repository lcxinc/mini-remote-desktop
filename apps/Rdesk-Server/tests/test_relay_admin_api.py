from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import get_current_user_optional
from app.models.user import User
from test_relay_node_api import (
    NODE_ID,
    TLS_HEADERS,
    _approve,
    _csr,
    _enroll,
    _error_code,
    _heartbeat_request,
    _issue_token,
    api,
)


def _override_role(client: TestClient, role: str | None) -> None:
    async def override() -> User | None:
        if role is None:
            return None
        return User(
            id=f"{role}-id",
            username=role,
            email=f"{role}@example.test",
            password_hash="unused",
            role=role,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

    client.app.dependency_overrides[get_current_user_optional] = override


def test_admin_role_is_required_for_all_management_routes(api: tuple[TestClient, object]) -> None:
    client, _ = api
    routes = [
        ("POST", "/api/v1/relays/enrollment-tokens", {"ttl_seconds": 300}),
        ("GET", "/api/v1/relays", None),
        ("POST", f"/api/v1/relays/{NODE_ID}/approve", None),
        ("POST", f"/api/v1/relays/{NODE_ID}/drain", None),
        ("POST", f"/api/v1/relays/{NODE_ID}/resume", None),
        ("POST", f"/api/v1/relays/{NODE_ID}/revoke", None),
    ]
    for role in (None, "user"):
        _override_role(client, role)
        for method, path, body in routes:
            response = client.request(method, path, json=body)
            assert response.status_code == 403, (method, path, response.text)
            assert _error_code(response) == "relay_admin_required"


def test_admin_approval_list_drain_resume_and_irreversible_revoke(
    api: tuple[TestClient, object],
) -> None:
    client, _ = api
    _enroll(client)
    _approve(client)

    listed = client.get("/api/v1/relays")
    assert listed.status_code == 200
    assert listed.json()[0]["node_id"] == NODE_ID
    assert listed.json()[0]["state"] == "unavailable"
    assert "encrypted_turn_secret" not in listed.text
    assert "signing_public_key" not in listed.text

    drained = client.post(f"/api/v1/relays/{NODE_ID}/drain")
    assert drained.status_code == 200
    assert drained.json()["state"] == "draining"
    resumed = client.post(f"/api/v1/relays/{NODE_ID}/resume")
    assert resumed.status_code == 200
    assert resumed.json()["state"] == "unavailable"
    revoked = client.post(f"/api/v1/relays/{NODE_ID}/revoke")
    assert revoked.status_code == 200
    assert revoked.json()["state"] == "revoked"
    again = client.post(f"/api/v1/relays/{NODE_ID}/revoke")
    assert again.status_code == 200
    assert again.json()["state"] == "revoked"
    resume = client.post(f"/api/v1/relays/{NODE_ID}/resume")
    assert resume.status_code == 409
    assert _error_code(resume) == "relay_node_revoked"


def test_enrollment_heartbeat_and_admin_transitions_are_durably_audited(
    api: tuple[TestClient, object],
) -> None:
    from app.models.relay_audit_event import RelayAuditEvent

    client, engine = api
    key, _ = _enroll(client)
    _, fingerprint = _approve(client)
    body, headers = _heartbeat_request(key, fingerprint)
    assert client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat", content=body, headers=headers
    ).status_code == 200
    for action in ("drain", "resume", "revoke"):
        assert client.post(f"/api/v1/relays/{NODE_ID}/{action}").status_code == 200

    with Session(engine) as session:
        events = list(
            session.scalars(
                select(RelayAuditEvent).order_by(RelayAuditEvent.created_at)
            )
        )
    actions = [event.action for event in events]
    assert actions == [
        "relay_enrollment_token_issued",
        "relay_enrollment_requested",
        "relay_node_approved",
        "relay_heartbeat_recorded",
        "relay_node_drained",
        "relay_node_resumed",
        "relay_node_revoked",
    ]
    assert all("token" not in str(event.details).lower() for event in events)
    assert all("signature" not in str(event.details).lower() for event in events)


def test_secrets_and_raw_auth_material_are_not_logged(
    api: tuple[TestClient, object], caplog: object
) -> None:
    client, _ = api
    caplog.set_level(logging.DEBUG)  # type: ignore[attr-defined]
    token = _issue_token(client)
    csr_pem, key = _csr(NODE_ID)
    request_private_key = key.private_bytes_raw().hex()
    response = client.post(
        "/api/v1/relays/enroll",
        headers={**TLS_HEADERS, "Authorization": "Bearer raw-auth-secret"},
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
    assert response.status_code == 202
    _, fingerprint = _approve(client)
    body, headers = _heartbeat_request(key, fingerprint)
    raw_signature = headers["X-Relay-Signature"]
    assert client.post(
        f"/api/v1/relays/{NODE_ID}/heartbeat", content=body, headers=headers
    ).status_code == 200

    output = caplog.text  # type: ignore[attr-defined]
    for secret in (
        token,
        request_private_key,
        raw_signature,
        "raw-auth-secret",
        settings.relay_ca_private_key_pem,
    ):
        assert secret not in output


def test_relay_registration_and_audit_tables_are_in_explicit_migration() -> None:
    migration = (
        Path(__file__).parents[1] / "app" / "db" / "migrate_add_relay_control.py"
    ).read_text(encoding="utf-8")
    assert "CREATE TABLE IF NOT EXISTS {registrations}" in migration
    assert "CREATE TABLE IF NOT EXISTS {audit_events}" in migration
    assert "relay_node_registrations" in migration
    assert "relay_audit_events" in migration
    assert '"relay_node_registrations", schema=schema' in migration
    assert "relay registration check constraints differ" in migration
