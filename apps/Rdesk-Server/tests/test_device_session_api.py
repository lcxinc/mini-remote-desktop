from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.response_security import SensitiveResponseCacheMiddleware
from app.core.security import create_access_token, create_device_access_token
from app.db.session import Base, get_db
from app.models.device import Device
from app.models.relay_audit_event import RelayAuditEvent
from app.models.session_request import SessionRequest
from app.models.user import User
from test_relay_node_api import AsyncSessionShim


JWT_SECRET = "vY7!qP2@kL9#sX4$mR8%tN6&wC3*eH5-zB1+uD0="
GOLDEN_COMMITMENT = "d4942aab9c4cd956ba314d4d4b6c19b744cd20132de7a69b2fb18b045de41608"


@dataclass
class DeviceSessionsAPI:
    app: FastAPI
    client: TestClient
    session: Session
    devices: dict[str, Device]
    tokens: dict[str, str] = field(repr=False)
    user_token: str = field(repr=False)


def _configure_jwt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(settings.__dict__, "jwt_secret", SecretStr(JWT_SECRET))
    monkeypatch.setitem(settings.__dict__, "jwt_issuer", "https://auth.rdesk.test")
    monkeypatch.setitem(settings.__dict__, "jwt_audience", "rdesk-api")
    monkeypatch.setitem(settings.__dict__, "device_jwt_audience", "rdesk-device")
    monkeypatch.setitem(settings.__dict__, "device_jwt_expire_minutes", 30)
    monkeypatch.setitem(settings.__dict__, "jwt_expire_minutes", 30)
    monkeypatch.setitem(settings.__dict__, "jwt_max_lifetime_minutes", 60)


def _user(user_id: str, tenant_id: str) -> User:
    return User(
        id=user_id,
        username=user_id,
        email=f"{user_id}@example.test",
        password_hash="unused",
        role="user",
        tenant_id=tenant_id,
    )


def _device(
    row_id: str,
    public_id: str,
    *,
    owner: User | None,
    tenant_id: str,
) -> Device:
    return Device(
        id=row_id,
        name=row_id,
        device_id=public_id,
        os="Linux",
        tenant_id=tenant_id,
        is_bound=owner is not None,
        bound_user_id=owner.id if owner is not None else None,
    )


@pytest.fixture
def device_sessions_api(monkeypatch: pytest.MonkeyPatch):
    _configure_jwt(monkeypatch)
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine, expire_on_commit=False)

    controller_user = _user("controller-user", "tenant-a")
    target_user = _user("target-user", "tenant-a")
    intruder_user = _user("intruder-user", "tenant-a")
    foreign_user = _user("foreign-user", "tenant-b")
    controller = _device(
        "controller-row", "controller-1", owner=controller_user, tenant_id="tenant-a"
    )
    target = _device("target-row", "target-1", owner=target_user, tenant_id="tenant-a")
    same_owner_peer = _device(
        "same-owner-row",
        "same-owner-target",
        owner=controller_user,
        tenant_id="tenant-a",
    )
    intruder = _device(
        "intruder-row", "intruder-1", owner=intruder_user, tenant_id="tenant-a"
    )
    foreign = _device(
        "foreign-row", "foreign-1", owner=foreign_user, tenant_id="tenant-b"
    )
    unbound = _device("unbound-row", "unbound-1", owner=None, tenant_id="tenant-a")
    session.add_all(
        [
            controller_user,
            target_user,
            intruder_user,
            foreign_user,
            controller,
            target,
            same_owner_peer,
            intruder,
            foreign,
            unbound,
        ]
    )
    session.commit()

    async def override_db():
        yield AsyncSessionShim(session)

    app = FastAPI()
    app.add_middleware(SensitiveResponseCacheMiddleware)
    app.include_router(api_router)
    app.dependency_overrides[get_db] = override_db
    client = TestClient(app)
    devices = {
        item.device_id: item
        for item in (controller, target, same_owner_peer, intruder, foreign, unbound)
    }
    tokens = {
        public_id: create_device_access_token(device)
        for public_id, device in devices.items()
    }
    user_token = create_access_token(
        controller_user.id, controller_user.username, controller_user.role
    )
    try:
        yield DeviceSessionsAPI(
            app=app,
            client=client,
            session=session,
            devices=devices,
            tokens=tokens,
            user_token=user_token,
        )
    finally:
        client.close()
        session.close()
        engine.dispose()


def _headers(api: DeviceSessionsAPI, public_id: str) -> dict[str, str]:
    return {"X-Rdesk-Device-Authorization": f"Bearer {api.tokens[public_id]}"}


def _request(
    *,
    session_id: str = "session-1",
    target_device_id: str = "target-1",
) -> dict[str, object]:
    return {
        "session_id": session_id,
        "idempotency_key": [9] * 16,
        "target_device_id": target_device_id,
        "access_mode": "attended",
        "requested_scopes": ["input.keyboard", "screen.view"],
        "requested_profile": None,
        "route_policy": "relay_only",
    }


def _create(
    api: DeviceSessionsAPI,
    *,
    caller: str = "controller-1",
    payload: dict[str, object] | None = None,
):
    return api.client.post(
        "/api/v1/device-sessions",
        headers=_headers(api, caller),
        json=payload or _request(),
    )


def _error(response: object) -> dict[str, str]:
    return response.json()["detail"]  # type: ignore[no-any-return,attr-defined]


def test_create_inspect_and_exact_retry_use_the_rust_request_commitment(
    device_sessions_api: DeviceSessionsAPI,
) -> None:
    api = device_sessions_api
    assert DeviceSessionsAPI.__dataclass_fields__["tokens"].repr is False
    assert DeviceSessionsAPI.__dataclass_fields__["user_token"].repr is False
    created = _create(api)
    assert created.status_code == 200, created.text
    assert created.headers["cache-control"] == "no-store, private"
    assert created.headers["pragma"] == "no-cache"
    body = created.json()
    assert body == {
        "session_id": "session-1",
        "request": {
            "session_id": "session-1",
            "idempotency_key": [9] * 16,
            "controller_device_id": "controller-1",
            "target_device_id": "target-1",
            "access_mode": "attended",
            "requested_scopes": ["input.keyboard", "screen.view"],
            "requested_profile": None,
            "route_policy": "relay_only",
        },
        "request_commitment": GOLDEN_COMMITMENT,
        "status": "requested",
        "approved_scopes": None,
        "approved_profile": None,
        "policy_revision": None,
        "policy_expires_at": None,
        "grant_expires_at": None,
        "active_relay_generation": None,
    }

    row = api.session.get(SessionRequest, "session-1")
    assert row is not None
    assert row.requester_user_id == "controller-user"
    assert row.requester_device_id == "controller-row"
    assert row.target_device_id == "target-row"
    assert row.signaling_room == "session-1"
    assert row.request_payload == body["request"]
    assert row.request_commitment == GOLDEN_COMMITMENT

    inspected = api.client.get(
        "/api/v1/device-sessions/session-1",
        headers=_headers(api, "target-1"),
    )
    assert inspected.status_code == 200
    assert inspected.json() == body

    retried = _create(api)
    assert retried.status_code == 200
    assert retried.json() == body
    assert api.session.query(SessionRequest).count() == 1
    audits = list(api.session.scalars(select(RelayAuditEvent)))
    assert [(event.action, event.details) for event in audits] == [
        (
            "wan_session_requested",
            {"session_id": "session-1", "status": "requested"},
        )
    ]


def test_conflicting_reuse_and_inspection_are_privacy_preserving(
    device_sessions_api: DeviceSessionsAPI,
) -> None:
    api = device_sessions_api
    assert _create(api).status_code == 200

    changed = _request()
    changed["requested_scopes"] = ["screen.view"]
    conflict = _create(api, payload=changed)
    other_device_conflict = _create(api, caller="intruder-1")
    assert conflict.status_code == 409
    assert other_device_conflict.status_code == 409
    assert (
        _error(conflict)
        == _error(other_device_conflict)
        == {
            "code": "wan_session_conflict",
            "message": "WAN session state conflicts",
        }
    )
    assert "controller-1" not in conflict.text
    assert "target-1" not in conflict.text

    unrelated = api.client.get(
        "/api/v1/device-sessions/session-1",
        headers=_headers(api, "intruder-1"),
    )
    missing = api.client.get(
        "/api/v1/device-sessions/session-missing",
        headers=_headers(api, "intruder-1"),
    )
    assert unrelated.status_code == missing.status_code == 404
    assert (
        _error(unrelated)
        == _error(missing)
        == {
            "code": "wan_session_not_found",
            "message": "WAN session is unavailable",
        }
    )


def test_request_identity_and_closed_wan_modes_fail_closed(
    device_sessions_api: DeviceSessionsAPI,
) -> None:
    api = device_sessions_api
    self_target = _create(
        api,
        payload=_request(session_id="session-self", target_device_id="controller-1"),
    )
    cross_tenant = _create(
        api,
        payload=_request(session_id="session-foreign", target_device_id="foreign-1"),
    )
    unbound_requester = _create(
        api,
        caller="unbound-1",
        payload=_request(session_id="session-unbound"),
    )
    assert {
        self_target.status_code,
        cross_tenant.status_code,
        unbound_requester.status_code,
    } == {403}

    api.devices["target-1"].auth_revoked_at = datetime.now(UTC)
    api.session.commit()
    revoked_target = _create(
        api,
        payload=_request(session_id="session-revoked-target"),
    )
    assert revoked_target.status_code == 403
    api.devices["target-1"].auth_revoked_at = None
    api.session.commit()

    same_owner = _create(
        api,
        payload=_request(
            session_id="session-same-owner", target_device_id="same-owner-target"
        ),
    )
    assert same_owner.status_code == 200, same_owner.text

    normalized_profile = _request(session_id="session-profile")
    normalized_profile["requested_profile"] = {
        "width": 1920,
        "height": 1080,
        "fps": 60,
        "bitrate_mbps": 20,
        "codec": "+h264",
    }
    profile_response = _create(api, payload=normalized_profile)
    assert profile_response.status_code == 200, profile_response.text
    assert list(profile_response.json()["request"]["requested_profile"]) == [
        "width",
        "height",
        "fps",
        "bitrate_mbps",
        "codec",
        "codec_profile",
        "bit_depth",
        "chroma_subsampling",
        "pixel_format",
        "hdr_enabled",
        "color_mode",
        "color_pipeline",
    ]

    invalid_payloads = []
    unattended = _request(session_id="session-unattended")
    unattended["access_mode"] = "unattended"
    invalid_payloads.append(unattended)
    direct = _request(session_id="session-direct")
    direct["route_policy"] = "direct_first"
    invalid_payloads.append(direct)
    unsorted = _request(session_id="session-unsorted")
    unsorted["requested_scopes"] = ["screen.view", "input.keyboard"]
    invalid_payloads.append(unsorted)
    duplicated = _request(session_id="session-duplicated")
    duplicated["requested_scopes"] = ["screen.view", "screen.view"]
    invalid_payloads.append(duplicated)
    zero_key = _request(session_id="session-zero-key")
    zero_key["idempotency_key"] = [0] * 16
    invalid_payloads.append(zero_key)
    unknown_scope = _request(session_id="session-unknown-scope")
    unknown_scope["requested_scopes"] = ["session.admin"]
    invalid_payloads.append(unknown_scope)
    invalid_profile = _request(session_id="session-invalid-profile")
    invalid_profile["requested_profile"] = {
        "width": 1920,
        "height": 1080,
        "fps": 60,
        "bitrate_mbps": 20,
        "codec": "H264",
    }
    invalid_payloads.append(invalid_profile)
    extra = _request(session_id="session-extra")
    extra["device_token"] = "must-not-be-accepted"
    invalid_payloads.append(extra)
    for payload in invalid_payloads:
        response = _create(api, payload=payload)
        assert response.status_code == 400, response.text
        assert response.json() == {
            "detail": {
                "code": "wan_session_invalid",
                "message": "WAN session request is invalid",
            }
        }
        assert "must-not-be-accepted" not in response.text
        assert response.headers["cache-control"] == "no-store, private"


def test_only_exact_participants_can_reject_close_and_revoke_idempotently(
    device_sessions_api: DeviceSessionsAPI,
) -> None:
    api = device_sessions_api
    assert _create(api).status_code == 200
    reject_path = "/api/v1/device-sessions/session-1/reject"
    assert (
        api.client.post(
            reject_path, headers=_headers(api, "controller-1"), json={}
        ).status_code
        == 403
    )
    assert (
        api.client.post(
            reject_path, headers=_headers(api, "same-owner-target"), json={}
        ).status_code
        == 404
    )
    rejected = api.client.post(reject_path, headers=_headers(api, "target-1"), json={})
    repeated_reject = api.client.post(
        reject_path, headers=_headers(api, "target-1"), json={}
    )
    assert rejected.status_code == repeated_reject.status_code == 200
    assert rejected.json()["status"] == repeated_reject.json()["status"] == "rejected"

    close_payload = _request(session_id="session-close")
    assert _create(api, payload=close_payload).status_code == 200
    close_path = "/api/v1/device-sessions/session-close/close"
    assert (
        api.client.post(
            close_path, headers=_headers(api, "intruder-1"), json={}
        ).status_code
        == 404
    )
    closed = api.client.post(close_path, headers=_headers(api, "controller-1"), json={})
    repeated_close = api.client.post(
        close_path, headers=_headers(api, "target-1"), json={}
    )
    assert closed.status_code == repeated_close.status_code == 200
    assert closed.json()["status"] == repeated_close.json()["status"] == "closed"

    revoke_payload = _request(session_id="session-revoke")
    assert _create(api, payload=revoke_payload).status_code == 200
    grant = api.session.get(SessionRequest, "session-revoke")
    now = datetime.now(UTC)
    grant.status = "approved"
    grant.approved_scopes = ["screen.view"]
    grant.approved_profile = None
    grant.policy_revision = 7
    grant.policy_expires_at = now + timedelta(minutes=2)
    grant.grant_expires_at = now + timedelta(minutes=2)
    grant.intended_peer_id = "target-row"
    grant.relay_allowed_regions = ["test-region"]
    grant.relay_preferred_regions = ["test-region"]
    grant.relay_accepted_transports = ["udp"]
    grant.active_relay_generation = 0
    api.session.commit()
    revoke_path = "/api/v1/device-sessions/session-revoke/revoke"
    assert (
        api.client.post(
            revoke_path, headers=_headers(api, "controller-1"), json={}
        ).status_code
        == 403
    )
    revoked = api.client.post(revoke_path, headers=_headers(api, "target-1"), json={})
    repeated_revoke = api.client.post(
        revoke_path, headers=_headers(api, "target-1"), json={}
    )
    assert revoked.status_code == repeated_revoke.status_code == 200
    assert revoked.json()["status"] == repeated_revoke.json()["status"] == "revoked"

    actions = [
        event.action
        for event in api.session.scalars(
            select(RelayAuditEvent).order_by(RelayAuditEvent.created_at)
        )
    ]
    assert actions == [
        "wan_session_requested",
        "wan_session_rejected",
        "wan_session_requested",
        "wan_session_closed",
        "wan_session_requested",
        "wan_session_revoked",
    ]


def test_user_and_device_bearer_tokens_are_not_interchangeable(
    device_sessions_api: DeviceSessionsAPI,
) -> None:
    api = device_sessions_api
    path = "/api/v1/device-sessions"
    anonymous = api.client.post(path, json=_request())
    user_in_device_header = api.client.post(
        path,
        headers={"X-Rdesk-Device-Authorization": f"Bearer {api.user_token}"},
        json=_request(),
    )
    device_in_user_header = api.client.post(
        path,
        headers={"Authorization": f"Bearer {api.tokens['controller-1']}"},
        json=_request(),
    )
    assert anonymous.status_code == 401
    assert user_in_device_header.status_code == 401
    assert device_in_user_header.status_code == 401
    assert anonymous.headers["cache-control"] == "no-store, private"
    assert api.session.query(SessionRequest).count() == 0


def test_unbound_participant_tokens_lose_session_authority(
    device_sessions_api: DeviceSessionsAPI,
) -> None:
    api = device_sessions_api
    assert _create(api).status_code == 200

    controller = api.devices["controller-1"]
    controller.is_bound = False
    controller.bound_user_id = None
    api.session.commit()
    assert _create(api).status_code == 403
    assert (
        api.client.get(
            "/api/v1/device-sessions/session-1",
            headers=_headers(api, "controller-1"),
        ).status_code
        == 404
    )
    controller.is_bound = True
    controller.bound_user_id = "controller-user"
    api.session.commit()

    target = api.devices["target-1"]
    target.is_bound = False
    target.bound_user_id = None
    api.session.commit()
    assert _create(api).status_code == 403
    assert (
        api.client.get(
            "/api/v1/device-sessions/session-1",
            headers=_headers(api, "target-1"),
        ).status_code
        == 404
    )


def test_rebound_controller_device_cannot_inherit_the_original_requester(
    device_sessions_api: DeviceSessionsAPI,
) -> None:
    api = device_sessions_api
    assert _create(api).status_code == 200
    controller = api.devices["controller-1"]
    controller.bound_user_id = "intruder-user"
    api.session.commit()

    assert _create(api).status_code == 403
    assert (
        api.client.get(
            "/api/v1/device-sessions/session-1",
            headers=_headers(api, "controller-1"),
        ).status_code
        == 404
    )


def test_device_session_openapi_uses_only_closed_device_auth_contract(
    device_sessions_api: DeviceSessionsAPI,
) -> None:
    schema = device_sessions_api.app.openapi()
    create = schema["paths"]["/api/v1/device-sessions"]["post"]
    assert create["security"] == [{"DeviceBearer": []}]
    request_schema = schema["components"]["schemas"]["DeviceSessionCreateIn"]
    assert request_schema["additionalProperties"] is False
    response_schema = schema["components"]["schemas"]["DeviceSessionOut"]
    assert response_schema["additionalProperties"] is False
