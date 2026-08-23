from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.v1.sessions import router
from app.core.config import settings
from app.core.security import get_current_user
from app.db.session import Base, get_db
from app.models.device import Device
from app.models.session_request import SessionRequest
from app.models.user import User
from test_relay_node_api import AsyncSessionShim


def _user(user_id: str, tenant_id: str) -> User:
    user = User(
        id=user_id,
        username=user_id,
        email=f"{user_id}@example.test",
        password_hash="unused",
        role="user",
    )
    user.tenant_id = tenant_id
    return user


def _device(owner: User, *, tenant_id: str | None = None) -> Device:
    device = Device(
        id="device-target",
        name="target",
        device_id="target-public-id",
        os="linux",
        is_bound=True,
        bound_user_id=owner.id,
    )
    device.tenant_id = tenant_id or owner.tenant_id
    return device


def _fixture(*, owner_tenant: str = "tenant-a"):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine, expire_on_commit=False)
    requester = _user("requester", "tenant-a")
    owner = _user("owner", owner_tenant)
    attacker = _user("attacker", "tenant-a")
    device = _device(owner, tenant_id=owner_tenant)
    session.add_all([requester, owner, attacker, device])
    session.commit()
    current = SimpleNamespace(user=requester)

    async def override_db():
        yield AsyncSessionShim(session)

    async def override_user():
        return current.user

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = override_user
    return engine, session, current, TestClient(app)


def _configure_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "session_grant_ttl_seconds": 120,
        "relay_policy_ttl_seconds": 90,
        "relay_policy_revision": 23,
        "relay_allowed_regions": "ap-east,eu-west",
        "relay_preferred_regions": "ap-east,eu-west",
        "relay_accepted_transports": "udp,tcp,tls",
    }
    for name, value in values.items():
        monkeypatch.setitem(settings.__dict__, name, value)


def test_session_request_requires_jwt_and_never_accepts_caller_requester_id() -> None:
    engine, session, current, client = _fixture()
    try:
        anonymous = FastAPI()
        anonymous.include_router(router, prefix="/api/v1")
        response = TestClient(anonymous).post(
            "/api/v1/sessions/request",
            json={"target_device_id": "device-target"},
        )
        assert response.status_code in {401, 403}

        created = client.post(
            "/api/v1/sessions/request",
            json={"target_device_id": "device-target"},
        )
        assert created.status_code == 200, created.text
        grant = session.scalar(select(SessionRequest))
        assert grant is not None
        assert grant.requester_user_id == current.user.id
        assert grant.tenant_id == "tenant-a"

        spoof = client.post(
            "/api/v1/sessions/request",
            json={
                "target_device_id": "device-target",
                "requester_user_id": "attacker",
            },
        )
        assert spoof.status_code == 422
        assert session.query(SessionRequest).count() == 1
    finally:
        session.close()
        engine.dispose()


def test_session_request_rejects_unbound_self_owned_and_cross_tenant_targets() -> None:
    for case in ("unbound", "self-owned", "cross-tenant"):
        owner_tenant = "tenant-b" if case == "cross-tenant" else "tenant-a"
        engine, session, current, client = _fixture(owner_tenant=owner_tenant)
        try:
            device = session.get(Device, "device-target")
            if case == "unbound":
                device.is_bound = False
                device.bound_user_id = None
            elif case == "self-owned":
                device.bound_user_id = current.user.id
            session.commit()
            response = client.post(
                "/api/v1/sessions/request",
                json={"target_device_id": "device-target"},
            )
            assert response.status_code == 403
            assert session.query(SessionRequest).count() == 0
        finally:
            session.close()
            engine.dispose()


def test_only_target_owner_can_approve_and_policy_is_server_generated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_policy(monkeypatch)
    engine, session, current, client = _fixture()
    try:
        requested = client.post(
            "/api/v1/sessions/request",
            json={"target_device_id": "device-target"},
        )
        assert requested.status_code == 200, requested.text
        request_id = requested.json()["request_id"]

        forbidden = client.post(f"/api/v1/sessions/{request_id}/approve", json={})
        assert forbidden.status_code == 403

        current.user = session.get(User, "owner")
        before = datetime.now(UTC)
        approved = client.post(f"/api/v1/sessions/{request_id}/approve", json={})
        after = datetime.now(UTC)
        assert approved.status_code == 200, approved.text
        body = approved.json()
        assert body["status"] == "approved"
        assert body["policy_revision"] == 23
        assert body["intended_peer_id"] == "device-target"
        grant = session.get(SessionRequest, request_id)
        assert grant.tenant_id == "tenant-a"
        assert grant.relay_allowed_regions == ["ap-east", "eu-west"]
        assert grant.relay_preferred_regions == ["ap-east", "eu-west"]
        assert grant.relay_accepted_transports == ["udp", "tcp", "tls"]
        grant_expiry = grant.grant_expires_at.replace(tzinfo=UTC)
        policy_expiry = grant.policy_expires_at.replace(tzinfo=UTC)
        assert before.timestamp() + 119 <= grant_expiry.timestamp()
        assert grant_expiry.timestamp() <= after.timestamp() + 121
        assert before.timestamp() + 89 <= policy_expiry.timestamp()
        assert policy_expiry.timestamp() <= after.timestamp() + 91

        conflict = client.post(f"/api/v1/sessions/{request_id}/approve", json={})
        assert conflict.status_code == 409
    finally:
        session.close()
        engine.dispose()


def test_approval_request_forbids_caller_deadline_revision_and_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_policy(monkeypatch)
    engine, session, current, client = _fixture()
    try:
        request_id = client.post(
            "/api/v1/sessions/request",
            json={"target_device_id": "device-target"},
        ).json()["request_id"]
        current.user = session.get(User, "owner")
        response = client.post(
            f"/api/v1/sessions/{request_id}/approve",
            json={
                "grant_expires_at": "2999-01-01T00:00:00Z",
                "policy_revision": 999,
                "relay_allowed_regions": ["attacker-region"],
            },
        )
        assert response.status_code == 422
        assert session.get(SessionRequest, request_id).status == "requested"
    finally:
        session.close()
        engine.dispose()
