from __future__ import annotations

import asyncio
import os
import re
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.v1.devices import bind_device_owner, router
from app.core.config import settings
from app.core.security import create_access_token
from app.db.session import Base, get_db
from app.models.device import Device
from app.models.device_enrollment import DeviceEnrollment
from app.models.relay_audit_event import RelayAuditEvent
from app.models.user import User
from app.services.device_enrollment import DeviceEnrollmentService
from test_relay_node_api import AsyncSessionShim


JWT_SECRET = "vY7!qP2@kL9#sX4$mR8%tN6&wC3*eH5-zB1+uD0="
DATABASE_URL = os.getenv("MRD_TEST_DATABASE_URL")


def _configure_jwt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(settings.__dict__, "jwt_secret", SecretStr(JWT_SECRET))
    monkeypatch.setitem(settings.__dict__, "jwt_issuer", "https://auth.rdesk.test")
    monkeypatch.setitem(settings.__dict__, "jwt_audience", "rdesk-api")
    monkeypatch.setitem(settings.__dict__, "jwt_expire_minutes", 30)
    monkeypatch.setitem(settings.__dict__, "jwt_max_lifetime_minutes", 60)
    monkeypatch.setitem(
        settings.__dict__, "device_enrollment_token_pepper", SecretStr("66" * 32)
    )
    monkeypatch.setitem(settings.__dict__, "device_enrollment_ttl_seconds", 300)


def _user(user_id: str, tenant_id: str, *, role: str = "user") -> User:
    return User(
        id=user_id,
        username=user_id,
        email=f"{user_id}@example.test",
        password_hash="unused",
        role=role,
        tenant_id=tenant_id,
    )


def _device(*, owner: User | None = None) -> Device:
    return Device(
        id="device-row-a",
        name="workstation-a",
        device_id="100000000001",
        os="Linux",
        motherboard_serial="serial-a",
        hostname="host-a",
        tenant_id=owner.tenant_id if owner else "default",
        is_bound=owner is not None,
        bound_user_id=owner.id if owner else None,
    )


def _register_payload(serial: str = "serial-new") -> dict[str, object]:
    return {
        "motherboard_serial": serial,
        "hostname": "host-new",
        "os_version": "Linux 6.8",
        "device_name": "new-workstation",
    }


@pytest.fixture
def device_api(monkeypatch: pytest.MonkeyPatch):
    _configure_jwt(monkeypatch)
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine, expire_on_commit=False)
    owner = _user("owner-a", "tenant-a")
    other = _user("owner-b", "tenant-b")
    admin = _user("admin-a", "tenant-admin", role="admin")
    device = _device()
    session.add_all([owner, other, admin, device])
    session.commit()

    async def override_db():
        yield AsyncSessionShim(session)

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_db] = override_db
    client = TestClient(app)
    try:
        yield SimpleNamespace(
            app=app,
            client=client,
            session=session,
            owner=owner,
            other=other,
            admin=admin,
            device=device,
            user_token=create_access_token(owner.id, owner.username, owner.role),
            other_token=create_access_token(other.id, other.username, other.role),
            admin_token=create_access_token(admin.id, admin.username, admin.role),
            device_token=create_access_token(device.device_id, device.name, "device"),
        )
    finally:
        client.close()
        session.close()
        engine.dispose()


def _dual_headers(user_token: str, device_token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {user_token}",
        "X-Rdesk-Device-Authorization": f"Bearer {device_token}",
    }


def _issue_device_enrollment(device_api: SimpleNamespace) -> str:
    response = device_api.client.post(
        "/api/v1/devices/enrollment-tokens",
        headers={"Authorization": f"Bearer {device_api.admin_token}"},
    )
    assert response.status_code == 200, response.text
    token = response.json()["token"]
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", token)
    assert token not in repr(response)
    return token


def _enrollment_headers(token: str) -> dict[str, str]:
    return {"X-Rdesk-Device-Enrollment": token}


@pytest.mark.parametrize("route", ["bind", "auto-bind", "unbind"])
def test_device_ownership_routes_require_user_and_matching_device_proof(
    device_api: SimpleNamespace, route: str
) -> None:
    path = f"/api/v1/devices/{route}"
    payload = {"device_id": device_api.device.device_id}
    anonymous = device_api.client.post(path, json=payload)
    user_only = device_api.client.post(
        path,
        json=payload,
        headers={"Authorization": f"Bearer {device_api.user_token}"},
    )
    device_only = device_api.client.post(
        path,
        json=payload,
        headers={
            "X-Rdesk-Device-Authorization": f"Bearer {device_api.device_token}"
        },
    )
    wrong_device = device_api.client.post(
        path,
        json=payload,
        headers=_dual_headers(
            device_api.user_token,
            create_access_token("another-device", "other", "device"),
        ),
    )
    spoof = device_api.client.post(
        path,
        json={**payload, "user_id": device_api.other.id},
        headers=_dual_headers(device_api.user_token, device_api.device_token),
    )

    assert anonymous.status_code in {401, 403}
    assert user_only.status_code == 401
    assert device_only.status_code in {401, 403}
    assert wrong_device.status_code == 401
    assert spoof.status_code == 422


def test_valid_dual_auth_binds_current_user_and_is_idempotent(
    device_api: SimpleNamespace,
) -> None:
    headers = _dual_headers(device_api.user_token, device_api.device_token)
    first = device_api.client.post(
        "/api/v1/devices/bind",
        json={"device_id": device_api.device.device_id},
        headers=headers,
    )
    second = device_api.client.post(
        "/api/v1/devices/auto-bind",
        json={"device_id": device_api.device.device_id},
        headers=headers,
    )

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    device_api.session.refresh(device_api.device)
    assert device_api.device.bound_user_id == device_api.owner.id
    assert device_api.device.tenant_id == device_api.owner.tenant_id


def test_auto_bind_never_forces_another_owner_or_cross_tenant_migration(
    device_api: SimpleNamespace,
) -> None:
    device_api.device.is_bound = True
    device_api.device.bound_user_id = device_api.owner.id
    device_api.device.tenant_id = device_api.owner.tenant_id
    device_api.session.commit()

    response = device_api.client.post(
        "/api/v1/devices/auto-bind",
        json={"device_id": device_api.device.device_id},
        headers=_dual_headers(device_api.other_token, device_api.device_token),
    )

    assert response.status_code in {403, 409}
    assert device_api.owner.id not in response.text
    device_api.session.refresh(device_api.device)
    assert device_api.device.bound_user_id == device_api.owner.id
    assert device_api.device.tenant_id == device_api.owner.tenant_id


def test_existing_registration_requires_current_device_proof_or_admin(
    device_api: SimpleNamespace,
) -> None:
    payload = _register_payload(device_api.device.motherboard_serial)
    anonymous = device_api.client.post("/api/v1/devices/register", json=payload)
    anonymous_unknown = device_api.client.post(
        "/api/v1/devices/register", json=_register_payload("unknown-serial")
    )
    wrong = device_api.client.post(
        "/api/v1/devices/register",
        json=payload,
        headers={
            "X-Rdesk-Device-Authorization": "Bearer "
            + create_access_token("another-device", "other", "device")
        },
    )
    proven = device_api.client.post(
        "/api/v1/devices/register",
        json=payload,
        headers={
            "X-Rdesk-Device-Authorization": f"Bearer {device_api.device_token}"
        },
    )
    admin = device_api.client.post(
        "/api/v1/devices/register",
        json=payload,
        headers={"Authorization": f"Bearer {device_api.admin_token}"},
    )

    assert anonymous.status_code == 401
    assert anonymous_unknown.status_code == 401
    assert anonymous.json()["detail"] == anonymous_unknown.json()["detail"]
    assert wrong.status_code in {401, 403}
    assert proven.status_code == 200, proven.text
    assert admin.status_code == 200, admin.text
    assert "serial-a" not in anonymous.text + wrong.text


def test_unrelated_device_proof_cannot_enumerate_registered_serials(
    device_api: SimpleNamespace,
) -> None:
    headers = {
        "X-Rdesk-Device-Authorization": f"Bearer {device_api.device_token}"
    }
    registered_target = device_api.client.post(
        "/api/v1/devices/register",
        json=_register_payload("serial-b"),
        headers=_enrollment_headers(_issue_device_enrollment(device_api)),
    )
    assert registered_target.status_code == 200

    known = device_api.client.post(
        "/api/v1/devices/register",
        json=_register_payload("serial-b"),
        headers=headers,
    )
    unknown = device_api.client.post(
        "/api/v1/devices/register",
        json=_register_payload("not-registered"),
        headers=headers,
    )
    assert known.status_code == unknown.status_code == 403
    assert known.json()["detail"] == unknown.json()["detail"]


def test_device_enrollment_token_issuance_requires_admin(
    device_api: SimpleNamespace,
) -> None:
    anonymous = device_api.client.post("/api/v1/devices/enrollment-tokens")
    ordinary_user = device_api.client.post(
        "/api/v1/devices/enrollment-tokens",
        headers={"Authorization": f"Bearer {device_api.user_token}"},
    )
    token = _issue_device_enrollment(device_api)

    assert anonymous.status_code in {401, 403}
    assert ordinary_user.status_code == 403
    assert len(token) == 43


def test_first_registration_requires_one_time_device_enrollment(
    device_api: SimpleNamespace,
) -> None:
    payload = _register_payload()
    anonymous = device_api.client.post("/api/v1/devices/register", json=payload)
    malformed = device_api.client.post(
        "/api/v1/devices/register",
        json=payload,
        headers=_enrollment_headers("not-a-valid-token"),
    )
    token = _issue_device_enrollment(device_api)
    created = device_api.client.post(
        "/api/v1/devices/register",
        json=payload,
        headers=_enrollment_headers(token),
    )

    assert anonymous.status_code == 401
    assert malformed.status_code == 401
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["access_token"]

    not_user = device_api.client.post(
        "/api/v1/devices/bind",
        json={"device_id": body["device_id"]},
        headers={
            "Authorization": f"Bearer {body['access_token']}",
            "X-Rdesk-Device-Authorization": f"Bearer {body['access_token']}",
        },
    )
    assert not_user.status_code == 401


def test_device_enrollment_header_must_be_exactly_one_bounded_token(
    device_api: SimpleNamespace,
) -> None:
    first = _issue_device_enrollment(device_api)
    second = _issue_device_enrollment(device_api)
    duplicate = device_api.client.post(
        "/api/v1/devices/register",
        json=_register_payload("duplicate-header-serial"),
        headers=[
            ("X-Rdesk-Device-Enrollment", first),
            ("X-Rdesk-Device-Enrollment", second),
        ],
    )
    oversized = device_api.client.post(
        "/api/v1/devices/register",
        json=_register_payload("oversized-header-serial"),
        headers=_enrollment_headers("A" * 4097),
    )
    assert duplicate.status_code == 401
    assert oversized.status_code == 401
    assert duplicate.json()["detail"]["code"] == "device_enrollment_invalid"
    assert oversized.json()["detail"]["code"] == "device_enrollment_invalid"


def test_lost_first_registration_response_is_recoverable_only_for_exact_payload(
    device_api: SimpleNamespace,
) -> None:
    token = _issue_device_enrollment(device_api)
    payload = _register_payload("serial-idempotent")
    first = device_api.client.post(
        "/api/v1/devices/register",
        json=payload,
        headers=_enrollment_headers(token),
    )
    retry = device_api.client.post(
        "/api/v1/devices/register",
        json=payload,
        headers=_enrollment_headers(token),
    )
    conflict = device_api.client.post(
        "/api/v1/devices/register",
        json={**payload, "hostname": "different-host"},
        headers=_enrollment_headers(token),
    )

    assert first.status_code == 200, first.text
    assert retry.status_code == 200, retry.text
    assert retry.json()["device_id"] == first.json()["device_id"]
    assert retry.json()["access_token"]
    assert conflict.status_code == 409
    assert token not in first.text + retry.text + conflict.text


def test_enrollment_token_cannot_refresh_an_existing_device(
    device_api: SimpleNamespace,
) -> None:
    token = _issue_device_enrollment(device_api)
    original_hostname = device_api.device.hostname
    response = device_api.client.post(
        "/api/v1/devices/register",
        json={
            **_register_payload(device_api.device.motherboard_serial),
            "hostname": "attacker-host",
        },
        headers=_enrollment_headers(token),
    )

    assert response.status_code in {401, 403, 409}
    device_api.session.refresh(device_api.device)
    assert device_api.device.hostname == original_hostname


def test_openapi_requires_user_and_device_security_together(
    device_api: SimpleNamespace,
) -> None:
    schema = device_api.app.openapi()
    for route in ("bind", "auto-bind", "unbind"):
        operation = schema["paths"][f"/api/v1/devices/{route}"]["post"]
        assert operation["security"] == [
            {"HTTPBearer": [], "DeviceBearer": []}
        ]
    request_schema = schema["components"]["schemas"]["DeviceBindRequest"]
    assert "user_id" not in request_schema.get("properties", {})
    device_scheme = schema["components"]["securitySchemes"]["DeviceBearer"]
    assert device_scheme["name"] == "X-Rdesk-Device-Authorization"
    enrollment_scheme = schema["components"]["securitySchemes"]["DeviceEnrollment"]
    assert enrollment_scheme["name"] == "X-Rdesk-Device-Enrollment"
    register = schema["paths"]["/api/v1/devices/register"]["post"]
    assert {"DeviceEnrollment": []} in register["security"]
    issue = schema["paths"]["/api/v1/devices/enrollment-tokens"]["post"]
    assert issue["security"] == [{"HTTPBearer": []}]


def _asyncpg_url(url: str) -> str:
    if url.startswith("postgresql://"):
        return "postgresql+asyncpg://" + url.removeprefix("postgresql://")
    return url


@pytest.mark.skipif(not DATABASE_URL, reason="MRD_TEST_DATABASE_URL is not configured")
@pytest.mark.anyio
async def test_concurrent_first_bind_has_exactly_one_owner() -> None:
    assert DATABASE_URL is not None
    schema = "device_owner_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
    admin_engine = create_async_engine(_asyncpg_url(DATABASE_URL))
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        _asyncpg_url(DATABASE_URL),
        connect_args={"server_settings": {"search_path": schema}},
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions.begin() as setup:
            setup.add_all(
                [
                    _user("race-owner-a", "tenant-a"),
                    _user("race-owner-b", "tenant-b"),
                    Device(
                        id="race-device-row",
                        name="race-device",
                        device_id="200000000002",
                        os="Linux",
                        motherboard_serial="race-serial",
                        tenant_id="default",
                        is_bound=False,
                    ),
                ]
            )
        start = asyncio.Event()

        async def bind(user_id: str, tenant_id: str) -> str:
            async with sessions() as session:
                await start.wait()
                try:
                    async with session.begin():
                        await bind_device_owner(
                            session,
                            device_id="200000000002",
                            current_user=SimpleNamespace(
                                id=user_id, tenant_id=tenant_id
                            ),
                            now=datetime.now(UTC),
                        )
                    return "ok"
                except HTTPException as error:
                    await session.rollback()
                    return str(error.status_code)

        first = asyncio.create_task(bind("race-owner-a", "tenant-a"))
        second = asyncio.create_task(bind("race-owner-b", "tenant-b"))
        start.set()
        results = await asyncio.wait_for(
            asyncio.gather(first, second), timeout=10
        )
        assert sorted(results) == ["409", "ok"]
        async with sessions() as verification:
            device = await verification.scalar(
                select(Device).where(Device.device_id == "200000000002")
            )
            assert device.bound_user_id in {"race-owner-a", "race-owner-b"}
            assert (device.bound_user_id, device.tenant_id) in {
                ("race-owner-a", "tenant-a"),
                ("race-owner-b", "tenant-b"),
            }
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()


@pytest.mark.skipif(not DATABASE_URL, reason="MRD_TEST_DATABASE_URL is not configured")
@pytest.mark.anyio
async def test_concurrent_device_enrollment_consumption_is_one_logical_result() -> None:
    assert DATABASE_URL is not None
    schema = "device_enrollment_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
    admin_engine = create_async_engine(_asyncpg_url(DATABASE_URL))
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        _asyncpg_url(DATABASE_URL),
        connect_args={"server_settings": {"search_path": schema}},
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime(2026, 8, 23, 18, 0, tzinfo=UTC)
    raw_token = "A" * 43
    registration = _register_payload("concurrent-enrollment-serial")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions.begin() as setup:
            setup.add(_user("enrollment-admin", "tenant-admin", role="admin"))
        async with sessions.begin() as setup:
            issued = await DeviceEnrollmentService(
                setup,
                token_pepper=bytes.fromhex("66" * 32),
                ttl_seconds=300,
                now=lambda: now,
                token_source=lambda _: raw_token,
            ).issue(admin_user_id="enrollment-admin")
        assert issued.token.get_secret_value() == raw_token

        start = asyncio.Event()

        async def consume() -> tuple[str, bool]:
            async with sessions() as session:
                await start.wait()
                async with session.begin():
                    result = await DeviceEnrollmentService(
                        session,
                        token_pepper=bytes.fromhex("66" * 32),
                        ttl_seconds=300,
                        now=lambda: now,
                    ).register(
                        token=SecretStr(raw_token), registration=registration
                    )
                    return result.device.id, result.recovered

        first = asyncio.create_task(consume())
        second = asyncio.create_task(consume())
        start.set()
        results = await asyncio.wait_for(
            asyncio.gather(first, second), timeout=10
        )
        assert results[0][0] == results[1][0]
        assert sorted(result[1] for result in results) == [False, True]

        async with sessions() as verification:
            assert await verification.scalar(
                select(func.count()).select_from(Device)
            ) == 1
            enrollment = await verification.scalar(select(DeviceEnrollment))
            assert enrollment is not None
            assert enrollment.consumed_at == now
            assert enrollment.registered_device_id == results[0][0]
            assert enrollment.token_digest != raw_token
            assert raw_token not in repr(enrollment)
            actions = list(
                await verification.scalars(
                    select(RelayAuditEvent.action).order_by(RelayAuditEvent.action)
                )
            )
            assert actions == [
                "device_enrollment_consumed",
                "device_enrollment_issued",
            ]
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()
