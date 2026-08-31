from __future__ import annotations

import asyncio
import os
import re
from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import jwt
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
from app.core.security import create_access_token, create_device_access_token
from app.db.session import Base, get_db
from app.models.device import Device
from app.models.device_enrollment import DeviceEnrollment
from app.models.relay_audit_event import RelayAuditEvent
from app.models.user import User
from app.services.device_enrollment import (
    DeviceEnrollmentError,
    DeviceEnrollmentService,
    device_serial_digest,
)
from test_relay_node_api import AsyncSessionShim


JWT_SECRET = "vY7!qP2@kL9#sX4$mR8%tN6&wC3*eH5-zB1+uD0="
SERIAL_PEPPER = bytes.fromhex("67" * 32)
DATABASE_URL = os.getenv("MRD_TEST_DATABASE_URL")


def _configure_jwt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(settings.__dict__, "jwt_secret", SecretStr(JWT_SECRET))
    monkeypatch.setitem(settings.__dict__, "jwt_issuer", "https://auth.rdesk.test")
    monkeypatch.setitem(settings.__dict__, "jwt_audience", "rdesk-api")
    monkeypatch.setitem(settings.__dict__, "device_jwt_audience", "rdesk-device")
    monkeypatch.setitem(settings.__dict__, "device_jwt_expire_minutes", 30)
    monkeypatch.setitem(settings.__dict__, "jwt_expire_minutes", 30)
    monkeypatch.setitem(settings.__dict__, "jwt_max_lifetime_minutes", 60)
    monkeypatch.setitem(
        settings.__dict__, "device_enrollment_token_pepper", SecretStr("66" * 32)
    )
    monkeypatch.setitem(
        settings.__dict__, "device_serial_pepper", SecretStr("67" * 32)
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
        motherboard_serial=None,
        motherboard_serial_digest=device_serial_digest(
            "serial-a", SERIAL_PEPPER
        ),
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
            device_token=create_device_access_token(device),
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
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"
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
    payload = _register_payload("serial-a")
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
    assert created.headers["cache-control"] == "no-store, private"
    assert created.headers["pragma"] == "no-cache"
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
            **_register_payload("serial-a"),
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


def test_device_registration_check_rejects_non_admin_before_serial_query(
    device_api: SimpleNamespace,
) -> None:
    serial_queries: list[str] = []

    class SerialQuerySpy(AsyncSessionShim):
        async def scalar(self, *args: object, **kwargs: object) -> object:
            statement = str(args[0]) if args else ""
            if "devices.motherboard_serial_digest" in statement:
                serial_queries.append(statement)
            return await super().scalar(*args, **kwargs)

    async def override_db():
        yield SerialQuerySpy(device_api.session)

    device_api.app.dependency_overrides[get_db] = override_db
    headers_by_caller = (
        {},
        {"Authorization": f"Bearer {device_api.user_token}"},
        {
            "X-Rdesk-Device-Authorization":
                f"Bearer {device_api.device_token}"
        },
    )
    for headers in headers_by_caller:
        known = device_api.client.post(
            "/api/v1/devices/inventory/check",
            json={"motherboard_serial": "serial-a"},
            headers=headers,
        )
        unknown = device_api.client.post(
            "/api/v1/devices/inventory/check",
            json={"motherboard_serial": "serial-unknown"},
            headers=headers,
        )
        assert known.status_code == unknown.status_code == 403
        assert known.json() == unknown.json()

    assert serial_queries == []


def test_device_registration_check_is_admin_inventory_only(
    device_api: SimpleNamespace,
) -> None:
    headers = {"Authorization": f"Bearer {device_api.admin_token}"}

    known = device_api.client.post(
        "/api/v1/devices/inventory/check",
        json={"motherboard_serial": "serial-a"},
        headers=headers,
    )
    unknown = device_api.client.post(
        "/api/v1/devices/inventory/check",
        json={"motherboard_serial": "serial-unknown"},
        headers=headers,
    )

    assert known.status_code == unknown.status_code == 200
    assert known.json() == {
        "registered": True,
        "device_id": device_api.device.device_id,
        "device_name": device_api.device.name,
        "is_bound": False,
    }
    assert unknown.json() == {"registered": False}
    operation = device_api.app.openapi()["paths"][
        "/api/v1/devices/inventory/check"
    ]["post"]
    assert operation["security"] == [{"HTTPBearer": []}]


def test_device_reads_are_tenant_and_owner_scoped(
    device_api: SimpleNamespace,
) -> None:
    same_tenant_other = _user("owner-c", device_api.owner.tenant_id)
    owned = device_api.device
    owned.is_bound = True
    owned.bound_user_id = device_api.owner.id
    owned.tenant_id = device_api.owner.tenant_id
    same_tenant_foreign = Device(
        id="device-row-c",
        name="same-tenant-foreign",
        device_id="100000000003",
        os="Linux",
        motherboard_serial_digest=device_serial_digest(
            "serial-c", SERIAL_PEPPER
        ),
        tenant_id=device_api.owner.tenant_id,
        is_bound=True,
        bound_user_id=same_tenant_other.id,
    )
    cross_tenant = Device(
        id="device-row-b",
        name="cross-tenant",
        device_id="100000000002",
        os="Linux",
        motherboard_serial_digest=device_serial_digest(
            "serial-b", SERIAL_PEPPER
        ),
        tenant_id=device_api.other.tenant_id,
        is_bound=True,
        bound_user_id=device_api.other.id,
    )
    device_api.session.add_all(
        [same_tenant_other, same_tenant_foreign, cross_tenant]
    )
    device_api.session.commit()
    owner_headers = {"Authorization": f"Bearer {device_api.user_token}"}
    admin_headers = {"Authorization": f"Bearer {device_api.admin_token}"}

    anonymous = device_api.client.get("/api/v1/devices")
    owner_list = device_api.client.get("/api/v1/devices", headers=owner_headers)
    admin_list = device_api.client.get("/api/v1/devices", headers=admin_headers)

    assert anonymous.status_code in {401, 403}
    assert [item["device_id"] for item in owner_list.json()] == [owned.device_id]
    assert {item["device_id"] for item in admin_list.json()} >= {
        owned.device_id,
        same_tenant_foreign.device_id,
        cross_tenant.device_id,
    }
    assert device_api.client.get(
        f"/api/v1/devices/{same_tenant_foreign.id}", headers=owner_headers
    ).status_code == 404
    assert device_api.client.get(
        f"/api/v1/devices/{cross_tenant.id}", headers=owner_headers
    ).status_code == 404
    assert device_api.client.get(
        f"/api/v1/devices/{owned.id}", headers=owner_headers
    ).status_code == 200
    assert device_api.client.get(
        f"/api/v1/devices/{cross_tenant.id}", headers=admin_headers
    ).status_code == 200

    anonymous_status = device_api.client.get(
        f"/api/v1/devices/{owned.device_id}/binding-status"
    )
    foreign_status = device_api.client.get(
        f"/api/v1/devices/{owned.device_id}/binding-status",
        headers={"Authorization": f"Bearer {device_api.other_token}"},
    )
    owner_status = device_api.client.get(
        f"/api/v1/devices/{owned.device_id}/binding-status",
        headers=owner_headers,
    )
    assert anonymous_status.status_code in {401, 403}
    assert foreign_status.status_code == 404
    assert owned.bound_user_id not in foreign_status.text
    assert owner_status.status_code == 200
    assert owner_status.json()["bound_user_id"] == device_api.owner.id


def test_device_rename_requires_owner_and_matching_device_or_admin(
    device_api: SimpleNamespace,
) -> None:
    device_api.device.is_bound = True
    device_api.device.bound_user_id = device_api.owner.id
    device_api.device.tenant_id = device_api.owner.tenant_id
    device_api.session.commit()
    path = f"/api/v1/devices/{device_api.device.device_id}/rename"
    owner_only = device_api.client.patch(
        path,
        json={"name": "owner-only"},
        headers={"Authorization": f"Bearer {device_api.user_token}"},
    )
    wrong_device = device_api.client.patch(
        path,
        json={"name": "wrong-device"},
        headers=_dual_headers(
            device_api.user_token,
            create_access_token("different-device", "other", "device"),
        ),
    )
    valid = device_api.client.patch(
        path,
        json={"name": "owner-renamed"},
        headers=_dual_headers(device_api.user_token, device_api.device_token),
    )
    admin = device_api.client.patch(
        path,
        json={"name": "admin-renamed"},
        headers={"Authorization": f"Bearer {device_api.admin_token}"},
    )

    assert owner_only.status_code in {401, 403}
    assert wrong_device.status_code in {401, 403}
    assert valid.status_code == 200
    assert admin.status_code == 200
    device_api.session.refresh(device_api.device)
    assert device_api.device.name == "admin-renamed"

    device_api.device.is_bound = False
    device_api.device.bound_user_id = None
    device_api.session.commit()
    unbound = device_api.client.patch(
        path,
        json={"name": "unbound-user-write"},
        headers=_dual_headers(device_api.user_token, device_api.device_token),
    )
    assert unbound.status_code in {403, 404}


def test_device_token_has_independent_context_and_rotation_revokes_old_token(
    device_api: SimpleNamespace,
) -> None:
    device_api.device.is_bound = True
    device_api.device.bound_user_id = device_api.owner.id
    device_api.device.tenant_id = device_api.owner.tenant_id
    device_api.session.commit()
    rotate_path = (
        f"/api/v1/devices/{device_api.device.device_id}/credentials/rotate"
    )

    rotated = device_api.client.post(
        rotate_path,
        headers=_dual_headers(device_api.user_token, device_api.device_token),
    )

    assert rotated.status_code == 200, rotated.text
    new_token = rotated.json()["access_token"]
    claims = jwt.decode(new_token, options={"verify_signature": False})
    assert claims["aud"] == "rdesk-device"
    assert claims["token_type"] == "device"
    assert claims["device_id"] == device_api.device.device_id
    assert claims["auth_version"] == 2
    old_rejected = device_api.client.post(
        "/api/v1/devices/auto-bind",
        json={"device_id": device_api.device.device_id},
        headers=_dual_headers(device_api.user_token, device_api.device_token),
    )
    assert old_rejected.status_code == 401

    revoked = device_api.client.post(
        f"/api/v1/devices/{device_api.device.device_id}/credentials/revoke",
        headers={"Authorization": f"Bearer {device_api.admin_token}"},
    )
    assert revoked.status_code == 200
    new_rejected = device_api.client.post(
        "/api/v1/devices/auto-bind",
        json={"device_id": device_api.device.device_id},
        headers=_dual_headers(device_api.user_token, new_token),
    )
    assert new_rejected.status_code == 401

    admin_rotated = device_api.client.post(
        f"/api/v1/devices/{device_api.device.device_id}/credentials/admin-rotate",
        headers={"Authorization": f"Bearer {device_api.admin_token}"},
    )
    assert admin_rotated.status_code == 200
    assert jwt.decode(
        admin_rotated.json()["access_token"],
        options={"verify_signature": False},
    )["auth_version"] == 4


def test_serial_inventory_uses_admin_post_and_registration_stores_digest_only(
    device_api: SimpleNamespace,
) -> None:
    admin_headers = {"Authorization": f"Bearer {device_api.admin_token}"}
    old_path = device_api.client.get(
        "/api/v1/devices/check/serial-a", headers=admin_headers
    )
    inventory = device_api.client.post(
        "/api/v1/devices/inventory/check",
        json={"motherboard_serial": "serial-a"},
        headers=admin_headers,
    )
    assert old_path.status_code == 404
    assert inventory.status_code == 200
    assert "serial-a" not in repr(inventory.request.url)
    assert not any(
        "motherboard_serial" in path
        for path in device_api.app.openapi()["paths"]
    )

    token = _issue_device_enrollment(device_api)
    registered = device_api.client.post(
        "/api/v1/devices/register",
        json=_register_payload("serial-private-new"),
        headers=_enrollment_headers(token),
    )
    assert registered.status_code == 200, registered.text
    row = device_api.session.scalar(
        select(Device).where(
            Device.device_id == registered.json()["device_id"]
        )
    )
    assert row is not None
    assert row.motherboard_serial is None
    assert re.fullmatch(
        r"[0-9a-f]{64}", getattr(row, "motherboard_serial_digest", "")
    )


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
                        motherboard_serial=None,
                        motherboard_serial_digest=device_serial_digest(
                            "race-serial", SERIAL_PEPPER
                        ),
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
                serial_pepper=SERIAL_PEPPER,
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
                        serial_pepper=SERIAL_PEPPER,
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


@pytest.mark.skipif(not DATABASE_URL, reason="MRD_TEST_DATABASE_URL is not configured")
@pytest.mark.anyio
async def test_different_enrollment_tokens_for_one_serial_conflict_stably() -> None:
    assert DATABASE_URL is not None
    schema = "device_serial_race_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
    admin_engine = create_async_engine(_asyncpg_url(DATABASE_URL))
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        _asyncpg_url(DATABASE_URL),
        connect_args={"server_settings": {"search_path": schema}},
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime(2026, 8, 23, 18, 30, tzinfo=UTC)
    token_pepper = bytes.fromhex("66" * 32)
    tokens = ("A" * 43, "B" * 43)
    registration = _register_payload("same-physical-serial")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions.begin() as setup:
            setup.add(_user("serial-race-admin", "tenant-admin", role="admin"))
        issued_tokens: list[str] = []
        for raw_token in tokens:
            async with sessions.begin() as setup:
                issued = await DeviceEnrollmentService(
                    setup,
                    token_pepper=token_pepper,
                    serial_pepper=SERIAL_PEPPER,
                    ttl_seconds=300,
                    now=lambda: now,
                    token_source=lambda _, value=raw_token: value,
                ).issue(admin_user_id="serial-race-admin")
                issued_tokens.append(issued.token.get_secret_value())

        start = asyncio.Event()

        async def consume(raw_token: str) -> str:
            async with sessions() as session:
                await start.wait()
                try:
                    async with session.begin():
                        await DeviceEnrollmentService(
                            session,
                            token_pepper=token_pepper,
                            serial_pepper=SERIAL_PEPPER,
                            ttl_seconds=300,
                            now=lambda: now,
                        ).register(
                            token=SecretStr(raw_token),
                            registration=registration,
                        )
                    return "ok"
                except DeviceEnrollmentError as error:
                    await session.rollback()
                    return error.code

        first = asyncio.create_task(consume(issued_tokens[0]))
        second = asyncio.create_task(consume(issued_tokens[1]))
        start.set()
        results = await asyncio.wait_for(
            asyncio.gather(first, second), timeout=10
        )
        assert sorted(results) == ["device_enrollment_conflict", "ok"]
        async with sessions() as verification:
            assert await verification.scalar(
                select(func.count()).select_from(Device)
            ) == 1
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()
