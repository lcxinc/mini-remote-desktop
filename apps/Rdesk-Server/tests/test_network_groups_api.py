from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.v1.network_groups import router
from app.core.security import get_current_user
from app.db.session import Base, get_db
from app.models.device import Device, DeviceStatus
from app.models.device_network_group import DeviceNetworkGroup
from app.models.network_group import NetworkGroup
from app.models.user import User


class AsyncSessionShim:
    def __init__(self, session: Session) -> None:
        self.session = session

    def add(self, instance: object) -> None:
        self.session.add(instance)

    async def scalar(self, *args: object, **kwargs: object) -> object:
        return self.session.scalar(*args, **kwargs)

    async def scalars(self, *args: object, **kwargs: object) -> object:
        return self.session.scalars(*args, **kwargs)

    async def execute(self, *args: object, **kwargs: object) -> object:
        return self.session.execute(*args, **kwargs)

    async def commit(self) -> None:
        self.session.commit()

    async def refresh(self, instance: object) -> None:
        self.session.refresh(instance)


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
    name: str,
    *,
    tenant_id: str,
    owner_id: str | None,
) -> Device:
    return Device(
        id=row_id,
        name=name,
        device_id=public_id,
        os="Linux",
        tenant_id=tenant_id,
        is_bound=owner_id is not None,
        bound_user_id=owner_id,
    )


@pytest.fixture
def network_group_api():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine, expire_on_commit=False)
    owner = _user("owner-a", "tenant-a")
    same_tenant_user = _user("owner-a-peer", "tenant-a")
    foreign_user = _user("owner-b", "tenant-b")
    group = NetworkGroup(
        id="group-a",
        user_id=owner.id,
        name="owner group",
        description=None,
        is_enabled=True,
    )
    own = _device(
        "row-own", "100000000001", "own-device", tenant_id="tenant-a", owner_id=owner.id
    )
    same_tenant_other = _device(
        "row-peer",
        "100000000002",
        "same-tenant-other-owner",
        tenant_id="tenant-a",
        owner_id=same_tenant_user.id,
    )
    foreign = _device(
        "row-foreign",
        "100000000003",
        "foreign-device",
        tenant_id="tenant-b",
        owner_id=foreign_user.id,
    )
    unbound = _device(
        "row-unbound",
        "100000000004",
        "unbound-device",
        tenant_id="tenant-a",
        owner_id=None,
    )
    session.add_all(
        [
            owner,
            same_tenant_user,
            foreign_user,
            group,
            own,
            same_tenant_other,
            foreign,
            unbound,
            DeviceStatus(id="status-own", device_id=own.id, status="online"),
            DeviceStatus(id="status-foreign", device_id=foreign.id, status="online"),
        ]
    )
    session.commit()

    async def override_db():
        yield AsyncSessionShim(session)

    async def override_user() -> User:
        return owner

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = override_user
    client = TestClient(app)
    try:
        yield SimpleNamespace(
            client=client,
            session=session,
            group=group,
            own=own,
            same_tenant_other=same_tenant_other,
            foreign=foreign,
            unbound=unbound,
        )
    finally:
        client.close()
        session.close()
        engine.dispose()


def test_add_devices_accepts_only_the_current_users_bound_tenant_devices(
    network_group_api: SimpleNamespace,
) -> None:
    fixture = network_group_api
    response = fixture.client.post(
        f"/api/v1/network-groups/{fixture.group.id}/devices",
        json={
            "device_ids": [
                fixture.own.device_id,
                fixture.same_tenant_other.device_id,
                fixture.foreign.device_id,
                fixture.unbound.device_id,
            ]
        },
    )
    assert response.status_code == 201, response.text

    associations = fixture.session.scalars(select(DeviceNetworkGroup)).all()
    assert [
        (association.device_id, association.network_group_id)
        for association in associations
    ] == [(fixture.own.id, fixture.group.id)]


def test_legacy_foreign_associations_are_hidden_and_cannot_be_mutated(
    network_group_api: SimpleNamespace,
) -> None:
    fixture = network_group_api
    fixture.session.add_all(
        [
            DeviceNetworkGroup(
                id=f"assoc-{device.id}",
                network_group_id=fixture.group.id,
                device_id=device.id,
                is_enabled=True,
            )
            for device in (
                fixture.own,
                fixture.same_tenant_other,
                fixture.foreign,
                fixture.unbound,
            )
        ]
    )
    fixture.session.commit()

    listed = fixture.client.get(f"/api/v1/network-groups/{fixture.group.id}/devices")
    assert listed.status_code == 200, listed.text
    assert [device["device_id"] for device in listed.json()] == [fixture.own.device_id]
    rendered = listed.text
    for forbidden in (
        fixture.same_tenant_other.device_id,
        fixture.foreign.device_id,
        fixture.unbound.device_id,
    ):
        assert forbidden not in rendered

    group = fixture.client.get(f"/api/v1/network-groups/{fixture.group.id}")
    assert group.status_code == 200, group.text
    assert group.json()["device_count"] == 1
    assert group.json()["online_device_count"] == 1
    groups = fixture.client.get("/api/v1/network-groups")
    assert groups.status_code == 200, groups.text
    listed_group = next(
        item for item in groups.json() if item["id"] == fixture.group.id
    )
    assert listed_group["device_count"] == 1
    assert listed_group["online_device_count"] == 1

    for device in (fixture.same_tenant_other, fixture.foreign, fixture.unbound):
        patched = fixture.client.patch(
            f"/api/v1/network-groups/{fixture.group.id}/devices/{device.device_id}",
            json={"is_enabled": False},
        )
        removed = fixture.client.delete(
            f"/api/v1/network-groups/{fixture.group.id}/devices/{device.device_id}"
        )
        assert patched.status_code == 404
        assert removed.status_code == 404
        association = fixture.session.get(DeviceNetworkGroup, f"assoc-{device.id}")
        assert association is not None
        assert association.is_enabled is True

    own_patch = fixture.client.patch(
        f"/api/v1/network-groups/{fixture.group.id}/devices/{fixture.own.device_id}",
        json={"is_enabled": False},
    )
    assert own_patch.status_code == 204
    own_remove = fixture.client.delete(
        f"/api/v1/network-groups/{fixture.group.id}/devices/{fixture.own.device_id}"
    )
    assert own_remove.status_code == 204
