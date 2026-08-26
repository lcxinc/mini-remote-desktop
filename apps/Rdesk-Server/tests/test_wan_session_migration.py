from __future__ import annotations

import asyncio
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.db.migrate_add_relay_access as relay_access_migration
from app.db.migrate_add_relay_access import migrate as migrate_relay_access
from app.db.migrate_add_relay_control import migrate as migrate_relay_control
from app.db.session import Base
from app.models.device import Device
from app.models.relay_access_generation import RelayAccessGeneration
from app.models.relay_node import RelayNode
from app.models.session_request import SessionRequest
from app.models.user import User


DATABASE_URL = os.getenv("MRD_TEST_DATABASE_URL")
NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)


def _asyncpg_url(url: str) -> str:
    if url.startswith("postgresql://"):
        return "postgresql+asyncpg://" + url.removeprefix("postgresql://")
    return url


def test_wan_session_models_persist_only_public_generation_state() -> None:
    session_columns = SessionRequest.__table__.columns
    required_session_columns = {
        "requester_device_id",
        "request_payload",
        "request_commitment",
        "access_mode",
        "route_policy",
        "requested_scopes",
        "requested_profile",
        "approved_scopes",
        "approved_profile",
        "active_relay_generation",
    }
    assert required_session_columns <= set(session_columns.keys())
    assert session_columns.requester_device_id.nullable
    assert session_columns.active_relay_generation.nullable

    generation = RelayAccessGeneration.__table__
    assert set(generation.primary_key.columns.keys()) == {"session_id", "generation"}
    assert {
        "session_id",
        "generation",
        "directory_id",
        "signed_directory",
        "signing_key_id",
        "signature_b64",
        "relay_url_digest",
        "primary_node_id",
        "reservation_ids",
        "expires_at",
        "created_at",
    } == set(generation.columns.keys())

    forbidden = ("username", "password", "token", "credential", "secret")
    assert not [
        column.name
        for column in generation.columns
        if any(marker in column.name.lower() for marker in forbidden)
    ]
    assert generation.columns.signed_directory.info.get("public_only") is True


def test_wan_session_models_define_closed_wan_and_generation_constraints() -> None:
    session_constraints = {
        constraint.name: str(constraint.sqltext)
        for constraint in SessionRequest.__table__.constraints
        if constraint.name and hasattr(constraint, "sqltext")
    }
    assert "ck_session_requests_wan_request_bundle" in session_constraints
    assert "ck_session_requests_wan_values" in session_constraints
    assert "ck_session_requests_wan_approval_bundle" in session_constraints
    assert "ck_session_requests_active_relay_generation" in session_constraints
    assert "attended" in session_constraints["ck_session_requests_wan_values"]
    assert "relay_only" in session_constraints["ck_session_requests_wan_values"]
    assert (
        "requester_device_id <> target_device_id"
        in session_constraints["ck_session_requests_wan_values"]
    )
    legacy_bundle = session_constraints["ck_session_requests_wan_request_bundle"]
    for field in (
        "requested_profile",
        "approved_scopes",
        "approved_profile",
        "active_relay_generation",
    ):
        assert f"{field} IS NULL" in legacy_bundle

    generation_constraints = {
        constraint.name
        for constraint in RelayAccessGeneration.__table__.constraints
        if constraint.name
    }
    assert {
        "relay_access_generations_pkey",
        "relay_access_generations_directory_id_key",
        "ck_relay_access_generations_generation",
        "ck_relay_access_generations_url_digest",
        "ck_relay_access_generations_expiry",
    } <= generation_constraints


def test_wan_session_models_create_with_the_local_sqlite_test_dialect() -> None:
    engine = create_engine("sqlite:///:memory:")
    try:
        Base.metadata.create_all(engine)
        table_names = set(inspect(engine).get_table_names())
        assert {"session_requests", "relay_access_generations"} <= table_names
    finally:
        engine.dispose()


def test_relay_access_migration_has_an_additive_v6_step() -> None:
    source = Path(relay_access_migration.__file__).read_text(encoding="utf-8")
    assert "_VERSIONS = (1, 2, 3, 4, 5, 6)" in source
    assert "CREATE TABLE IF NOT EXISTS {generations}" in source
    assert "ADD COLUMN IF NOT EXISTS requester_device_id" in source
    assert "ADD COLUMN IF NOT EXISTS active_relay_generation" in source
    assert "relay_access_generations" in source
    assert "username" not in _generation_table_sql(source).lower()
    assert "password" not in _generation_table_sql(source).lower()
    assert "credential" not in _generation_table_sql(source).lower()


def _generation_table_sql(source: str) -> str:
    start = source.index("CREATE TABLE IF NOT EXISTS {generations}")
    end = source.index('"""', start)
    return source[start:end]


@pytest.mark.skipif(
    not DATABASE_URL,
    reason=(
        "MRD_TEST_DATABASE_URL is not configured; active relay generation "
        "concurrency verification requires PostgreSQL"
    ),
)
@pytest.mark.anyio
async def test_active_generation_key_remains_unique_across_transactions() -> None:
    assert DATABASE_URL is not None
    schema = "wan_generation_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
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
            await migrate_relay_control(connection)
            await connection.run_sync(Base.metadata.create_all)
            await migrate_relay_access(connection)
        async with sessions.begin() as setup:
            setup.add_all(
                [
                    User(
                        id="wan-controller-user",
                        username="wan-controller-user",
                        email="wan-controller@example.test",
                        password_hash="unused",
                        role="user",
                        tenant_id="tenant-wan",
                    ),
                    User(
                        id="wan-target-user",
                        username="wan-target-user",
                        email="wan-target@example.test",
                        password_hash="unused",
                        role="user",
                        tenant_id="tenant-wan",
                    ),
                ]
            )
            await setup.flush()
            setup.add_all(
                [
                    Device(
                        id="wan-controller-row",
                        name="wan-controller",
                        device_id="wan-controller-public",
                        os="Linux",
                        tenant_id="tenant-wan",
                        is_bound=True,
                        bound_user_id="wan-controller-user",
                    ),
                    Device(
                        id="wan-target-row",
                        name="wan-target",
                        device_id="wan-target-public",
                        os="Linux",
                        tenant_id="tenant-wan",
                        is_bound=True,
                        bound_user_id="wan-target-user",
                    ),
                ]
            )
            await setup.flush()
            setup.add(
                RelayNode(
                    node_id="relay-node-placeholder",
                    region="test-region",
                    failure_domain="test-domain",
                    state="unavailable",
                    endpoints=["turn:relay.invalid:3478?transport=udp"],
                    certificate_fingerprint="sha256:" + "0" * 64,
                    encrypted_turn_secret=b"\x00",
                    max_allocations=1,
                    max_egress_bps=1,
                    created_at=NOW,
                    updated_at=NOW,
                )
            )
            await setup.flush()
            setup.add(
                SessionRequest(
                    id="wan-session",
                    requester_user_id="wan-controller-user",
                    requester_device_id="wan-controller-row",
                    target_device_id="wan-target-row",
                    signaling_room="wan-session",
                    tenant_id="tenant-wan",
                    status="requested",
                    request_payload={"session_id": "wan-session"},
                    request_commitment="a" * 64,
                    access_mode="attended",
                    route_policy="relay_only",
                    requested_scopes=["screen.view"],
                )
            )

        start = asyncio.Event()

        async def insert_generation(directory_id: str) -> str:
            await start.wait()
            try:
                async with sessions.begin() as transaction:
                    transaction.add(
                        RelayAccessGeneration(
                            session_id="wan-session",
                            generation=0,
                            directory_id=directory_id,
                            signed_directory={"format_version": 1},
                            signing_key_id="test-key",
                            signature_b64="cHVibGljLXNpZ25hdHVyZQ==",
                            relay_url_digest="b" * 64,
                            primary_node_id="relay-node-placeholder",
                            reservation_ids=["reservation-placeholder"],
                            expires_at=NOW + timedelta(minutes=2),
                            created_at=NOW,
                        )
                    )
                return "inserted"
            except IntegrityError:
                return "conflict"

        first = asyncio.create_task(insert_generation("directory-a"))
        second = asyncio.create_task(insert_generation("directory-b"))
        start.set()
        assert sorted(await asyncio.gather(first, second)) == ["conflict", "inserted"]
        async with sessions() as verification:
            rows = (
                await verification.execute(select(RelayAccessGeneration))
            ).scalars().all()
            assert len(rows) == 1
            assert rows[0].generation == 0
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()
