from __future__ import annotations

import asyncio
import os
import re
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.db.migrate_add_relay_access as relay_access_migration
from app.db.migrate_add_relay_access import migrate as migrate_relay_access
from app.db.migrate_add_relay_control import migrate as migrate_relay_control
from app.db.session import Base
from app.models.device import Device
from app.models.relay_enrollment import RelayEnrollment
from app.models.relay_node import RelayNode
from app.models.relay_node_registration import RelayNodeRegistration
from app.models.relay_reservation import RelayReservation
from app.models.session_request import SessionRequest
from app.models.user import User
from app.services.relay_directory import RelayAccessError, RelayAccessService
from app.services.relay_repository import AesGcmRelaySecretCipher, RelayRepository
from app.services.relay_signing import Ed25519RelayDirectorySigner
from app.services.turn_credentials import NodeTurnCredentialService


DATABASE_URL = os.getenv("MRD_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="MRD_TEST_DATABASE_URL is not configured; relay access concurrency skipped",
)
NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def asyncpg_url(url: str) -> str:
    if url.startswith("postgresql://"):
        return "postgresql+asyncpg://" + url.removeprefix("postgresql://")
    return url


@pytest.mark.anyio
@pytest.mark.parametrize(
    "malformation",
    [
        "ALTER TABLE session_requests ALTER COLUMN intended_peer_id TYPE TEXT",
        "ALTER TABLE session_requests DROP CONSTRAINT ck_session_requests_status; "
        "ALTER TABLE session_requests ADD CONSTRAINT ck_session_requests_status "
        "CHECK (status IS NOT NULL)",
    ],
)
async def test_access_migration_rejects_wrong_types_and_weakened_constraints(
    malformation: str,
) -> None:
    assert DATABASE_URL is not None
    schema = "relay_access_bad_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
    admin_engine = create_async_engine(asyncpg_url(DATABASE_URL))
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        asyncpg_url(DATABASE_URL),
        connect_args={"server_settings": {"search_path": schema}},
    )
    try:
        async with engine.begin() as connection:
            await migrate_relay_control(connection)
            await connection.run_sync(Base.metadata.create_all)
            for statement in malformation.split("; "):
                await connection.execute(text(statement))
        with pytest.raises(relay_access_migration.RelayAccessMigrationError):
            await migrate_relay_access(engine)
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()


@pytest.mark.anyio
@pytest.mark.parametrize(
    "malformation",
    [
        "DROP INDEX ix_session_requests_tenant_id; CREATE UNIQUE INDEX "
        "ix_session_requests_tenant_id ON session_requests (tenant_id)",
        "ALTER TABLE session_requests ALTER COLUMN intended_peer_id "
        "SET DEFAULT 'spoof'",
        "ALTER TABLE relay_node_registrations ALTER COLUMN physical_host_id "
        "SET DEFAULT 'untrusted-host'",
        "ALTER TABLE relay_access_schema_migrations ALTER COLUMN version TYPE BIGINT",
        "ALTER TABLE relay_access_schema_migrations ALTER COLUMN applied_at DROP DEFAULT",
        "ALTER TABLE relay_access_schema_migrations DROP CONSTRAINT "
        "relay_access_schema_migrations_pkey",
        "INSERT INTO relay_access_schema_migrations (version) VALUES (999)",
    ],
)
async def test_access_migration_rejects_malformed_ledger_and_index_semantics(
    malformation: str,
) -> None:
    assert DATABASE_URL is not None
    schema = "relay_access_exact_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
    admin_engine = create_async_engine(asyncpg_url(DATABASE_URL))
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        asyncpg_url(DATABASE_URL),
        connect_args={"server_settings": {"search_path": schema}},
    )
    try:
        async with engine.begin() as connection:
            await migrate_relay_control(connection)
            await connection.run_sync(Base.metadata.create_all)
            await migrate_relay_access(connection)
            for statement in malformation.split("; "):
                await connection.execute(text(statement))
        with pytest.raises(relay_access_migration.RelayAccessMigrationError):
            await migrate_relay_access(engine)
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()


@pytest.mark.anyio
async def test_access_migration_normalizes_legacy_device_owner_state() -> None:
    assert DATABASE_URL is not None
    schema = "relay_access_owner_backfill_" + re.sub(
        r"[^a-z0-9]", "", uuid4().hex
    )
    admin_engine = create_async_engine(asyncpg_url(DATABASE_URL))
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        asyncpg_url(DATABASE_URL),
        connect_args={"server_settings": {"search_path": schema}},
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with engine.begin() as connection:
            await migrate_relay_control(connection)
            await connection.run_sync(Base.metadata.create_all)
            await connection.execute(
                text("ALTER TABLE devices DROP CONSTRAINT ck_devices_bound_owner")
            )
            await connection.execute(
                text("ALTER TABLE devices ALTER COLUMN tenant_id DROP NOT NULL")
            )
        async with sessions.begin() as setup:
            owner = User(
                id="legacy-owner",
                username="legacy-owner",
                email="legacy-owner@example.test",
                password_hash="unused",
                role="user",
                tenant_id="tenant-a",
            )
            setup.add(owner)
        async with sessions.begin() as setup:
            setup.add_all(
                [
                    Device(
                        id="legacy-owned-row",
                        name="legacy-owned",
                        device_id="legacy-owned-device",
                        os="Linux",
                        tenant_id="default",
                        is_bound=False,
                        bound_user_id=owner.id,
                    ),
                    Device(
                        id="legacy-ownerless-row",
                        name="legacy-ownerless",
                        device_id="legacy-ownerless-device",
                        os="Linux",
                        tenant_id="default",
                        is_bound=True,
                        bound_user_id=None,
                    ),
                    Device(
                        id="legacy-valid-row",
                        name="legacy-valid",
                        device_id="legacy-valid-device",
                        os="Linux",
                        tenant_id="default",
                        is_bound=True,
                        bound_user_id=owner.id,
                    ),
                ]
            )
        async with engine.begin() as connection:
            await connection.execute(text("UPDATE devices SET tenant_id = NULL"))

        await migrate_relay_access(engine)

        async with sessions() as verification:
            devices = {
                device.device_id: device
                for device in (
                    await verification.scalars(select(Device))
                ).all()
            }
            owned = devices["legacy-owned-device"]
            assert owned.is_bound is False
            assert owned.bound_user_id is None
            assert owned.tenant_id == "default"
            ownerless = devices["legacy-ownerless-device"]
            assert ownerless.is_bound is False
            assert ownerless.bound_user_id is None
            assert ownerless.tenant_id == "default"
            valid = devices["legacy-valid-device"]
            assert valid.is_bound is True
            assert valid.bound_user_id == "legacy-owner"
            assert valid.tenant_id == "tenant-a"
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()


@pytest.mark.anyio
async def test_concurrent_directory_issuance_never_oversubscribes_real_postgres():
    assert DATABASE_URL is not None
    schema = "relay_access_test_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
    admin_engine = create_async_engine(asyncpg_url(DATABASE_URL))
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        asyncpg_url(DATABASE_URL),
        connect_args={"server_settings": {"search_path": schema}},
    )
    cipher = AesGcmRelaySecretCipher(bytes.fromhex("51" * 32))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with engine.begin() as connection:
            await migrate_relay_control(connection)
            await connection.run_sync(Base.metadata.create_all)
            await migrate_relay_access(connection)
            await migrate_relay_access(connection)
        async with sessions() as setup:
            for index, (node_id, domain, capacity) in enumerate(
                (
                    ("relay-a", "rack-primary", 1),
                    ("relay-b", "rack-primary", 1),
                    ("relay-c", "rack-backup", 2),
                ),
                start=1,
            ):
                enrollment = RelayEnrollment(
                    id=f"pg-enrollment-{index}", token_digest=f"{index:064x}",
                    expires_at=NOW + timedelta(hours=1), used_at=NOW,
                    enrolled_node_id=node_id, created_at=NOW,
                )
                encrypted_secret = cipher.encrypt(
                    f"real-postgres-secret-{node_id}".encode(),
                    associated_data=node_id.encode(),
                )
                node = RelayNode(
                    node_id=node_id, region="ap-east", failure_domain=domain,
                    physical_host_id=f"host-{node_id}", state="available",
                    endpoints=[f"turn:{node_id}.example.test:3478?transport=udp"],
                    certificate_fingerprint="sha256:" + f"{index:064x}",
                    encrypted_turn_secret=encrypted_secret,
                    max_allocations=capacity, active_allocations=0,
                    max_egress_bps=1_000_000, current_egress_bps=0,
                    heartbeat_sequence=3, healthy_heartbeat_streak=3,
                    lease_expires_at=NOW + timedelta(seconds=15),
                    created_at=NOW, updated_at=NOW,
                )
                registration = RelayNodeRegistration(
                    node_id=node.node_id, enrollment_id=enrollment.id,
                    region=node.region, failure_domain=node.failure_domain,
                    physical_host_id=node.physical_host_id, topology_approved_at=NOW,
                    endpoints=node.endpoints, max_allocations=capacity,
                    max_egress_bps=1_000_000, csr_pem=b"fixture",
                    signing_public_key=bytes([index]) * 32,
                    encrypted_turn_secret=encrypted_secret, status="approved",
                    certificate_pem=b"fixture",
                    certificate_expires_at=NOW + timedelta(hours=1),
                    created_at=NOW, approved_at=NOW,
                )
                setup.add_all([enrollment, node, registration])
            for suffix in ("a", "b"):
                user = User(
                    id=f"pg-user-{suffix}", username=f"pg-user-{suffix}",
                    email=f"pg-{suffix}@example.test", password_hash="unused", role="user",
                    tenant_id="tenant-a",
                )
                setup.add(user)
                await setup.flush()
                device = Device(
                    id=f"pg-device-{suffix}", name="target",
                    device_id=f"pg-device-public-{suffix}", os="linux",
                    is_bound=True, bound_user_id=user.id, tenant_id="tenant-a",
                )
                setup.add(device)
                await setup.flush()
                grant = SessionRequest(
                    id=f"pg-session-{suffix}", requester_user_id=user.id,
                    target_device_id=device.id, signaling_room=f"pg-room-{suffix}",
                    tenant_id="tenant-a", status="approved",
                    grant_expires_at=NOW + timedelta(minutes=5),
                    policy_revision=17, policy_expires_at=NOW + timedelta(minutes=4),
                    intended_peer_id=device.id, relay_allowed_regions=["ap-east"],
                    relay_preferred_regions=["ap-east"],
                    relay_accepted_transports=["udp"],
                )
                setup.add(grant)
            await setup.commit()

        async def issue(suffix: str):
            async with sessions() as db:
                service = RelayAccessService(
                    session=db,
                    repository=RelayRepository(
                        db, enrollment_token_pepper=bytes.fromhex("52" * 32),
                        secret_cipher=cipher, max_reservations_per_session=2,
                    ),
                    signer=Ed25519RelayDirectorySigner(
                        key_id="pg-test-key", private_key_seed=bytes([0x42]) * 32
                    ),
                    credential_issuer=NodeTurnCredentialService(
                        cipher=cipher, ttl_seconds=600,
                        now=lambda: int(NOW.timestamp()),
                    ),
                    directory_ttl_seconds=30,
                    now=lambda: NOW,
                )
                return await service.issue_access(
                    current_user_id=f"pg-user-{suffix}",
                    session_id=f"pg-session-{suffix}",
                    policy_revision=17,
                    intended_peer_id=f"pg-device-{suffix}",
                )

        results = await asyncio.gather(issue("a"), issue("b"), return_exceptions=True)
        successes = [result for result in results if not isinstance(result, Exception)]
        assert len(successes) == 2, results
        assert all(len(result.directory.payload.candidates) == 2 for result in successes)
        assert all(len(result.credentials) == 2 for result in successes)
        assert {
            tuple(item.node_id for item in result.directory.payload.candidates)
            for result in successes
        } == {("relay-a", "relay-c"), ("relay-b", "relay-c")}
        async with sessions() as verification:
            count = await verification.scalar(
                select(func.count()).select_from(RelayReservation)
            )
            assert count == 4
            per_node = dict(
                (
                    await verification.execute(
                        select(RelayReservation.node_id, func.count())
                        .group_by(RelayReservation.node_id)
                    )
                ).all()
            )
            assert per_node == {"relay-a": 1, "relay-b": 1, "relay-c": 2}
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()
