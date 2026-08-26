from __future__ import annotations

import asyncio
import hashlib
import os
import re
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import event, func, inspect, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.db.migrate_add_relay_access as relay_access_migration
from app.db.migrate_add_relay_access import migrate as migrate_relay_access
from app.db.migrate_add_relay_control import migrate as migrate_relay_control
from app.db.session import Base
from app.models.device import Device
from app.models.device_enrollment import DeviceEnrollment
from app.models.relay_enrollment import RelayEnrollment
from app.models.relay_node import RelayNode
from app.models.relay_node_registration import RelayNodeRegistration
from app.models.relay_reservation import RelayReservation
from app.models.session_request import SessionRequest
from app.models.user import User
from app.services.relay_directory import RelayAccessError, RelayAccessService
from app.services.device_enrollment import device_serial_digest
from app.services.relay_repository import AesGcmRelaySecretCipher, RelayRepository
from app.services.relay_signing import Ed25519RelayDirectorySigner
from app.services.session_grants import SessionGrantPolicy, SessionGrantService
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
        "ALTER TABLE session_requests ALTER COLUMN active_relay_generation TYPE INTEGER",
        "ALTER TABLE relay_access_generations ALTER COLUMN relay_url_digest TYPE TEXT",
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
@pytest.mark.parametrize(
    "malformation",
        [
            "ALTER TABLE relay_access_schema_migrations ADD CONSTRAINT "
            "ck_relay_access_ledger_extra_deny CHECK (FALSE) NOT VALID",
            "ALTER TABLE device_enrollments ADD CONSTRAINT "
        "ck_device_enrollments_extra_deny CHECK (FALSE) NOT VALID",
        "ALTER TABLE device_enrollments ADD CONSTRAINT "
        "device_enrollments_extra_unique UNIQUE (expires_at, id)",
        "ALTER TABLE device_enrollments ADD CONSTRAINT "
        "device_enrollments_extra_fkey FOREIGN KEY (registered_device_id) "
        "REFERENCES device_enrollments (id)",
        "CREATE INDEX ix_device_enrollments_extra_partial ON "
        "device_enrollments (expires_at) WHERE consumed_at IS NULL",
        "ALTER TABLE relay_access_generations ADD CONSTRAINT "
        "ck_relay_access_generations_extra_deny CHECK (FALSE) NOT VALID",
        "DROP INDEX ix_device_enrollments_expiry; CREATE INDEX "
        "ix_device_enrollments_expiry ON device_enrollments USING HASH "
        "(expires_at)",
        "ALTER TABLE device_enrollments DROP CONSTRAINT "
        "ck_device_enrollments_expiry; ALTER TABLE device_enrollments ADD "
        "CONSTRAINT ck_device_enrollments_expiry "
        "CHECK (expires_at > issued_at) NOT VALID",
        "ALTER TABLE device_enrollments DROP CONSTRAINT "
        "device_enrollments_token_digest_key; ALTER TABLE device_enrollments "
        "ADD CONSTRAINT device_enrollments_token_digest_key "
        "UNIQUE (token_digest) DEFERRABLE INITIALLY DEFERRED",
        "ALTER TABLE device_enrollments DROP CONSTRAINT "
        "device_enrollments_pkey; ALTER TABLE device_enrollments ADD "
        "CONSTRAINT device_enrollments_pkey PRIMARY KEY (id) "
        "DEFERRABLE INITIALLY DEFERRED",
    ],
)
async def test_access_migration_rejects_extra_managed_semantic_objects(
    malformation: str,
) -> None:
    assert DATABASE_URL is not None
    schema = "relay_access_extra_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
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
@pytest.mark.parametrize(
    "malformation",
    [
        "ALTER TABLE users ADD CONSTRAINT ck_users_extra_deny "
        "CHECK (FALSE) NOT VALID",
        "ALTER TABLE devices ADD CONSTRAINT devices_extra_unique "
        "UNIQUE (name, id)",
        "ALTER TABLE session_requests ADD CONSTRAINT "
        "session_requests_extra_self_fkey FOREIGN KEY (id) "
        "REFERENCES session_requests (id)",
        "CREATE INDEX ix_users_extra_admin_partial ON users (username) "
        "WHERE role = 'admin'",
    ],
)
async def test_access_migration_rejects_auth_table_schema_drift_and_rolls_back(
    malformation: str,
) -> None:
    assert DATABASE_URL is not None
    schema = "relay_access_auth_exact_" + re.sub(
        r"[^a-z0-9]", "", uuid4().hex
    )
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
            await connection.execute(text(malformation))

        with pytest.raises(relay_access_migration.RelayAccessMigrationError):
            await migrate_relay_access(engine)

        async with engine.connect() as connection:
            ledger_exists = await connection.run_sync(
                lambda sync: inspect(sync).has_table(
                    "relay_access_schema_migrations"
                )
            )
            checks = await connection.run_sync(
                lambda sync: {
                    item["name"]
                    for item in inspect(sync).get_check_constraints("users")
                }
            )
        assert ledger_exists is False
        assert "ck_users_tenant_id_canonical" not in checks
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()


@pytest.mark.anyio
async def test_access_migration_creates_and_strictly_validates_device_enrollments() -> None:
    assert DATABASE_URL is not None
    schema = "relay_access_enrollment_" + re.sub(
        r"[^a-z0-9]", "", uuid4().hex
    )
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
            await connection.execute(text("DROP TABLE device_enrollments"))
        await migrate_relay_access(engine)
        async with engine.connect() as connection:
            tables = await connection.run_sync(
                lambda sync: set(inspect(sync).get_table_names())
            )
            versions = list(
                (
                    await connection.execute(
                        text(
                            "SELECT version FROM relay_access_schema_migrations "
                            "ORDER BY version"
                        )
                    )
                ).scalars()
            )
        assert "device_enrollments" in tables
        assert versions == [1, 2, 3, 4, 5, 6]
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()


@pytest.mark.anyio
async def test_access_migration_fails_closed_on_legacy_device_owner_conflicts() -> None:
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

        with pytest.raises(
            relay_access_migration.RelayAccessMigrationError,
            match="ownership remediation required for 2 device row",
        ):
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
            assert owned.bound_user_id == "legacy-owner"
            assert owned.tenant_id is None
            ownerless = devices["legacy-ownerless-device"]
            assert ownerless.is_bound is True
            assert ownerless.bound_user_id is None
            assert ownerless.tenant_id is None
            valid = devices["legacy-valid-device"]
            assert valid.is_bound is True
            assert valid.bound_user_id == "legacy-owner"
            assert valid.tenant_id is None
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()


@pytest.mark.anyio
async def test_current_access_migration_is_read_only_and_allows_operational_indexes() -> None:
    assert DATABASE_URL is not None
    schema = "relay_access_read_only_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
    admin_engine = create_async_engine(asyncpg_url(DATABASE_URL))
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        asyncpg_url(DATABASE_URL),
        connect_args={"server_settings": {"search_path": schema}},
    )
    statements: list[str] = []
    try:
        async with engine.begin() as connection:
            await migrate_relay_control(connection)
            await connection.run_sync(Base.metadata.create_all)
            await migrate_relay_access(connection)
            await connection.execute(
                text("CREATE INDEX ops_users_role ON users (role)")
            )
            await connection.execute(
                text(
                    "CREATE INDEX ops_relay_updated ON relay_nodes (updated_at)"
                )
            )
            await connection.execute(
                text(
                    "CREATE INDEX ops_access_applied ON "
                    "relay_access_schema_migrations (applied_at)"
                )
            )

        def capture_statement(*args: object) -> None:
            statements.append(str(args[2]))

        event.listen(engine.sync_engine, "before_cursor_execute", capture_statement)
        try:
            await migrate_relay_access(engine)
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", capture_statement)
        mutating = re.compile(r"\b(?:alter|create|drop|update|insert|delete)\b", re.I)
        assert not [statement for statement in statements if mutating.search(statement)]
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()


@pytest.mark.anyio
async def test_access_migration_runs_only_the_missing_version_step() -> None:
    assert DATABASE_URL is not None
    schema = "relay_access_incremental_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
    admin_engine = create_async_engine(asyncpg_url(DATABASE_URL))
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        asyncpg_url(DATABASE_URL),
        connect_args={"server_settings": {"search_path": schema}},
    )
    statements: list[str] = []
    try:
        async with engine.begin() as connection:
            await migrate_relay_control(connection)
            await connection.run_sync(Base.metadata.create_all)
            await migrate_relay_access(connection)
            await connection.execute(
                text("DELETE FROM relay_access_schema_migrations WHERE version = 6")
            )

        def capture_statement(*args: object) -> None:
            statements.append(str(args[2]).lower())

        event.listen(engine.sync_engine, "before_cursor_execute", capture_statement)
        try:
            await migrate_relay_access(engine)
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", capture_statement)
        assert not [
            statement
            for statement in statements
            if re.search(r"\bupdate\s+(?:table\s+)?(?:users|devices|session_requests)\b", statement)
        ]
        assert not [
            statement
            for statement in statements
            if "device_enrollments" in statement
            and re.search(r"\b(?:create|alter|update|delete)\b", statement)
        ]
        inserts = [
            statement
            for statement in statements
            if "insert into relay_access_schema_migrations" in statement
        ]
        assert len(inserts) == 1
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()


@pytest.mark.anyio
@pytest.mark.parametrize("with_pepper", [False, True])
async def test_device_serial_backfill_requires_pepper_and_clears_plaintext(
    with_pepper: bool,
) -> None:
    assert DATABASE_URL is not None
    schema = "relay_serial_backfill_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
    admin_engine = create_async_engine(asyncpg_url(DATABASE_URL))
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        asyncpg_url(DATABASE_URL),
        connect_args={"server_settings": {"search_path": schema}},
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    pepper = bytes.fromhex("91" * 32)
    try:
        async with engine.begin() as connection:
            await migrate_relay_control(connection)
            await connection.run_sync(Base.metadata.create_all)
            await connection.execute(
                text(
                    "ALTER TABLE devices DROP CONSTRAINT "
                    "ck_devices_plaintext_serial_cleared"
                )
            )
        async with sessions.begin() as setup:
            setup.add(
                Device(
                    id="legacy-serial-row",
                    name="legacy-serial-device",
                    device_id="legacy-serial-public",
                    os="Linux",
                    motherboard_serial="private-serial-value",
                    motherboard_serial_digest=None,
                    is_bound=False,
                )
            )
        if not with_pepper:
            with pytest.raises(
                relay_access_migration.RelayAccessMigrationError,
                match="serial remediation requires",
            ):
                await migrate_relay_access(engine)
            async with sessions() as verification:
                row = await verification.get(Device, "legacy-serial-row")
                assert row.motherboard_serial == "private-serial-value"
                assert row.motherboard_serial_digest is None
            return

        await migrate_relay_access(engine, serial_pepper=pepper)
        async with sessions() as verification:
            row = await verification.get(Device, "legacy-serial-row")
            assert row.motherboard_serial is None
            assert row.motherboard_serial_digest == device_serial_digest(
                "private-serial-value", pepper
            )
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()


@pytest.mark.anyio
async def test_request_approve_and_access_concurrency_has_no_lock_cycle() -> None:
    assert DATABASE_URL is not None
    schema = "relay_grant_lock_order_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
    admin_engine = create_async_engine(asyncpg_url(DATABASE_URL))
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        asyncpg_url(DATABASE_URL),
        connect_args={"server_settings": {"search_path": schema}},
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    policy = SessionGrantPolicy(
        grant_ttl_seconds=120,
        policy_ttl_seconds=90,
        revision=17,
        allowed_regions=("ap-east",),
        preferred_regions=("ap-east",),
        accepted_transports=("udp",),
    )
    cipher = AesGcmRelaySecretCipher(bytes.fromhex("71" * 32))
    try:
        async with engine.begin() as connection:
            await migrate_relay_control(connection)
            await connection.run_sync(Base.metadata.create_all)
            await migrate_relay_access(connection)
        async with sessions.begin() as setup:
            setup.add_all(
                [
                    User(
                        id="lock-requester", username="lock-requester",
                        email="lock-requester@example.test", password_hash="unused",
                        role="user", tenant_id="tenant-lock",
                    ),
                    User(
                        id="lock-owner", username="lock-owner",
                        email="lock-owner@example.test", password_hash="unused",
                        role="user", tenant_id="tenant-lock",
                    ),
                ]
            )
            await setup.flush()
            setup.add(
                Device(
                    id="lock-device", name="lock-device",
                    device_id="lock-device-public", os="Linux",
                    tenant_id="tenant-lock", is_bound=True,
                    bound_user_id="lock-owner",
                )
            )
            await setup.flush()
            setup.add(
                SessionRequest(
                    id="lock-session", requester_user_id="lock-requester",
                    target_device_id="lock-device", signaling_room="lock-room",
                    tenant_id="tenant-lock", status="requested",
                )
            )
        start = asyncio.Event()

        async def request_another() -> str:
            async with sessions() as session:
                await start.wait()
                async with session.begin():
                    await SessionGrantService(
                        session, policy=policy, signaling_url="wss://signal.test",
                        now=lambda: NOW,
                    ).request(
                        current_user_id="lock-requester",
                        target_device_id="lock-device",
                    )
                return "request-ok"

        async def approve() -> str:
            async with sessions() as session:
                await start.wait()
                async with session.begin():
                    await SessionGrantService(
                        session, policy=policy, signaling_url="wss://signal.test",
                        now=lambda: NOW,
                    ).approve(
                        session_id="lock-session", current_user_id="lock-owner"
                    )
                return "approve-ok"

        async def access() -> str:
            async with sessions() as session:
                await start.wait()
                service = RelayAccessService(
                    session=session,
                    repository=RelayRepository(
                        session,
                        enrollment_token_pepper=bytes.fromhex("72" * 32),
                        secret_cipher=cipher,
                    ),
                    signer=Ed25519RelayDirectorySigner(
                        key_id="lock-test",
                        private_key_seed=bytes.fromhex("73" * 32),
                    ),
                    credential_issuer=NodeTurnCredentialService(
                        cipher=cipher, now=lambda: int(NOW.timestamp())
                    ),
                    current_policy=policy,
                    now=lambda: NOW,
                )
                try:
                    await service.issue_access(
                        current_user_id="lock-requester",
                        session_id="lock-session",
                        policy_revision=17,
                        intended_peer_id="lock-device",
                    )
                except RelayAccessError as error:
                    return error.code
                return "access-ok"

        tasks = [
            asyncio.create_task(request_another()),
            asyncio.create_task(approve()),
            asyncio.create_task(access()),
        ]
        start.set()
        results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=10)
        assert results[0] == "request-ok"
        assert results[1] == "approve-ok"
        assert results[2] in {"relay_access_denied", "relay_capacity_unavailable"}
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()


@pytest.mark.anyio
async def test_capacity_reservation_does_not_lock_unrelated_nodes() -> None:
    assert DATABASE_URL is not None
    schema = "relay_node_lock_scope_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
    admin_engine = create_async_engine(asyncpg_url(DATABASE_URL))
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        asyncpg_url(DATABASE_URL),
        connect_args={"server_settings": {"search_path": schema}},
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    blocker = None
    blocked_task = None
    try:
        async with engine.begin() as connection:
            await migrate_relay_control(connection)
            await connection.run_sync(Base.metadata.create_all)
            await migrate_relay_access(connection)
        async with sessions.begin() as setup:
            for index, node_id in enumerate(("scoped-a", "scoped-b"), start=1):
                setup.add(
                    RelayNode(
                        node_id=node_id,
                        region="ap-east",
                        failure_domain=f"rack-{index}",
                        physical_host_id=f"host-{index}",
                        state="available",
                        endpoints=[f"turn:{node_id}.example.test:3478?transport=udp"],
                        certificate_fingerprint="sha256:" + f"{index:064x}",
                        encrypted_turn_secret=bytes([index]) * 32,
                        max_allocations=2,
                        active_allocations=0,
                        max_egress_bps=1_000_000,
                        current_egress_bps=0,
                        heartbeat_sequence=3,
                        healthy_heartbeat_streak=3,
                        lease_expires_at=NOW + timedelta(minutes=1),
                        created_at=NOW,
                        updated_at=NOW,
                    )
                )

        blocker = sessions()
        await blocker.begin()
        assert await blocker.scalar(
            select(RelayNode)
            .where(RelayNode.node_id == "scoped-a")
            .with_for_update()
        ) is not None

        async def reserve(node_id: str, session_id: str) -> list[str]:
            async with sessions() as db:
                async with db.begin():
                    rows = await RelayRepository(
                        db,
                        enrollment_token_pepper=bytes.fromhex("74" * 32),
                        secret_cipher=AesGcmRelaySecretCipher(bytes.fromhex("75" * 32)),
                    ).reserve_capacity(
                        session_id=session_id,
                        user_id=f"user-{session_id}",
                        ordered_node_ids=[node_id],
                        now=NOW,
                        ttl_seconds=30,
                    )
                    return [row.node_id for row in rows]

        blocked_task = asyncio.create_task(reserve("scoped-a", "session-a"))
        await asyncio.sleep(0)
        unrelated = await asyncio.wait_for(
            reserve("scoped-b", "session-b"), timeout=2
        )
        assert unrelated == ["scoped-b"]
        assert not blocked_task.done()
        await blocker.commit()
        await blocker.close()
        blocker = None
        assert await asyncio.wait_for(blocked_task, timeout=2) == ["scoped-a"]
        blocked_task = None
    finally:
        if blocker is not None:
            await blocker.rollback()
            await blocker.close()
        if blocked_task is not None:
            blocked_task.cancel()
            await asyncio.gather(blocked_task, return_exceptions=True)
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()


@pytest.mark.anyio
async def test_directory_admission_uses_canonical_node_lock_order() -> None:
    """Opposite scores plus existing primaries must not form A->B / B->A."""

    assert DATABASE_URL is not None
    schema = "relay_cross_lock_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
    admin_engine = create_async_engine(asyncpg_url(DATABASE_URL))
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        asyncpg_url(DATABASE_URL),
        connect_args={"server_settings": {"search_path": schema}},
    )
    cipher = AesGcmRelaySecretCipher(bytes.fromhex("76" * 32))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with engine.begin() as connection:
            await migrate_relay_control(connection)
            await connection.run_sync(Base.metadata.create_all)
            await migrate_relay_access(connection)
        async with sessions() as setup:
            for index, (node_id, region) in enumerate(
                (("cross-a", "ap-east"), ("cross-b", "eu-west")), start=1
            ):
                enrollment = RelayEnrollment(
                    id=f"cross-enrollment-{index}",
                    token_digest=f"{index + 10:064x}",
                    expires_at=NOW + timedelta(hours=1),
                    used_at=NOW,
                    enrolled_node_id=node_id,
                    created_at=NOW,
                )
                encrypted_secret = cipher.encrypt(
                    hashlib.sha256(f"cross-secret-{node_id}".encode()).digest(),
                    associated_data=node_id.encode(),
                )
                node = RelayNode(
                    node_id=node_id,
                    region=region,
                    failure_domain=f"rack-{index}",
                    physical_host_id=f"host-{index}",
                    state="available",
                    endpoints=[f"turn:{node_id}.example.test:3478?transport=udp"],
                    certificate_fingerprint="sha256:" + f"{index + 10:064x}",
                    encrypted_turn_secret=encrypted_secret,
                    max_allocations=4,
                    active_allocations=0,
                    max_egress_bps=1_000_000,
                    current_egress_bps=0,
                    measured_rtt_ms=10,
                    recent_failure_bps=0,
                    heartbeat_sequence=3,
                    healthy_heartbeat_streak=3,
                    lease_expires_at=NOW + timedelta(minutes=1),
                    created_at=NOW,
                    updated_at=NOW,
                )
                registration = RelayNodeRegistration(
                    node_id=node_id,
                    enrollment_id=enrollment.id,
                    region=region,
                    failure_domain=node.failure_domain,
                    physical_host_id=node.physical_host_id,
                    topology_approved_at=NOW,
                    endpoints=node.endpoints,
                    max_allocations=node.max_allocations,
                    max_egress_bps=node.max_egress_bps,
                    csr_pem=b"fixture",
                    signing_public_key=bytes([index + 10]) * 32,
                    encrypted_turn_secret=encrypted_secret,
                    status="approved",
                    certificate_pem=b"fixture",
                    certificate_expires_at=NOW + timedelta(hours=1),
                    created_at=NOW,
                    approved_at=NOW,
                )
                setup.add_all([enrollment, node, registration])
            for suffix, primary in (("a", "cross-a"), ("b", "cross-b")):
                requester = User(
                    id=f"cross-user-{suffix}",
                    username=f"cross-user-{suffix}",
                    email=f"cross-{suffix}@example.test",
                    password_hash="unused",
                    role="user",
                    tenant_id="tenant-cross",
                )
                owner = User(
                    id=f"cross-owner-{suffix}",
                    username=f"cross-owner-{suffix}",
                    email=f"cross-owner-{suffix}@example.test",
                    password_hash="unused",
                    role="user",
                    tenant_id="tenant-cross",
                )
                setup.add_all([requester, owner])
                await setup.flush()
                device = Device(
                    id=f"cross-device-{suffix}",
                    name="target",
                    device_id=f"cross-device-public-{suffix}",
                    os="linux",
                    is_bound=True,
                    bound_user_id=owner.id,
                    tenant_id="tenant-cross",
                )
                setup.add(device)
                await setup.flush()
                preferred = (
                    ["ap-east", "eu-west"]
                    if suffix == "a"
                    else ["eu-west", "ap-east"]
                )
                setup.add_all(
                    [
                        SessionRequest(
                            id=f"cross-session-{suffix}",
                            requester_user_id=requester.id,
                            target_device_id=device.id,
                            signaling_room=f"cross-room-{suffix}",
                            tenant_id="tenant-cross",
                            status="approved",
                            grant_expires_at=NOW + timedelta(minutes=5),
                            policy_revision=17,
                            policy_expires_at=NOW + timedelta(minutes=4),
                            intended_peer_id=device.id,
                            relay_allowed_regions=["ap-east", "eu-west"],
                            relay_preferred_regions=preferred,
                            relay_accepted_transports=["udp"],
                        ),
                        RelayReservation(
                            id=f"cross-reservation-{suffix}",
                            session_id=f"cross-session-{suffix}",
                            user_id=requester.id,
                            node_id=primary,
                            expires_at=NOW + timedelta(seconds=30),
                            superseded_at=None,
                            directory_generation=f"seed-{suffix}",
                            created_at=NOW,
                        ),
                    ]
                )
            await setup.commit()

        arrival_lock = asyncio.Lock()
        both_first_stages = asyncio.Event()
        arrivals = 0

        async def rendezvous() -> None:
            nonlocal arrivals
            async with arrival_lock:
                arrivals += 1
                if arrivals == 2:
                    both_first_stages.set()
            await asyncio.wait_for(both_first_stages.wait(), timeout=5)

        async def issue(suffix: str):
            preferred = (
                ("ap-east", "eu-west")
                if suffix == "a"
                else ("eu-west", "ap-east")
            )
            async with sessions() as db:
                repository = RelayRepository(
                    db,
                    enrollment_token_pepper=bytes.fromhex("77" * 32),
                    secret_cipher=cipher,
                    max_reservations_per_session=2,
                )
                original_reserve = repository.reserve_capacity

                async def synchronized_reserve(**kwargs):
                    result = await original_reserve(**kwargs)
                    # The vulnerable directory used two result_limit=1 calls. Hold
                    # both first-node locks until each request starts its backup.
                    if kwargs.get("result_limit") == 1:
                        await rendezvous()
                    return result

                repository.reserve_capacity = synchronized_reserve  # type: ignore[method-assign]
                service = RelayAccessService(
                    session=db,
                    repository=repository,
                    signer=Ed25519RelayDirectorySigner(
                        key_id="cross-lock-key",
                        private_key_seed=bytes.fromhex("78" * 32),
                    ),
                    credential_issuer=NodeTurnCredentialService(
                        cipher=cipher, now=lambda: int(NOW.timestamp())
                    ),
                    current_policy=SessionGrantPolicy(
                        revision=17,
                        grant_ttl_seconds=600,
                        policy_ttl_seconds=600,
                        allowed_regions=("ap-east", "eu-west"),
                        preferred_regions=preferred,
                        accepted_transports=("udp",),
                    ),
                    directory_ttl_seconds=30,
                    now=lambda: NOW,
                )
                return await service.issue_access(
                    current_user_id=f"cross-user-{suffix}",
                    session_id=f"cross-session-{suffix}",
                    policy_revision=17,
                    intended_peer_id=f"cross-device-{suffix}",
                )

        results = await asyncio.wait_for(
            asyncio.gather(issue("a"), issue("b"), return_exceptions=True),
            timeout=10,
        )
        assert all(not isinstance(result, Exception) for result in results), results
        assert all(
            {candidate.node_id for candidate in result.directory.payload.candidates}
            == {"cross-a", "cross-b"}
            for result in results
        )
        assert {
            next(
                candidate.node_id
                for candidate in result.directory.payload.candidates
                if candidate.selection_reason == "preferred-region"
            )
            for result in results
        } == {"cross-a", "cross-b"}
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
                    hashlib.sha256(
                        f"real-postgres-secret-{node_id}".encode()
                    ).digest(),
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
                requester = User(
                    id=f"pg-user-{suffix}", username=f"pg-user-{suffix}",
                    email=f"pg-{suffix}@example.test", password_hash="unused", role="user",
                    tenant_id="tenant-a",
                )
                owner = User(
                    id=f"pg-owner-{suffix}", username=f"pg-owner-{suffix}",
                    email=f"pg-owner-{suffix}@example.test", password_hash="unused",
                    role="user", tenant_id="tenant-a",
                )
                setup.add_all([requester, owner])
                await setup.flush()
                device = Device(
                    id=f"pg-device-{suffix}", name="target",
                    device_id=f"pg-device-public-{suffix}", os="linux",
                    is_bound=True, bound_user_id=owner.id, tenant_id="tenant-a",
                )
                setup.add(device)
                await setup.flush()
                grant = SessionRequest(
                    id=f"pg-session-{suffix}", requester_user_id=requester.id,
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
                    current_policy=SessionGrantPolicy(
                        revision=17,
                        grant_ttl_seconds=600,
                        policy_ttl_seconds=600,
                        allowed_regions=("ap-east",),
                        preferred_regions=("ap-east",),
                        accepted_transports=("udp",),
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
