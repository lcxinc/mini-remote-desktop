from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import re
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import AsyncIterator
from uuid import uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy import event, func, inspect, select, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    async_sessionmaker,
    create_async_engine,
)

from app.db.migrate_add_relay_control import migrate
import app.db.migrate_add_relay_control as relay_migration
from app.models.relay_audit_event import RelayAuditEvent
from app.models.relay_enrollment import RelayEnrollment
from app.models.relay_node import RelayNode
from app.models.relay_node_registration import RelayNodeRegistration
from app.models.relay_reservation import RelayReservation
from app.services.relay_node_auth import validate_relay_csr
from app.services.relay_repository import (
    AesGcmRelaySecretCipher,
    RelayRepository,
    RelayRepositoryError,
)
from app.services.relay_registry import (
    RelayIdentity,
    RelayRegistry,
    RelayRegistryError,
    rotation_proof_message,
)
from test_relay_node_api import _ca_material, _csr


DATABASE_URL = os.getenv("MRD_TEST_DATABASE_URL")
TURN_REST_SECRET = SecretStr(
    base64.urlsafe_b64encode(b"postgres-relay-turn-secret-32b!!")
    .rstrip(b"=")
    .decode("ascii")
)
pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason=(
        "MRD_TEST_DATABASE_URL is not configured; PostgreSQL transactional "
        "concurrency tests skipped"
    ),
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def asyncpg_url(url: str) -> str:
    if url.startswith("postgresql://"):
        return "postgresql+asyncpg://" + url.removeprefix("postgresql://")
    return url


def fingerprint(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def canonical_turn_secret(label: str) -> str:
    return base64.urlsafe_b64encode(
        hashlib.sha256(label.encode()).digest()
    ).rstrip(b"=").decode("ascii")


@asynccontextmanager
async def isolated_postgres_engine() -> AsyncIterator[AsyncEngine]:
    assert DATABASE_URL is not None
    schema = "relay_test_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
    admin_engine = create_async_engine(asyncpg_url(DATABASE_URL))
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        asyncpg_url(DATABASE_URL),
        connect_args={"server_settings": {"search_path": schema}},
    )
    try:
        await migrate(engine)
        await migrate(engine)
        yield engine
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()


async def insert_legacy_draining_node(
    connection: AsyncConnection, *, node_id: str
) -> None:
    await connection.execute(
        text(
            """
            INSERT INTO relay_nodes (
                node_id, region, failure_domain, state, endpoints,
                certificate_fingerprint, encrypted_turn_secret,
                max_allocations, max_egress_bps, desired_draining,
                created_at, updated_at
            ) VALUES (
                :node_id, 'ap-east', 'rack-legacy', 'draining',
                '[]'::jsonb, :fingerprint, decode(:secret_hex, 'hex'),
                10, 1000000, false, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
            )
            """
        ),
        {
            "node_id": node_id,
            "fingerprint": fingerprint(node_id),
            "secret_hex": "11" * 32,
        },
    )


async def enroll_postgres_node(
    repository: RelayRepository,
    *,
    token: str,
    node_id: str,
    certificate_fingerprint: str,
    now: datetime,
    max_allocations: int = 10,
    ready: bool = True,
) -> None:
    await repository.store_enrollment_token(
        token=token,
        expires_at=now + timedelta(minutes=5),
        now=now,
    )
    node = await repository.enroll_node(
        token=token,
        node_id=node_id,
        region="ap-east",
        failure_domain=f"rack-{node_id}",
        certificate_fingerprint=certificate_fingerprint,
        endpoints=["turn:relay.example.test:3478?transport=udp"],
        max_allocations=max_allocations,
        max_egress_bps=1_000_000,
        turn_secret=canonical_turn_secret(f"turn-secret-{node_id}"),
        now=now,
    )
    if ready:
        for sequence in (1, 2, 3):
            await repository.record_heartbeat(
                node_id=node.node_id,
                certificate_fingerprint=node.certificate_fingerprint,
                sequence=sequence,
                active_allocations=0,
                current_egress_bps=0,
                now=now,
            )


async def seed_registry_rotation_node(
    session: object,
    *,
    node_id: str,
    now: datetime,
) -> tuple[RelayIdentity, AesGcmRelaySecretCipher, str]:
    """Insert the smallest approved identity needed by registry race tests."""

    csr_pem, _ = _csr(node_id)
    canonical_csr, signing_public_key = validate_relay_csr(csr_pem, node_id)
    cipher = AesGcmRelaySecretCipher(bytes.fromhex("66" * 32))
    active_secret = canonical_turn_secret(f"active-{node_id}")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(node_id.encode()).digest()).rstrip(
        b"="
    ).decode("ascii")
    enrollment_id = str(uuid4())
    session.add(
        RelayEnrollment(
            id=enrollment_id,
            token_digest=hashlib.sha256(f"token-{node_id}".encode()).hexdigest(),
            expires_at=now + timedelta(hours=2),
            used_at=now,
            enrolled_node_id=node_id,
            created_at=now,
        )
    )
    node = RelayNode(
        node_id=node_id,
        region="ap-east",
        failure_domain="rack-race",
        physical_host_id="host-race",
        state="draining",
        endpoints=["turn:relay.example.test:3478?transport=udp"],
        certificate_fingerprint=fingerprint(f"current-{node_id}"),
        encrypted_turn_secret=cipher.encrypt(
            active_secret.encode("ascii"), associated_data=node_id.encode("ascii")
        ),
        max_allocations=10,
        active_allocations=0,
        max_egress_bps=1_000_000,
        current_ingress_bps=0,
        current_egress_bps=0,
        identity_epoch=1,
        active_secret_version=1,
        applied_secret_version=1,
        desired_secret_version=2,
        desired_draining=True,
        secret_not_before=now - timedelta(minutes=2),
        old_credential_deadline=now - timedelta(minutes=1),
        rotation_challenge=challenge,
        heartbeat_sequence=0,
        healthy_heartbeat_streak=0,
        lease_expires_at=now,
        created_at=now,
        updated_at=now,
    )
    session.add(node)
    session.add(
        RelayNodeRegistration(
            node_id=node_id,
            enrollment_id=enrollment_id,
            region="ap-east",
            failure_domain="rack-race",
            physical_host_id="host-race",
            topology_approved_at=now,
            endpoints=["turn:relay.example.test:3478?transport=udp"],
            max_allocations=10,
            max_egress_bps=1_000_000,
            csr_pem=canonical_csr,
            signing_public_key=signing_public_key,
            encrypted_turn_secret=node.encrypted_turn_secret,
            status="approved",
            certificate_pem=b"CURRENT CERTIFICATE",
            certificate_expires_at=now + timedelta(hours=1),
            ca_certificate_pem=b"CURRENT CA",
            receipt_digest=hashlib.sha256(f"receipt-{node_id}".encode()).hexdigest(),
            receipt_expires_at=now + timedelta(hours=1),
            created_at=now,
            approved_at=now,
        )
    )
    await session.commit()
    return (
        RelayIdentity(
            node_id=node_id,
            certificate_fingerprint=node.certificate_fingerprint,
            signing_public_key=signing_public_key,
            state=node.state,
        ),
        cipher,
        challenge,
    )


async def wait_for_postgres_blocker(
    engine: AsyncEngine,
    *,
    waiter_pid: int,
    blocker_pid: int,
) -> str | None:
    """Wait on PostgreSQL's own lock graph, not a timing sleep."""

    async with engine.connect() as observer:
        async with asyncio.timeout(5):
            while True:
                row = (
                    await observer.execute(
                        text(
                            "SELECT pg_blocking_pids(pid) AS blockers, wait_event "
                            "FROM pg_stat_activity WHERE pid = :waiter_pid"
                        ),
                        {"waiter_pid": waiter_pid},
                    )
                ).mappings().one()
                if blocker_pid in row["blockers"]:
                    return row["wait_event"]


@pytest.mark.anyio
async def test_concurrent_rotation_requests_refresh_stale_identity_and_audit_once() -> None:
    now = datetime.now(UTC)
    node_id = "relay-stale-rotation-request"
    pepper = "76" * 32
    async with isolated_postgres_engine() as engine:
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with sessions() as setup_session:
            _, cipher, _ = await seed_registry_rotation_node(
                setup_session, node_id=node_id, now=now
            )
            node = await setup_session.get(RelayNode, node_id)
            assert node is not None
            node.state = "unavailable"
            node.desired_draining = False
            node.desired_secret_version = node.active_secret_version
            node.secret_not_before = None
            node.old_credential_deadline = None
            node.rotation_challenge = None
            await setup_session.commit()

        async with sessions() as first, sessions() as second:
            first_registry = RelayRegistry(
                first, enrollment_token_pepper=pepper, turn_secret_cipher=cipher
            )
            second_registry = RelayRegistry(
                second, enrollment_token_pepper=pepper, turn_secret_cipher=cipher
            )
            stale_node = await second.get(RelayNode, node_id)
            assert stale_node is not None
            assert stale_node.desired_secret_version == 1
            first_pid = int(await first.scalar(text("SELECT pg_backend_pid()")))
            second_pid = int(await second.scalar(text("SELECT pg_backend_pid()")))

            first_result = await first_registry.request_secret_rotation(
                node_id=node_id,
                actor_id="admin-first",
                credential_ttl_seconds=60,
                now=now,
            )
            first_challenge = first_result.rotation_challenge
            second_request = asyncio.create_task(
                second_registry.request_secret_rotation(
                    node_id=node_id,
                    actor_id="admin-second",
                    credential_ttl_seconds=60,
                    now=now + timedelta(microseconds=1),
                )
            )
            wait_event = await wait_for_postgres_blocker(
                engine, waiter_pid=second_pid, blocker_pid=first_pid
            )
            await first.commit()
            second_result = await second_request
            assert wait_event == "advisory"
            assert second_result.desired_secret_version == 2
            assert second_result.rotation_challenge == first_challenge
            await second.commit()

        async with sessions() as verification:
            request_audits = await verification.scalar(
                select(func.count())
                .select_from(RelayAuditEvent)
                .where(
                    RelayAuditEvent.node_id == node_id,
                    RelayAuditEvent.action == "relay_secret_rotation_requested",
                )
            )
            assert request_audits == 1


@pytest.mark.anyio
async def test_conflicting_rotation_upload_refreshes_stale_identity_after_advisory_lock() -> None:
    now = datetime.now(UTC)
    node_id = "relay-stale-upload-race"
    pepper = "77" * 32
    async with isolated_postgres_engine() as engine:
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with sessions() as setup_session:
            identity, cipher, _ = await seed_registry_rotation_node(
                setup_session, node_id=node_id, now=now
            )

        async with sessions() as first, sessions() as second:
            first_registry = RelayRegistry(
                first, enrollment_token_pepper=pepper, turn_secret_cipher=cipher
            )
            second_registry = RelayRegistry(
                second, enrollment_token_pepper=pepper, turn_secret_cipher=cipher
            )
            # Simulate the API dependency authenticating both requests before either
            # mutation acquires the per-node transaction lock.
            first_identity = await first_registry.identity(
                node_id=node_id,
                certificate_fingerprint=identity.certificate_fingerprint,
                now=now,
            )
            second_identity = await second_registry.identity(
                node_id=node_id,
                certificate_fingerprint=identity.certificate_fingerprint,
                now=now,
            )
            stale_node = await second.get(RelayNode, node_id)
            stale_registration = await second.get(RelayNodeRegistration, node_id)
            assert stale_node is not None and stale_node.pending_rotation_id is None
            assert stale_registration is not None
            first_pid = int(await first.scalar(text("SELECT pg_backend_pid()")))
            second_pid = int(await second.scalar(text("SELECT pg_backend_pid()")))

            await first_registry.upload_secret_rotation(
                identity=first_identity,
                sequence=10,
                identity_epoch=1,
                rotation_id="rotation-first",
                secret_version=2,
                turn_rest_secret=SecretStr(canonical_turn_secret("first-secret")),
                now=now,
            )
            second_upload = asyncio.create_task(
                second_registry.upload_secret_rotation(
                    identity=second_identity,
                    sequence=11,
                    identity_epoch=1,
                    rotation_id="rotation-second",
                    secret_version=2,
                    turn_rest_secret=SecretStr(canonical_turn_secret("second-secret")),
                    now=now + timedelta(microseconds=1),
                )
            )
            wait_event = await wait_for_postgres_blocker(
                engine, waiter_pid=second_pid, blocker_pid=first_pid
            )
            assert wait_event == "advisory"
            await first.commit()

            with pytest.raises(RelayRegistryError) as conflict:
                await second_upload
            assert conflict.value.code == "relay_secret_rotation_conflict"
            await second.rollback()

        async with sessions() as verification:
            node = await verification.get(RelayNode, node_id)
            assert node is not None
            assert node.pending_rotation_id == "rotation-first"
            assert node.heartbeat_sequence == 10
            upload_audits = await verification.scalar(
                select(func.count())
                .select_from(RelayAuditEvent)
                .where(
                    RelayAuditEvent.node_id == node_id,
                    RelayAuditEvent.action == "relay_secret_rotation_uploaded",
                )
            )
            assert upload_audits == 1


@pytest.mark.anyio
async def test_heartbeat_waits_on_identity_lock_and_preserves_concurrent_rotation_upload() -> None:
    now = datetime.now(UTC)
    node_id = "relay-heartbeat-upload-race"
    pepper = "78" * 32
    async with isolated_postgres_engine() as engine:
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with sessions() as setup_session:
            identity, cipher, _ = await seed_registry_rotation_node(
                setup_session, node_id=node_id, now=now
            )

        async with sessions() as first, sessions() as second:
            first_registry = RelayRegistry(
                first, enrollment_token_pepper=pepper, turn_secret_cipher=cipher
            )
            second_registry = RelayRegistry(
                second, enrollment_token_pepper=pepper, turn_secret_cipher=cipher
            )
            first_identity = await first_registry.identity(
                node_id=node_id,
                certificate_fingerprint=identity.certificate_fingerprint,
                now=now,
            )
            second_identity = await second_registry.identity(
                node_id=node_id,
                certificate_fingerprint=identity.certificate_fingerprint,
                now=now,
            )
            stale_node = await second.get(RelayNode, node_id)
            stale_registration = await second.get(RelayNodeRegistration, node_id)
            assert stale_node is not None and stale_node.pending_rotation_id is None
            assert stale_registration is not None
            first_pid = int(await first.scalar(text("SELECT pg_backend_pid()")))
            second_pid = int(await second.scalar(text("SELECT pg_backend_pid()")))

            await first_registry.upload_secret_rotation(
                identity=first_identity,
                sequence=10,
                identity_epoch=1,
                rotation_id="rotation-heartbeat-race",
                secret_version=2,
                turn_rest_secret=SecretStr(canonical_turn_secret("heartbeat-race")),
                now=now,
            )
            heartbeat = asyncio.create_task(
                second_registry.record_heartbeat(
                    identity=second_identity,
                    sequence=11,
                    identity_epoch=1,
                    boot_id=base64.urlsafe_b64encode(b"b" * 16)
                    .rstrip(b"=")
                    .decode("ascii"),
                    nonce=base64.urlsafe_b64encode(b"n" * 32)
                    .rstrip(b"=")
                    .decode("ascii"),
                    process_health="healthy",
                    listener_health="healthy",
                    probe_health="healthy",
                    active_allocations=0,
                    current_ingress_bps=0,
                    current_egress_bps=0,
                    max_allocations=10,
                    max_egress_bps=1_000_000,
                    packet_loss_bps=0,
                    cpu_usage_bps=0,
                    memory_usage_bps=0,
                    applied_secret_version=1,
                    endpoints=["turn:relay.example.test:3478?transport=udp"],
                    now=now + timedelta(microseconds=1),
                )
            )
            wait_event = await wait_for_postgres_blocker(
                engine, waiter_pid=second_pid, blocker_pid=first_pid
            )
            await first.commit()
            result = await heartbeat
            assert wait_event == "advisory"
            assert result.heartbeat_sequence == 11
            await second.commit()

        async with sessions() as verification:
            node = await verification.get(RelayNode, node_id)
            assert node is not None
            assert node.pending_rotation_id == "rotation-heartbeat-race"
            assert node.desired_draining is True
            assert node.state == "draining"
            assert node.heartbeat_sequence == 11


@pytest.mark.anyio
async def test_duplicate_rotation_commit_refreshes_locked_row_and_audits_once() -> None:
    now = datetime.now(UTC)
    node_id = "relay-stale-commit-race"
    pepper = "79" * 32
    new_secret = canonical_turn_secret("commit-race-secret")
    rotation_id = "rotation-commit-race"
    evidence = hashlib.sha256(b"commit-race-probe").digest()
    async with isolated_postgres_engine() as engine:
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with sessions() as setup_session:
            identity, cipher, challenge = await seed_registry_rotation_node(
                setup_session, node_id=node_id, now=now
            )
            setup_registry = RelayRegistry(
                setup_session,
                enrollment_token_pepper=pepper,
                turn_secret_cipher=cipher,
            )
            setup_identity = await setup_registry.identity(
                node_id=node_id,
                certificate_fingerprint=identity.certificate_fingerprint,
                now=now,
            )
            await setup_registry.upload_secret_rotation(
                identity=setup_identity,
                sequence=5,
                identity_epoch=1,
                rotation_id=rotation_id,
                secret_version=2,
                turn_rest_secret=SecretStr(new_secret),
                now=now,
            )
            await setup_session.commit()

        pending_digest = hashlib.sha256(
            base64.urlsafe_b64decode(new_secret + "=")
        ).digest()
        proof_message = rotation_proof_message(
            node_id=node_id,
            identity_epoch=1,
            rotation_id=rotation_id,
            secret_version=2,
            rotation_challenge=challenge,
            pending_secret_digest=pending_digest,
            probe_evidence_sha256=evidence,
        )
        proof_mac = hmac.new(
            new_secret.encode("ascii"), proof_message, hashlib.sha256
        ).hexdigest()
        commit_kwargs = {
            "identity_epoch": 1,
            "rotation_id": rotation_id,
            "secret_version": 2,
            "rotation_challenge": challenge,
            "probe_evidence_sha256": evidence.hex(),
            "proof_mac": proof_mac,
        }

        async with sessions() as first, sessions() as second:
            first_registry = RelayRegistry(
                first, enrollment_token_pepper=pepper, turn_secret_cipher=cipher
            )
            second_registry = RelayRegistry(
                second, enrollment_token_pepper=pepper, turn_secret_cipher=cipher
            )
            first_identity = await first_registry.identity(
                node_id=node_id,
                certificate_fingerprint=identity.certificate_fingerprint,
                now=now,
            )
            second_identity = await second_registry.identity(
                node_id=node_id,
                certificate_fingerprint=identity.certificate_fingerprint,
                now=now,
            )
            stale_node = await second.get(RelayNode, node_id)
            stale_registration = await second.get(RelayNodeRegistration, node_id)
            assert stale_node is not None and stale_node.pending_rotation_id == rotation_id
            assert stale_registration is not None
            first_pid = int(await first.scalar(text("SELECT pg_backend_pid()")))
            second_pid = int(await second.scalar(text("SELECT pg_backend_pid()")))

            await first_registry.commit_secret_rotation(
                identity=first_identity,
                sequence=10,
                now=now,
                **commit_kwargs,
            )
            duplicate_commit = asyncio.create_task(
                second_registry.commit_secret_rotation(
                    identity=second_identity,
                    sequence=11,
                    now=now + timedelta(microseconds=1),
                    **commit_kwargs,
                )
            )
            wait_event = await wait_for_postgres_blocker(
                engine, waiter_pid=second_pid, blocker_pid=first_pid
            )
            await first.commit()
            duplicate = await duplicate_commit
            assert wait_event == "advisory"
            assert duplicate.active_secret_version == 2
            await second.commit()

        async with sessions() as verification:
            node = await verification.get(RelayNode, node_id)
            assert node is not None
            assert node.heartbeat_sequence == 11
            assert node.committed_rotation_id == rotation_id
            commit_audits = await verification.scalar(
                select(func.count())
                .select_from(RelayAuditEvent)
                .where(
                    RelayAuditEvent.node_id == node_id,
                    RelayAuditEvent.action == "relay_secret_rotation_committed",
                )
            )
            assert commit_audits == 1


@pytest.mark.anyio
async def test_renewal_serializes_old_epoch_heartbeat_and_records_previous_sequence() -> None:
    now = datetime.now(UTC)
    node_id = "relay-renewal-epoch-race"
    pepper = "7a" * 32
    renewal_csr, _ = _csr(node_id)
    ca_certificate, ca_private_key, _, _ = _ca_material()
    async with isolated_postgres_engine() as engine:
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with sessions() as setup_session:
            identity, cipher, _ = await seed_registry_rotation_node(
                setup_session, node_id=node_id, now=now
            )
            # This race exercises an ordinary renewal versus an old-epoch
            # heartbeat.  Rotation-in-flight renewals are intentionally
            # rejected by the fail-closed lifecycle invariant.
            seeded = await setup_session.get(RelayNode, node_id)
            assert seeded is not None
            seeded.state = "unavailable"
            seeded.desired_draining = False
            seeded.desired_secret_version = seeded.active_secret_version
            seeded.secret_not_before = None
            seeded.old_credential_deadline = None
            seeded.rotation_challenge = None
            await setup_session.commit()

        async with sessions() as first, sessions() as second:
            first_registry = RelayRegistry(
                first, enrollment_token_pepper=pepper, turn_secret_cipher=cipher
            )
            second_registry = RelayRegistry(
                second, enrollment_token_pepper=pepper, turn_secret_cipher=cipher
            )
            first_identity = await first_registry.identity(
                node_id=node_id,
                certificate_fingerprint=identity.certificate_fingerprint,
                now=now,
            )
            second_identity = await second_registry.identity(
                node_id=node_id,
                certificate_fingerprint=identity.certificate_fingerprint,
                now=now,
            )
            stale_node = await second.get(RelayNode, node_id)
            stale_registration = await second.get(RelayNodeRegistration, node_id)
            assert stale_node is not None and stale_node.identity_epoch == 1
            assert stale_registration is not None
            first_pid = int(await first.scalar(text("SELECT pg_backend_pid()")))
            second_pid = int(await second.scalar(text("SELECT pg_backend_pid()")))

            renewed = await first_registry.renew(
                identity=first_identity,
                sequence=10,
                renewal_id="renewal-epoch-race",
                csr_pem=renewal_csr,
                ca_certificate_pem=ca_certificate,
                ca_private_key_pem=ca_private_key,
                ca_private_key_password="",
                validity_seconds=3600,
                renew_before_seconds=3600,
                previous_auth_grace_seconds=300,
                renewal_record_retention_seconds=3600,
                now=now,
            )
            assert renewed.node.identity_epoch == 2
            old_epoch_heartbeat = asyncio.create_task(
                second_registry.record_heartbeat(
                    identity=second_identity,
                    sequence=11,
                    identity_epoch=1,
                    boot_id=base64.urlsafe_b64encode(b"r" * 16)
                    .rstrip(b"=")
                    .decode("ascii"),
                    nonce=base64.urlsafe_b64encode(b"s" * 32)
                    .rstrip(b"=")
                    .decode("ascii"),
                    process_health="healthy",
                    listener_health="healthy",
                    probe_health="healthy",
                    active_allocations=0,
                    current_ingress_bps=0,
                    current_egress_bps=0,
                    max_allocations=10,
                    max_egress_bps=1_000_000,
                    packet_loss_bps=0,
                    cpu_usage_bps=0,
                    memory_usage_bps=0,
                    applied_secret_version=1,
                    endpoints=["turn:relay.example.test:3478?transport=udp"],
                    now=now + timedelta(microseconds=1),
                )
            )
            wait_event = await wait_for_postgres_blocker(
                engine, waiter_pid=second_pid, blocker_pid=first_pid
            )
            await first.commit()
            with pytest.raises(RelayRegistryError) as stale_epoch:
                await old_epoch_heartbeat
            assert wait_event == "advisory"
            assert stale_epoch.value.code == "relay_certificate_invalid"
            await second.rollback()

        async with sessions() as verification:
            node = await verification.get(RelayNode, node_id)
            assert node is not None
            assert node.identity_epoch == 2
            assert node.heartbeat_sequence == 0
            assert node.previous_identity_sequence == 10
            heartbeat_audits = await verification.scalar(
                select(func.count())
                .select_from(RelayAuditEvent)
                .where(
                    RelayAuditEvent.node_id == node_id,
                    RelayAuditEvent.action == "relay_heartbeat_recorded",
                )
            )
            assert heartbeat_audits == 0


@pytest.mark.anyio
async def test_concurrent_admission_uses_row_locks_and_never_oversubscribes() -> None:
    assert DATABASE_URL is not None
    schema = "relay_test_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
    admin_engine = create_async_engine(asyncpg_url(DATABASE_URL))
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))

    engine = create_async_engine(
        asyncpg_url(DATABASE_URL),
        connect_args={"server_settings": {"search_path": schema}},
    )
    try:
        await migrate(engine)
        await migrate(engine)  # The production migration must be idempotent.
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
        cipher = AesGcmRelaySecretCipher(bytes.fromhex("33" * 32))

        async with sessions() as setup_session:
            repository = RelayRepository(
                setup_session,
                enrollment_token_pepper=bytes.fromhex("44" * 32),
                secret_cipher=cipher,
            )
            await repository.store_enrollment_token(
                token="postgres-one-use-enrollment-token",
                expires_at=now + timedelta(minutes=5),
                now=now,
            )
            node = await repository.enroll_node(
                token="postgres-one-use-enrollment-token",
                node_id="relay-only",
                region="ap-east",
                failure_domain="rack-only",
                certificate_fingerprint=fingerprint("postgres-only"),
                endpoints=["turn:relay.example.test:3478?transport=udp"],
                max_allocations=1,
                max_egress_bps=1_000_000,
                turn_secret=canonical_turn_secret("postgres-turn-secret"),
                now=now,
            )
            for sequence in (1, 2, 3):
                await repository.record_heartbeat(
                    node_id=node.node_id,
                    certificate_fingerprint=node.certificate_fingerprint,
                    sequence=sequence,
                    active_allocations=0,
                    current_egress_bps=0,
                    now=now,
                )
            await setup_session.commit()

        started = asyncio.Event()
        arrivals = 0
        arrivals_lock = asyncio.Lock()

        async def reserve(session_id: str) -> list[RelayReservation]:
            nonlocal arrivals
            async with sessions() as session:
                repository = RelayRepository(
                    session,
                    enrollment_token_pepper=bytes.fromhex("44" * 32),
                    secret_cipher=cipher,
                )
                async with arrivals_lock:
                    arrivals += 1
                    if arrivals == 2:
                        started.set()
                await started.wait()
                reservations = await repository.reserve_capacity(
                    session_id=session_id,
                    user_id=f"user-{session_id}",
                    ordered_node_ids=["relay-only"],
                    now=now,
                )
                await session.commit()
                return reservations

        results = await asyncio.gather(reserve("session-a"), reserve("session-b"))
        assert sorted(len(result) for result in results) == [0, 1]

        async with sessions() as verification_session:
            count = await verification_session.scalar(
                select(func.count()).select_from(RelayReservation)
            )
            assert count == 1
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()


@pytest.mark.anyio
async def test_active_allocations_plus_pending_never_exceed_node_capacity() -> None:
    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    cipher = AesGcmRelaySecretCipher(bytes.fromhex("33" * 32))
    async with isolated_postgres_engine() as engine:
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with sessions() as setup_session:
            repository = RelayRepository(
                setup_session,
                enrollment_token_pepper=bytes.fromhex("44" * 32),
                secret_cipher=cipher,
            )
            await enroll_postgres_node(
                repository,
                token="postgres-active-capacity-token",
                node_id="relay-active",
                certificate_fingerprint=fingerprint("postgres-active"),
                now=now,
                max_allocations=1,
                ready=False,
            )
            node = await repository.record_heartbeat(
                node_id="relay-active",
                certificate_fingerprint=fingerprint("postgres-active"),
                sequence=1,
                active_allocations=1,
                current_egress_bps=0,
                now=now,
            )
            assert node.active_allocations == 1
            await setup_session.commit()

        async def reserve(session_id: str) -> list[RelayReservation]:
            async with sessions() as session:
                repository = RelayRepository(
                    session,
                    enrollment_token_pepper=bytes.fromhex("44" * 32),
                    secret_cipher=cipher,
                )
                result = await repository.reserve_capacity(
                    session_id=session_id,
                    user_id=f"user-{session_id}",
                    ordered_node_ids=["relay-active"],
                    now=now,
                )
                await session.commit()
                return result

        results = await asyncio.gather(reserve("active-a"), reserve("active-b"))
        assert results == [[], []]
        async with sessions() as verification_session:
            count = await verification_session.scalar(
                select(func.count()).select_from(RelayReservation)
            )
            assert count == 0


@pytest.mark.anyio
async def test_session_advisory_lock_bounds_disjoint_candidate_transactions() -> None:
    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    cipher = AesGcmRelaySecretCipher(bytes.fromhex("33" * 32))
    async with isolated_postgres_engine() as engine:
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with sessions() as setup_session:
            repository = RelayRepository(
                setup_session,
                enrollment_token_pepper=bytes.fromhex("44" * 32),
                secret_cipher=cipher,
            )
            for index in range(4):
                await enroll_postgres_node(
                    repository,
                    token=f"postgres-disjoint-enrollment-token-{index}",
                    node_id=f"relay-disjoint-{index}",
                    certificate_fingerprint=fingerprint(
                        f"postgres-disjoint-{index}"
                    ),
                    now=now,
                )
            await setup_session.commit()

        started = asyncio.Event()
        arrivals = 0
        arrivals_lock = asyncio.Lock()

        async def reserve(node_ids: list[str]) -> list[RelayReservation]:
            nonlocal arrivals
            async with sessions() as session:
                repository = RelayRepository(
                    session,
                    enrollment_token_pepper=bytes.fromhex("44" * 32),
                    secret_cipher=cipher,
                )
                async with arrivals_lock:
                    arrivals += 1
                    if arrivals == 2:
                        started.set()
                await started.wait()
                result = await repository.reserve_capacity(
                    session_id="one-shared-session",
                    user_id="one-shared-user",
                    ordered_node_ids=node_ids,
                    now=now,
                )
                await session.commit()
                return result

        results = await asyncio.gather(
            reserve(["relay-disjoint-0", "relay-disjoint-1"]),
            reserve(["relay-disjoint-2", "relay-disjoint-3"]),
        )
        assert sorted(len(result) for result in results) == [0, 2]
        async with sessions() as verification_session:
            count = await verification_session.scalar(
                select(func.count())
                .select_from(RelayReservation)
                .where(RelayReservation.session_id == "one-shared-session")
            )
            assert count == 2


@pytest.mark.anyio
async def test_reservation_rechecks_state_after_waiting_for_node_lock() -> None:
    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    cipher = AesGcmRelaySecretCipher(bytes.fromhex("33" * 32))
    async with isolated_postgres_engine() as engine:
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with sessions() as setup_session:
            repository = RelayRepository(
                setup_session,
                enrollment_token_pepper=bytes.fromhex("44" * 32),
                secret_cipher=cipher,
            )
            await enroll_postgres_node(
                repository,
                token="postgres-lock-state-enrollment-token",
                node_id="relay-lock-state",
                certificate_fingerprint=fingerprint("postgres-lock-state"),
                now=now,
            )
            await setup_session.commit()

        state_locked = asyncio.Event()
        release_update = asyncio.Event()
        cache_loaded = asyncio.Event()

        async def transition_to_draining() -> None:
            async with sessions() as session:
                async with session.begin():
                    node = await session.scalar(
                        select(RelayNode)
                        .where(RelayNode.node_id == "relay-lock-state")
                        .with_for_update()
                    )
                    assert node is not None
                    node.state = "draining"
                    await session.flush()
                    state_locked.set()
                    await release_update.wait()

        async def reserve_after_transition() -> list[RelayReservation]:
            async with sessions() as session:
                cached = await session.get(RelayNode, "relay-lock-state")
                assert cached is not None and cached.state == "available"
                cache_loaded.set()
                await state_locked.wait()
                repository = RelayRepository(
                    session,
                    enrollment_token_pepper=bytes.fromhex("44" * 32),
                    secret_cipher=cipher,
                )
                result = await repository.reserve_capacity(
                    session_id="lock-state-session",
                    user_id="lock-state-user",
                    ordered_node_ids=["relay-lock-state"],
                    now=now,
                )
                await session.commit()
                return result

        reservation = asyncio.create_task(reserve_after_transition())
        await cache_loaded.wait()
        transition = asyncio.create_task(transition_to_draining())
        await state_locked.wait()
        await asyncio.sleep(0)
        release_update.set()
        await transition
        assert await reservation == []


@pytest.mark.anyio
async def test_concurrent_enrollment_conflicts_are_stable_and_transactions_recover() -> None:
    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    pepper = bytes.fromhex("44" * 32)
    cipher = AesGcmRelaySecretCipher(bytes.fromhex("33" * 32))
    async with isolated_postgres_engine() as engine:
        sessions = async_sessionmaker(engine, expire_on_commit=False)

        async def store_same_token(label: str) -> tuple[str, str]:
            async with sessions() as session:
                repository = RelayRepository(
                    session,
                    enrollment_token_pepper=pepper,
                    secret_cipher=cipher,
                )
                await repository.store_enrollment_token(
                    token=f"outer-unrelated-work-token-{label}",
                    expires_at=now + timedelta(minutes=5),
                    now=now,
                )
                try:
                    await repository.store_enrollment_token(
                        token="sensitive-shared-enrollment-token",
                        expires_at=now + timedelta(minutes=5),
                        now=now,
                    )
                    await session.commit()
                    return "ok", ""
                except RelayRepositoryError as error:
                    await session.execute(select(1))
                    await repository.store_enrollment_token(
                        token="recovery-after-token-conflict",
                        expires_at=now + timedelta(minutes=5),
                        now=now,
                    )
                    await session.commit()
                    return error.code, str(error)

        token_results = await asyncio.gather(
            store_same_token("a"), store_same_token("b")
        )
        assert sorted(code for code, _ in token_results) == [
            "ENROLLMENT_TOKEN_EXISTS",
            "ok",
        ]
        assert all("sensitive" not in message for _, message in token_results)

        async with sessions() as token_session:
            repository = RelayRepository(
                token_session,
                enrollment_token_pepper=pepper,
                secret_cipher=cipher,
            )
            for suffix in ("node-a", "node-b", "cert-a", "cert-b"):
                await repository.store_enrollment_token(
                    token=f"concurrent-enrollment-token-{suffix}",
                    expires_at=now + timedelta(minutes=5),
                    now=now,
                )
            await token_session.commit()

        async def concurrent_enroll(
            *, token: str, node_id: str, fingerprint: str
        ) -> tuple[str, str]:
            async with sessions() as session:
                repository = RelayRepository(
                    session,
                    enrollment_token_pepper=pepper,
                    secret_cipher=cipher,
                )
                await repository.store_enrollment_token(
                    token=f"outer-work-{token}",
                    expires_at=now + timedelta(minutes=5),
                    now=now,
                )
                try:
                    await repository.enroll_node(
                        token=token,
                        node_id=node_id,
                        region="ap-east",
                        failure_domain=f"rack-{node_id}",
                        certificate_fingerprint=fingerprint,
                        endpoints=["turn:relay.example.test:3478?transport=udp"],
                        max_allocations=1,
                        max_egress_bps=1,
                        turn_secret=canonical_turn_secret(
                            f"sensitive-secret-{token}"
                        ),
                        now=now,
                    )
                    await session.commit()
                    return "ok", ""
                except RelayRepositoryError as error:
                    await session.execute(select(1))
                    await repository.store_enrollment_token(
                        token=f"recovery-{token}",
                        expires_at=now + timedelta(minutes=5),
                        now=now,
                    )
                    await session.commit()
                    return error.code, str(error)

        node_results = await asyncio.gather(
            concurrent_enroll(
                token="concurrent-enrollment-token-node-a",
                node_id="relay-shared-node",
                fingerprint=fingerprint("sensitive-node-a"),
            ),
            concurrent_enroll(
                token="concurrent-enrollment-token-node-b",
                node_id="relay-shared-node",
                fingerprint=fingerprint("sensitive-node-b"),
            ),
        )
        assert sorted(code for code, _ in node_results) == ["NODE_ALREADY_EXISTS", "ok"]
        assert all("sensitive" not in message for _, message in node_results)

        adversarial_fingerprint = fingerprint(
            "legal-duplicate-containing-no-user-controlled-constraint-name"
        )
        certificate_results = await asyncio.gather(
            concurrent_enroll(
                token="concurrent-enrollment-token-cert-a",
                node_id="relay-cert-a",
                fingerprint=adversarial_fingerprint,
            ),
            concurrent_enroll(
                token="concurrent-enrollment-token-cert-b",
                node_id="relay-cert-b",
                fingerprint=adversarial_fingerprint,
            ),
        )
        assert sorted(code for code, _ in certificate_results) == [
            "CERTIFICATE_ALREADY_BOUND",
            "ok",
        ]
        assert all(
            adversarial_fingerprint not in message
            and "duplicate key" not in message.lower()
            for _, message in certificate_results
        )

        async with sessions() as verification_session:
            repository = RelayRepository(
                verification_session,
                enrollment_token_pepper=pepper,
                secret_cipher=cipher,
            )
            for token in (
                "concurrent-enrollment-token-node-a",
                "concurrent-enrollment-token-node-b",
                "concurrent-enrollment-token-cert-a",
                "concurrent-enrollment-token-cert-b",
            ):
                with pytest.raises(RelayRepositoryError) as retained:
                    await repository.store_enrollment_token(
                        token=f"outer-work-{token}",
                        expires_at=now + timedelta(minutes=5),
                        now=now,
                    )
                assert retained.value.code == "ENROLLMENT_TOKEN_EXISTS"
            for label in ("a", "b"):
                with pytest.raises(RelayRepositoryError) as retained:
                    await repository.store_enrollment_token(
                        token=f"outer-unrelated-work-token-{label}",
                        expires_at=now + timedelta(minutes=5),
                        now=now,
                    )
                assert retained.value.code == "ENROLLMENT_TOKEN_EXISTS"


@pytest.mark.anyio
async def test_different_tokens_cannot_concurrently_replace_the_same_registration() -> None:
    now = datetime.now(UTC)
    pepper = "44" * 32
    node_id = "relay-concurrent-reenrollment"
    cipher = AesGcmRelaySecretCipher(bytes.fromhex("55" * 32))
    async with isolated_postgres_engine() as engine:
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with sessions() as setup_session:
            registry = RelayRegistry(
                setup_session, enrollment_token_pepper=pepper
            )
            first_token, _ = await registry.issue_enrollment_token(
                ttl_seconds=300, actor_id="admin", now=now
            )
            second_token, _ = await registry.issue_enrollment_token(
                ttl_seconds=300, actor_id="admin", now=now
            )
            await setup_session.commit()

        first_csr, _ = _csr(node_id)
        second_csr, _ = _csr(node_id)
        start = asyncio.Event()

        async def enroll(
            token: str, csr_pem: str
        ) -> tuple[str, str, str | None]:
            async with sessions() as session:
                registry = RelayRegistry(
                    session,
                    enrollment_token_pepper=pepper,
                    turn_secret_cipher=cipher,
                )
                await start.wait()
                try:
                    requested = await registry.request_enrollment(
                        token=token,
                        node_id=node_id,
                        region="ap-east",
                        failure_domain="rack-concurrent",
                        endpoints=[
                            "turn:relay.example.test:3478?transport=udp"
                        ],
                        max_allocations=10,
                        max_egress_bps=1_000_000,
                        csr_pem=csr_pem,
                        turn_rest_secret=TURN_REST_SECRET,
                        receipt_ttl_seconds=3600,
                        now=now,
                    )
                    await session.commit()
                    return (
                        "ok",
                        requested.registration.enrollment_id,
                        requested.receipt,
                    )
                except RelayRegistryError as error:
                    await session.rollback()
                    return error.code, str(error.status_code), None

        first = asyncio.create_task(enroll(first_token, first_csr))
        second = asyncio.create_task(enroll(second_token, second_csr))
        start.set()
        results = await asyncio.wait_for(
            asyncio.gather(first, second), timeout=10
        )
        successful = [result for result in results if result[0] == "ok"]
        rejected = [result for result in results if result[0] != "ok"]
        assert len(successful) == len(rejected) == 1
        assert rejected[0][:2] == ("relay_enrollment_pending", "409")

        enrollment_id, receipt = successful[0][1], successful[0][2]
        assert receipt is not None
        async with sessions() as verification_session:
            registry = RelayRegistry(
                verification_session, enrollment_token_pepper=pepper
            )
            pending = await registry.pickup_enrollment(
                enrollment_id=enrollment_id,
                receipt=receipt,
                ca_certificate_pem="unused",
                ca_private_key_pem="unused",
                ca_private_key_password="",
                validity_seconds=3600,
                now=now,
            )
            assert pending.status == "pending"
            registration = await verification_session.get(
                RelayNodeRegistration, node_id
            )
            assert registration is not None
            assert registration.enrollment_id == enrollment_id
            assert cipher.decrypt(
                bytes(registration.encrypted_turn_secret),
                associated_data=node_id.encode("ascii"),
            ) == TURN_REST_SECRET.get_secret_value().encode("ascii")


@pytest.mark.anyio
async def test_pickup_and_revoke_serialize_without_deadlock() -> None:
    now = datetime.now(UTC)
    pepper = "44" * 32
    node_id = "relay-pickup-revoke-race"
    ca_certificate, ca_private_key, _, _ = _ca_material()
    csr_pem, _ = _csr(node_id)
    cipher = AesGcmRelaySecretCipher(bytes.fromhex("55" * 32))
    async with isolated_postgres_engine() as engine:
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with sessions() as setup_session:
            registry = RelayRegistry(
                setup_session,
                enrollment_token_pepper=pepper,
                turn_secret_cipher=cipher,
            )
            token, _ = await registry.issue_enrollment_token(
                ttl_seconds=300, actor_id="admin", now=now
            )
            requested = await registry.request_enrollment(
                token=token,
                node_id=node_id,
                region="ap-east",
                failure_domain="rack-race",
                endpoints=["turn:relay.example.test:3478?transport=udp"],
                max_allocations=10,
                max_egress_bps=1_000_000,
                csr_pem=csr_pem,
                turn_rest_secret=TURN_REST_SECRET,
                receipt_ttl_seconds=3600,
                now=now,
            )
            enrollment_id = requested.registration.enrollment_id
            receipt = requested.receipt
            await registry.approve(
                node_id=node_id,
                actor_id="admin",
                failure_domain="rack-race",
                physical_host_id="host-race",
                now=now,
            )
            await setup_session.commit()

        start = asyncio.Event()

        async def pickup() -> str:
            async with sessions() as session:
                registry = RelayRegistry(
                    session,
                    enrollment_token_pepper=pepper,
                    turn_secret_cipher=cipher,
                )
                await start.wait()
                try:
                    result = await registry.pickup_enrollment(
                        enrollment_id=enrollment_id,
                        receipt=receipt,
                        ca_certificate_pem=ca_certificate,
                        ca_private_key_pem=ca_private_key,
                        ca_private_key_password="",
                        validity_seconds=3600,
                        now=now,
                    )
                    await session.commit()
                    return result.status
                except RelayRegistryError as error:
                    await session.rollback()
                    return error.code

        async def revoke() -> str:
            async with sessions() as session:
                registry = RelayRegistry(session, enrollment_token_pepper=pepper)
                await start.wait()
                result = await registry.revoke(
                    node_id=node_id, actor_id="admin", now=now
                )
                await session.commit()
                return result.state

        pickup_task = asyncio.create_task(pickup())
        revoke_task = asyncio.create_task(revoke())
        start.set()
        pickup_result, revoke_result = await asyncio.wait_for(
            asyncio.gather(pickup_task, revoke_task), timeout=10
        )
        assert pickup_result in {"approved", "relay_enrollment_invalid"}
        assert revoke_result == "revoked"

        async with sessions() as verification_session:
            registration = await verification_session.get(
                RelayNodeRegistration, node_id
            )
            node = await verification_session.get(RelayNode, node_id)
            assert registration is not None
            assert registration.status == "revoked"
            assert node is None or node.state == "revoked"
            registry = RelayRegistry(
                verification_session, enrollment_token_pepper=pepper
            )
            with pytest.raises(RelayRegistryError) as replayed:
                await registry.pickup_enrollment(
                    enrollment_id=enrollment_id,
                    receipt=receipt,
                    ca_certificate_pem=ca_certificate,
                    ca_private_key_pem=ca_private_key,
                    ca_private_key_password="",
                    validity_seconds=3600,
                    now=now + timedelta(seconds=1),
                )
            assert replayed.value.code == "relay_enrollment_invalid"


@pytest.mark.anyio
async def test_migration_schema_matches_orm_and_required_indexes() -> None:
    async with isolated_postgres_engine() as engine:
        def inspect_schema(sync_connection: object) -> dict[str, object]:
            inspector = inspect(sync_connection)
            return {
                "nodes_columns": {
                    column["name"]: column
                    for column in inspector.get_columns("relay_nodes")
                },
                "nodes_checks": {
                    constraint["name"]
                    for constraint in inspector.get_check_constraints("relay_nodes")
                },
                "reservation_indexes": {
                    (
                        index["name"],
                        tuple(index["column_names"]),
                    )
                    for index in inspector.get_indexes("relay_reservations")
                },
            }

        async with engine.connect() as connection:
            snapshot = await connection.run_sync(inspect_schema)
            versions = await connection.scalar(
                text("SELECT COUNT(*) FROM relay_schema_migrations WHERE version = 1")
            )
            current_version = await connection.scalar(
                text("SELECT MAX(version) FROM relay_schema_migrations")
            )
        assert versions == 1
        assert current_version == 8
        columns = snapshot["nodes_columns"]
        assert str(columns["endpoints"]["type"]).upper() == "JSONB"
        assert columns["state"]["nullable"] is False
        assert "unavailable" in str(columns["state"]["default"])
        for name in (
            "active_allocations",
            "current_egress_bps",
            "heartbeat_sequence",
            "recent_failure_bps",
            "current_ingress_bps",
        ):
            assert str(columns[name]["default"]).strip("()") == "0"
        for name in (
            "identity_epoch",
            "active_secret_version",
            "applied_secret_version",
            "desired_secret_version",
        ):
            assert str(columns[name]["default"]).strip("()") == "1"
        assert str(columns["desired_draining"]["default"]).strip("()") == "false"
        assert {
            "ck_relay_nodes_state",
            "ck_relay_nodes_max_allocations",
            "ck_relay_nodes_active_allocations",
            "ck_relay_nodes_max_egress",
            "ck_relay_nodes_current_egress",
            "ck_relay_nodes_heartbeat_sequence",
            "ck_relay_nodes_measured_rtt",
            "ck_relay_nodes_recent_failure",
        }.issubset(snapshot["nodes_checks"])
        assert (
            "ix_relay_reservations_node_expiry",
            ("node_id", "expires_at"),
        ) in snapshot["reservation_indexes"]
        assert (
            "ix_relay_reservations_session_expiry",
            ("session_id", "expires_at"),
        ) in snapshot["reservation_indexes"]

        endpoint_type = RelayNode.__table__.c.endpoints.type.dialect_impl(
            engine.sync_engine.dialect
        )
        assert isinstance(endpoint_type, JSONB)
        assert RelayNode.__table__.c.state.server_default is not None


@pytest.mark.anyio
async def test_current_migration_ledger_runs_read_only_schema_verification() -> None:
    async with isolated_postgres_engine() as engine:
        statements: list[str] = []

        def capture_sql(
            _connection: object,
            _cursor: object,
            statement: str,
            _parameters: object,
            _context: object,
            _executemany: bool,
        ) -> None:
            statements.append(" ".join(statement.upper().split()))

        event.listen(engine.sync_engine, "before_cursor_execute", capture_sql)
        try:
            await migrate(engine)
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", capture_sql)

        mutating = tuple(
            statement
            for statement in statements
            if statement.startswith(
                ("ALTER ", "CREATE ", "DELETE ", "DO ", "DROP ", "INSERT ", "UPDATE ")
            )
        )
        assert mutating == ()


@pytest.mark.anyio
async def test_migration_with_only_v8_missing_executes_only_v8_step() -> None:
    async with isolated_postgres_engine() as engine:
        async with engine.begin() as connection:
            await insert_legacy_draining_node(
                connection, node_id="relay-v7-draining"
            )
            await connection.execute(
                text("DELETE FROM relay_schema_migrations WHERE version = 8")
            )
            await connection.execute(
                text(
                    "ALTER TABLE relay_nodes "
                    "DROP COLUMN current_ingress_bps, "
                    "DROP COLUMN identity_epoch, "
                    "DROP COLUMN previous_identity_sequence, "
                    "DROP COLUMN last_boot_id, "
                    "DROP COLUMN last_heartbeat_nonce, DROP COLUMN process_health, "
                    "DROP COLUMN listener_health, DROP COLUMN probe_health, "
                    "DROP COLUMN packet_loss_bps, DROP COLUMN cpu_usage_bps, "
                    "DROP COLUMN memory_usage_bps, DROP COLUMN active_secret_version, "
                    "DROP COLUMN applied_secret_version, DROP COLUMN desired_secret_version, "
                    "DROP COLUMN desired_draining, DROP COLUMN secret_not_before, "
                    "DROP COLUMN old_credential_deadline, DROP COLUMN pending_secret_version, "
                    "DROP COLUMN pending_encrypted_turn_secret, "
                    "DROP COLUMN pending_secret_digest, DROP COLUMN pending_rotation_id, "
                    "DROP COLUMN pending_secret_uploaded_at, "
                    "DROP COLUMN rotation_challenge, DROP COLUMN committed_rotation_id, "
                    "DROP COLUMN committed_identity_epoch, "
                    "DROP COLUMN committed_rotation_challenge, "
                    "DROP COLUMN committed_probe_evidence_sha256, "
                    "DROP COLUMN committed_proof_mac"
                )
            )

        statements: list[str] = []

        def capture_sql(
            _connection: object,
            _cursor: object,
            statement: str,
            _parameters: object,
            _context: object,
            _executemany: bool,
        ) -> None:
            statements.append(" ".join(statement.upper().split()))

        event.listen(engine.sync_engine, "before_cursor_execute", capture_sql)
        try:
            await migrate(engine)
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", capture_sql)

        mutating = [
            statement
            for statement in statements
            if statement.startswith(
                ("ALTER ", "CREATE ", "DELETE ", "DO ", "DROP ", "INSERT ", "UPDATE ")
            )
        ]
        assert len(mutating) == 3, mutating
        assert all(
            "RELAY_NODES" in statement
            or "INSERT INTO RELAY_SCHEMA_MIGRATIONS" in statement
            for statement in mutating
        )
        assert [statement.split(maxsplit=1)[0] for statement in mutating] == [
            "ALTER",
            "DO",
            "INSERT",
        ]
        async with engine.connect() as connection:
            versions = list(
                (
                    await connection.execute(
                        text(
                            "SELECT version FROM relay_schema_migrations "
                            "ORDER BY version"
                        )
                    )
                ).scalars()
            )
            desired_draining = await connection.scalar(
                text(
                    "SELECT desired_draining FROM relay_nodes "
                    "WHERE node_id = 'relay-v7-draining'"
                )
            )
        assert versions == list(range(1, 9))
        assert desired_draining is True


@pytest.mark.anyio
async def test_v7_to_v8_failure_rolls_back_columns_constraints_and_ledger(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with isolated_postgres_engine() as engine:
        async with engine.begin() as connection:
            await insert_legacy_draining_node(
                connection, node_id="relay-v7-rollback-draining"
            )
            await connection.execute(
                text("DELETE FROM relay_schema_migrations WHERE version = 8")
            )
            await connection.execute(
                text(
                    "ALTER TABLE relay_nodes "
                    "DROP COLUMN current_ingress_bps, "
                    "DROP COLUMN identity_epoch, "
                    "DROP COLUMN previous_identity_sequence, "
                    "DROP COLUMN last_boot_id, "
                    "DROP COLUMN last_heartbeat_nonce, DROP COLUMN process_health, "
                    "DROP COLUMN listener_health, DROP COLUMN probe_health, "
                    "DROP COLUMN packet_loss_bps, DROP COLUMN cpu_usage_bps, "
                    "DROP COLUMN memory_usage_bps, DROP COLUMN active_secret_version, "
                    "DROP COLUMN applied_secret_version, DROP COLUMN desired_secret_version, "
                    "DROP COLUMN desired_draining, DROP COLUMN secret_not_before, "
                    "DROP COLUMN old_credential_deadline, DROP COLUMN pending_secret_version, "
                    "DROP COLUMN pending_encrypted_turn_secret, "
                    "DROP COLUMN pending_secret_digest, DROP COLUMN pending_rotation_id, "
                    "DROP COLUMN pending_secret_uploaded_at, "
                    "DROP COLUMN rotation_challenge, DROP COLUMN committed_rotation_id, "
                    "DROP COLUMN committed_identity_epoch, "
                    "DROP COLUMN committed_rotation_challenge, "
                    "DROP COLUMN committed_probe_evidence_sha256, "
                    "DROP COLUMN committed_proof_mac"
                )
            )

        def fail_exact_verifier(*_args: object) -> None:
            raise relay_migration.RelaySchemaMismatchError("injected v8 verifier failure")

        monkeypatch.setattr(
            relay_migration, "_assert_schema_conforms", fail_exact_verifier
        )
        with pytest.raises(
            relay_migration.RelaySchemaMismatchError,
            match="injected v8 verifier failure",
        ):
            await migrate(engine)

        async with engine.connect() as connection:
            version = await connection.scalar(
                text("SELECT MAX(version) FROM relay_schema_migrations")
            )

            def has_v8_column(sync_connection: object) -> bool:
                columns = {
                    column["name"]
                    for column in inspect(sync_connection).get_columns("relay_nodes")
                }
                return any(
                    column in columns
                    for column in (
                        "identity_epoch",
                        "rotation_challenge",
                        "committed_proof_mac",
                    )
                )

            column_exists = await connection.run_sync(has_v8_column)
            state = await connection.scalar(
                text(
                    "SELECT state FROM relay_nodes "
                    "WHERE node_id = 'relay-v7-rollback-draining'"
                )
            )
        assert version == 7
        assert column_exists is False
        assert state == "draining"


@pytest.mark.anyio
async def test_genuine_v6_schema_upgrades_through_v8_with_all_rotation_constraints() -> None:
    async with isolated_postgres_engine() as engine:
        async with engine.begin() as connection:
            await insert_legacy_draining_node(
                connection, node_id="relay-v6-draining"
            )
            await connection.execute(
                text("DELETE FROM relay_schema_migrations WHERE version >= 7")
            )
            await connection.execute(
                text(
                    "ALTER TABLE relay_reservations "
                    "DROP COLUMN superseded_at, DROP COLUMN directory_generation"
                )
            )
            await connection.execute(
                text(
                    "ALTER TABLE relay_nodes "
                    "DROP COLUMN current_ingress_bps, "
                    "DROP COLUMN identity_epoch, "
                    "DROP COLUMN previous_identity_sequence, "
                    "DROP COLUMN last_boot_id, DROP COLUMN last_heartbeat_nonce, "
                    "DROP COLUMN process_health, DROP COLUMN listener_health, "
                    "DROP COLUMN probe_health, DROP COLUMN packet_loss_bps, "
                    "DROP COLUMN cpu_usage_bps, DROP COLUMN memory_usage_bps, "
                    "DROP COLUMN active_secret_version, "
                    "DROP COLUMN applied_secret_version, "
                    "DROP COLUMN desired_secret_version, DROP COLUMN desired_draining, "
                    "DROP COLUMN secret_not_before, DROP COLUMN old_credential_deadline, "
                    "DROP COLUMN pending_secret_version, "
                    "DROP COLUMN pending_encrypted_turn_secret, "
                    "DROP COLUMN pending_secret_digest, DROP COLUMN pending_rotation_id, "
                    "DROP COLUMN pending_secret_uploaded_at, "
                    "DROP COLUMN rotation_challenge, DROP COLUMN committed_rotation_id, "
                    "DROP COLUMN committed_identity_epoch, "
                    "DROP COLUMN committed_rotation_challenge, "
                    "DROP COLUMN committed_probe_evidence_sha256, "
                    "DROP COLUMN committed_proof_mac"
                )
            )

        await migrate(engine)

        async with engine.connect() as connection:
            versions = list(
                (
                    await connection.execute(
                        text(
                            "SELECT version FROM relay_schema_migrations "
                            "ORDER BY version"
                        )
                    )
                ).scalars()
            )

            def inspect_upgrade(sync_connection: object) -> tuple[set[str], set[str]]:
                inspector = inspect(sync_connection)
                columns = {
                    column["name"]
                    for column in inspector.get_columns("relay_nodes")
                }
                checks = {
                    constraint["name"]
                    for constraint in inspector.get_check_constraints("relay_nodes")
                }
                return columns, checks

            columns, checks = await connection.run_sync(inspect_upgrade)
            desired_draining = await connection.scalar(
                text(
                    "SELECT desired_draining FROM relay_nodes "
                    "WHERE node_id = 'relay-v6-draining'"
                )
            )
        assert versions == list(range(1, 9))
        assert desired_draining is True
        assert "previous_identity_sequence" in columns
        assert {
            "ck_relay_nodes_previous_identity_sequence",
            "ck_relay_nodes_rotation_pending",
            "ck_relay_nodes_rotation_challenge",
            "ck_relay_nodes_rotation_committed_proof",
        }.issubset(checks)

        statements: list[str] = []

        def capture_sql(
            _connection: object,
            _cursor: object,
            statement: str,
            _parameters: object,
            _context: object,
            _executemany: bool,
        ) -> None:
            statements.append(" ".join(statement.upper().split()))

        event.listen(engine.sync_engine, "before_cursor_execute", capture_sql)
        try:
            await migrate(engine)
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", capture_sql)
        assert not any(
            statement.startswith(
                ("ALTER ", "CREATE ", "DELETE ", "DO ", "DROP ", "INSERT ", "UPDATE ")
            )
            for statement in statements
        )


@pytest.mark.anyio
async def test_v6_draining_backfill_rolls_back_with_the_generic_upgrade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with isolated_postgres_engine() as engine:
        async with engine.begin() as connection:
            await insert_legacy_draining_node(
                connection, node_id="relay-v6-rollback-draining"
            )
            await connection.execute(
                text("DELETE FROM relay_schema_migrations WHERE version >= 7")
            )
            await connection.execute(
                text(
                    "ALTER TABLE relay_reservations "
                    "DROP COLUMN superseded_at, DROP COLUMN directory_generation"
                )
            )
            await connection.execute(
                text(
                    "ALTER TABLE relay_nodes "
                    "DROP COLUMN current_ingress_bps, DROP COLUMN identity_epoch, "
                    "DROP COLUMN previous_identity_sequence, DROP COLUMN last_boot_id, "
                    "DROP COLUMN last_heartbeat_nonce, DROP COLUMN process_health, "
                    "DROP COLUMN listener_health, DROP COLUMN probe_health, "
                    "DROP COLUMN packet_loss_bps, DROP COLUMN cpu_usage_bps, "
                    "DROP COLUMN memory_usage_bps, DROP COLUMN active_secret_version, "
                    "DROP COLUMN applied_secret_version, DROP COLUMN desired_secret_version, "
                    "DROP COLUMN desired_draining, DROP COLUMN secret_not_before, "
                    "DROP COLUMN old_credential_deadline, DROP COLUMN pending_secret_version, "
                    "DROP COLUMN pending_encrypted_turn_secret, "
                    "DROP COLUMN pending_secret_digest, DROP COLUMN pending_rotation_id, "
                    "DROP COLUMN pending_secret_uploaded_at, "
                    "DROP COLUMN rotation_challenge, DROP COLUMN committed_rotation_id, "
                    "DROP COLUMN committed_identity_epoch, "
                    "DROP COLUMN committed_rotation_challenge, "
                    "DROP COLUMN committed_probe_evidence_sha256, "
                    "DROP COLUMN committed_proof_mac"
                )
            )

        def fail_exact_verifier(*_args: object) -> None:
            raise relay_migration.RelaySchemaMismatchError(
                "injected generic verifier failure"
            )

        monkeypatch.setattr(
            relay_migration, "_assert_schema_conforms", fail_exact_verifier
        )
        with pytest.raises(
            relay_migration.RelaySchemaMismatchError,
            match="injected generic verifier failure",
        ):
            await migrate(engine)

        async with engine.connect() as connection:
            version = await connection.scalar(
                text("SELECT MAX(version) FROM relay_schema_migrations")
            )
            state = await connection.scalar(
                text(
                    "SELECT state FROM relay_nodes "
                    "WHERE node_id = 'relay-v6-rollback-draining'"
                )
            )

            def has_desired_draining(sync_connection: object) -> bool:
                return "desired_draining" in {
                    column["name"]
                    for column in inspect(sync_connection).get_columns("relay_nodes")
                }

            column_exists = await connection.run_sync(has_desired_draining)
        assert version == 6
        assert state == "draining"
        assert column_exists is False


@pytest.mark.anyio
async def test_migration_accepts_existing_connection_and_fails_closed_on_partial_table() -> None:
    assert DATABASE_URL is not None
    malformed_tables = (
        "CREATE TABLE relay_nodes (node_id VARCHAR(128) PRIMARY KEY)",
        """
        CREATE TABLE relay_enrollments (
            id VARCHAR(36) NOT NULL,
            token_digest VARCHAR(64) NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            used_at TIMESTAMPTZ,
            enrolled_node_id VARCHAR(128),
            created_at TIMESTAMPTZ NOT NULL,
            CONSTRAINT relay_enrollments_token_digest_key UNIQUE (token_digest)
        )
        """,
    )
    for create_malformed_table in malformed_tables:
        schema = "relay_partial_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
        admin_engine = create_async_engine(asyncpg_url(DATABASE_URL))
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        engine = create_async_engine(
            asyncpg_url(DATABASE_URL),
            connect_args={"server_settings": {"search_path": schema}},
        )
        try:
            async with engine.begin() as connection:
                await connection.execute(text(create_malformed_table))
            with pytest.raises(relay_migration.RelaySchemaMismatchError):
                async with engine.begin() as connection:
                    await migrate(connection)
        finally:
            await engine.dispose()
            async with admin_engine.begin() as connection:
                await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            await admin_engine.dispose()


@pytest.mark.anyio
async def test_concurrent_migrations_serialize_with_a_schema_scoped_transaction_lock() -> None:
    assert DATABASE_URL is not None
    schema = "relay_concurrent_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
    admin_engine = create_async_engine(asyncpg_url(DATABASE_URL))
    first_engine = create_async_engine(asyncpg_url(DATABASE_URL))
    second_engine = create_async_engine(asyncpg_url(DATABASE_URL))
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))

    first_ready = asyncio.Event()
    release_first = asyncio.Event()
    second_started = asyncio.Event()
    second_finished = asyncio.Event()
    lock_observations: list[bool] = []

    async def first_migration() -> None:
        async with first_engine.begin() as connection:
            await migrate(connection, schema=schema)
            lock_observations.append(
                bool(
                    await connection.scalar(
                        text(
                            "SELECT EXISTS ("
                            "SELECT 1 FROM pg_locks "
                            "WHERE locktype = 'advisory' "
                            "AND pid = pg_backend_pid() AND granted"
                            ")"
                        )
                    )
                )
            )
            first_ready.set()
            await release_first.wait()

    async def second_migration() -> None:
        await first_ready.wait()
        second_started.set()
        async with second_engine.begin() as connection:
            await migrate(connection, schema=schema)
        second_finished.set()

    try:
        first_task = asyncio.create_task(first_migration())
        await asyncio.wait_for(first_ready.wait(), timeout=5)
        second_task = asyncio.create_task(second_migration())
        await asyncio.wait_for(second_started.wait(), timeout=5)
        await asyncio.sleep(0.05)
        assert not second_finished.is_set()
        release_first.set()
        await asyncio.gather(first_task, second_task)

        assert lock_observations == [True]
        async with first_engine.connect() as connection:
            assert not bool(
                await connection.scalar(
                    text(
                        "SELECT EXISTS ("
                        "SELECT 1 FROM pg_locks "
                        "WHERE locktype = 'advisory' "
                        "AND pid = pg_backend_pid() AND granted"
                        ")"
                    )
                )
            )
        await migrate(first_engine, schema=schema)
        async with first_engine.connect() as connection:
            assert await connection.scalar(
                text(
                    f'SELECT COUNT(*) FROM "{schema}".relay_schema_migrations '
                    "WHERE version = 1"
                )
            ) == 1
    finally:
        release_first.set()
        await first_engine.dispose()
        await second_engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()


@pytest.mark.anyio
async def test_migration_rejects_semantically_weakened_check_constraint() -> None:
    async with isolated_postgres_engine() as engine:
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "ALTER TABLE relay_nodes "
                    "DROP CONSTRAINT ck_relay_nodes_max_allocations"
                )
            )
            await connection.execute(
                text(
                    "ALTER TABLE relay_nodes ADD CONSTRAINT "
                    "ck_relay_nodes_max_allocations "
                    "CHECK (max_allocations > 0 OR TRUE)"
                )
            )
        with pytest.raises(relay_migration.RelaySchemaMismatchError):
            await migrate(engine)


@pytest.mark.anyio
async def test_migration_rejects_cross_schema_deferrable_reservation_fk() -> None:
    assert DATABASE_URL is not None
    other_schema = "relay_wrong_fk_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
    admin_engine = create_async_engine(asyncpg_url(DATABASE_URL))
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{other_schema}"'))
    try:
        async with isolated_postgres_engine() as engine:
            async with engine.begin() as connection:
                await connection.execute(
                    text(
                        f'CREATE TABLE "{other_schema}".relay_nodes '
                        "(node_id VARCHAR(128) PRIMARY KEY)"
                    )
                )
                await connection.execute(
                    text(
                        "ALTER TABLE relay_reservations DROP CONSTRAINT "
                        "relay_reservations_node_id_fkey"
                    )
                )
                await connection.execute(
                    text(
                        "ALTER TABLE relay_reservations ADD CONSTRAINT "
                        "relay_reservations_node_id_fkey FOREIGN KEY (node_id) "
                        f'REFERENCES "{other_schema}".relay_nodes (node_id) '
                        "ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED"
                    )
                )
            with pytest.raises(relay_migration.RelaySchemaMismatchError):
                await migrate(engine)
    finally:
        async with admin_engine.begin() as connection:
            await connection.execute(
                text(f'DROP SCHEMA "{other_schema}" CASCADE')
            )
        await admin_engine.dispose()


@pytest.mark.anyio
@pytest.mark.parametrize(
    "malformation",
    [
        "ALTER TABLE relay_nodes ALTER COLUMN state SET DEFAULT 'notunavailable'",
        "ALTER TABLE relay_node_registrations ALTER COLUMN status SET DEFAULT 'notpending'",
        "ALTER TABLE relay_nodes ALTER COLUMN measured_rtt_ms SET DEFAULT 7",
        "DROP INDEX ix_relay_nodes_region; CREATE UNIQUE INDEX "
        "ix_relay_nodes_region ON relay_nodes (region)",
        "DROP INDEX ix_relay_nodes_region; CREATE INDEX "
        "ix_relay_nodes_region ON relay_nodes USING HASH (region)",
        "ALTER TABLE relay_node_registrations DROP CONSTRAINT "
        "relay_node_registrations_enrollment_id_fkey; ALTER TABLE "
        "relay_node_registrations ADD CONSTRAINT "
        "relay_node_registrations_enrollment_id_fkey FOREIGN KEY "
        "(enrollment_id) REFERENCES relay_enrollments (id) ON DELETE RESTRICT "
        "DEFERRABLE INITIALLY DEFERRED",
        "ALTER TABLE relay_node_registrations DROP CONSTRAINT "
        "ck_relay_node_registrations_topology; ALTER TABLE "
        "relay_node_registrations ADD CONSTRAINT "
        "ck_relay_node_registrations_topology CHECK ("
        "topology_approved_at IS NULL AND (physical_host_id IS NULL OR "
        "topology_approved_at IS NOT NULL) AND physical_host_id IS NOT NULL)",
        "ALTER TABLE relay_nodes DROP CONSTRAINT "
        "ck_relay_nodes_max_allocations; ALTER TABLE relay_nodes ADD "
        "CONSTRAINT ck_relay_nodes_max_allocations "
        "CHECK (max_allocations > 0) NOT VALID",
        "ALTER TABLE relay_enrollments DROP CONSTRAINT "
        "relay_enrollments_token_digest_key; ALTER TABLE relay_enrollments "
        "ADD CONSTRAINT relay_enrollments_token_digest_key "
        "UNIQUE (token_digest) DEFERRABLE INITIALLY DEFERRED",
        "ALTER TABLE relay_audit_events DROP CONSTRAINT "
        "relay_audit_events_pkey; ALTER TABLE relay_audit_events ADD "
        "CONSTRAINT relay_audit_events_pkey PRIMARY KEY (id) "
        "DEFERRABLE INITIALLY DEFERRED",
        "ALTER TABLE relay_schema_migrations ALTER COLUMN version TYPE BIGINT",
        "ALTER TABLE relay_schema_migrations ALTER COLUMN applied_at DROP DEFAULT",
        "ALTER TABLE relay_schema_migrations DROP CONSTRAINT relay_schema_migrations_pkey",
        "DELETE FROM relay_schema_migrations WHERE version = 6",
        "INSERT INTO relay_schema_migrations (version) VALUES (999)",
    ],
)
async def test_control_migration_rejects_semantically_malicious_schema(
    malformation: str,
) -> None:
    async with isolated_postgres_engine() as engine:
        async with engine.begin() as connection:
            for statement in malformation.split("; "):
                await connection.execute(text(statement))
        with pytest.raises(relay_migration.RelaySchemaMismatchError):
            await migrate(engine)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "malformation",
    [
        "ALTER TABLE relay_nodes ADD CONSTRAINT ck_relay_nodes_extra_deny "
        "CHECK (FALSE) NOT VALID",
        "ALTER TABLE relay_nodes ADD CONSTRAINT relay_nodes_extra_unique "
        "UNIQUE (region, node_id)",
        "ALTER TABLE relay_nodes ADD CONSTRAINT relay_nodes_extra_fkey "
        "FOREIGN KEY (node_id) REFERENCES relay_nodes (node_id)",
        "CREATE INDEX ix_relay_nodes_extra_partial ON relay_nodes (region) "
        "WHERE state = 'available'",
    ],
)
async def test_control_migration_rejects_extra_semantic_objects(
    malformation: str,
) -> None:
    async with isolated_postgres_engine() as engine:
        async with engine.begin() as connection:
            await connection.execute(text(malformation))
        with pytest.raises(relay_migration.RelaySchemaMismatchError):
            await migrate(engine)


@pytest.mark.anyio
async def test_v4_behaviorally_upgrades_v2_schema_and_serializes_concurrent_upgrade() -> None:
    assert DATABASE_URL is not None
    schema = "relay_v3_upgrade_" + re.sub(r"[^a-z0-9]", "", uuid4().hex)
    admin_engine = create_async_engine(asyncpg_url(DATABASE_URL))
    async with admin_engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    first = create_async_engine(asyncpg_url(DATABASE_URL))
    second = create_async_engine(asyncpg_url(DATABASE_URL))
    try:
        await migrate(first, schema=schema)
        registration_v3_columns = (
            "receipt_digest",
            "receipt_expires_at",
            "ca_certificate_pem",
            "previous_certificate_fingerprint",
            "previous_signing_public_key",
            "previous_auth_expires_at",
            "renewal_request_id",
            "renewal_csr_sha256",
            "renewal_certificate_pem",
            "renewal_certificate_expires_at",
        )
        registration_v4_columns = (
            "request_digest",
            "previous_certificate_expires_at",
            "renewal_record_expires_at",
        )
        async with first.begin() as connection:
            await connection.execute(
                text(
                    f'ALTER TABLE "{schema}".relay_nodes '
                    "DROP CONSTRAINT IF EXISTS "
                    "ck_relay_nodes_healthy_heartbeat_streak"
                )
            )
            await connection.execute(
                text(
                    f'ALTER TABLE "{schema}".relay_nodes '
                    "DROP COLUMN IF EXISTS healthy_heartbeat_streak"
                )
            )
            for column in (*registration_v3_columns, *registration_v4_columns):
                await connection.execute(
                    text(
                        f'ALTER TABLE "{schema}".relay_node_registrations '
                        f'DROP COLUMN IF EXISTS {column}'
                    )
                )
            await connection.execute(
                text(
                    f'DELETE FROM "{schema}".relay_schema_migrations '
                    "WHERE version >= 3"
                )
            )

        await asyncio.gather(
            migrate(first, schema=schema), migrate(second, schema=schema)
        )
        async with first.connect() as connection:
            node_columns = {
                row["column_name"]
                for row in (
                    await connection.execute(
                        text(
                            "SELECT column_name FROM information_schema.columns "
                            "WHERE table_schema = :schema AND table_name = 'relay_nodes'"
                        ),
                        {"schema": schema},
                    )
                ).mappings()
            }
            registration_columns = {
                row["column_name"]
                for row in (
                    await connection.execute(
                        text(
                            "SELECT column_name FROM information_schema.columns "
                            "WHERE table_schema = :schema AND "
                            "table_name = 'relay_node_registrations'"
                        ),
                        {"schema": schema},
                    )
                ).mappings()
            }
            versions = list(
                (
                    await connection.execute(
                        text(
                            f'SELECT version FROM "{schema}".relay_schema_migrations '
                            "ORDER BY version"
                        )
                    )
                ).scalars()
            )
            assert "healthy_heartbeat_streak" in node_columns
            assert set(registration_v3_columns).issubset(registration_columns)
            assert set(registration_v4_columns).issubset(registration_columns)
            assert versions == [1, 2, 3, 4, 5, 6, 7, 8]
    finally:
        await first.dispose()
        await second.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()


@pytest.mark.anyio
async def test_v4_backfills_only_complete_v3_inflight_renewals_without_extending_grace() -> None:
    now = datetime.now(UTC)
    pepper = "44" * 32
    active_node_id = "relay-v3-renewal-active"
    expired_node_id = "relay-v3-renewal-expired"
    partial_node_id = "relay-v3-renewal-partial"
    active_csr, _ = _csr(active_node_id)
    expired_csr, _ = _csr(expired_node_id)
    partial_csr, _ = _csr(partial_node_id)
    active_canonical, _ = validate_relay_csr(active_csr, active_node_id)
    expired_canonical, _ = validate_relay_csr(expired_csr, expired_node_id)
    partial_canonical, _ = validate_relay_csr(partial_csr, partial_node_id)
    active_grace = now + timedelta(minutes=5)
    expired_grace = now - timedelta(seconds=1)

    async with isolated_postgres_engine() as engine:
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        async with sessions() as setup_session:
            for node_id, old_grace, canonical_csr, complete in (
                (active_node_id, active_grace, active_canonical, True),
                (expired_node_id, expired_grace, expired_canonical, True),
                (partial_node_id, active_grace, partial_canonical, False),
            ):
                enrollment_id = str(uuid4())
                setup_session.add(
                    RelayEnrollment(
                        id=enrollment_id,
                        token_digest=hashlib.sha256(node_id.encode()).hexdigest(),
                        expires_at=now + timedelta(hours=1),
                        used_at=now,
                        enrolled_node_id=node_id,
                        created_at=now,
                    )
                )
                setup_session.add(
                    RelayNode(
                        node_id=node_id,
                        region="ap-east",
                        failure_domain="rack-v3",
                        state="unavailable",
                        endpoints=[
                            "turn:relay.example.test:3478?transport=udp"
                        ],
                        certificate_fingerprint=fingerprint(f"current-{node_id}"),
                        encrypted_turn_secret=b"v3",
                        max_allocations=10,
                        active_allocations=0,
                        max_egress_bps=1_000_000,
                        current_egress_bps=0,
                        heartbeat_sequence=0,
                        healthy_heartbeat_streak=0,
                        lease_expires_at=None,
                        revoked_at=None,
                        created_at=now,
                        updated_at=now,
                    )
                )
                setup_session.add(
                    RelayNodeRegistration(
                        node_id=node_id,
                        enrollment_id=enrollment_id,
                        region="ap-east",
                        failure_domain="rack-v3",
                        endpoints=[
                            "turn:relay.example.test:3478?transport=udp"
                        ],
                        max_allocations=10,
                        max_egress_bps=1_000_000,
                        csr_pem=canonical_csr,
                        signing_public_key=b"c" * 32,
                        status="approved",
                        certificate_pem=b"CURRENT CERTIFICATE",
                        certificate_expires_at=now + timedelta(hours=1),
                        request_digest=None,
                        receipt_digest=hashlib.sha256(node_id.encode()).hexdigest(),
                        receipt_expires_at=now + timedelta(hours=1),
                        ca_certificate_pem=(b"CACHED CA" if complete else None),
                        previous_certificate_fingerprint=fingerprint(
                            f"previous-{node_id}"
                        ),
                        previous_signing_public_key=b"p" * 32,
                        previous_auth_expires_at=old_grace,
                        previous_certificate_expires_at=None,
                        renewal_request_id=f"renewal-{node_id}",
                        renewal_csr_sha256=hashlib.sha256(canonical_csr).hexdigest(),
                        renewal_certificate_pem=b"CACHED RENEWED CERTIFICATE",
                        renewal_certificate_expires_at=now + timedelta(hours=1),
                        renewal_record_expires_at=None,
                        created_at=now,
                        approved_at=now,
                    )
                )
            await setup_session.commit()

        async with engine.begin() as connection:
            for column in (
                "request_digest",
                "previous_certificate_expires_at",
                "renewal_record_expires_at",
            ):
                await connection.execute(
                    text(
                        "ALTER TABLE relay_node_registrations "
                        f"DROP COLUMN {column}"
                    )
                )
            await connection.execute(
                text("DELETE FROM relay_schema_migrations WHERE version >= 4")
            )

        await migrate(engine)
        async with sessions() as verification_session:
            active_registration = await verification_session.get(
                RelayNodeRegistration, active_node_id
            )
            expired_registration = await verification_session.get(
                RelayNodeRegistration, expired_node_id
            )
            partial_registration = await verification_session.get(
                RelayNodeRegistration, partial_node_id
            )
            assert active_registration is not None
            assert expired_registration is not None
            assert partial_registration is not None
            assert active_registration.previous_certificate_expires_at == active_grace
            assert active_registration.renewal_record_expires_at == active_grace
            assert expired_registration.previous_certificate_expires_at == expired_grace
            assert expired_registration.renewal_record_expires_at == expired_grace
            assert partial_registration.previous_certificate_expires_at is None
            assert partial_registration.renewal_record_expires_at is None

            registry = RelayRegistry(
                verification_session, enrollment_token_pepper=pepper
            )
            active_node = await verification_session.get(RelayNode, active_node_id)
            expired_node = await verification_session.get(RelayNode, expired_node_id)
            assert active_node is not None and expired_node is not None
            current_identity = RelayIdentity(
                node_id=active_node_id,
                certificate_fingerprint=active_node.certificate_fingerprint,
                signing_public_key=b"c" * 32,
                state=active_node.state,
            )
            previous_identity = RelayIdentity(
                node_id=active_node_id,
                certificate_fingerprint=fingerprint(f"previous-{active_node_id}"),
                signing_public_key=b"p" * 32,
                state=active_node.state,
                is_previous=True,
            )
            renewal_kwargs = {
                "sequence": 1,
                "renewal_id": f"renewal-{active_node_id}",
                "csr_pem": active_csr,
                "ca_certificate_pem": "must-not-be-used",
                "ca_private_key_pem": "must-not-be-used",
                "ca_private_key_password": "",
                "validity_seconds": 3600,
                "renew_before_seconds": 3600,
                "previous_auth_grace_seconds": 300,
                "renewal_record_retention_seconds": 3600,
                "now": now,
            }
            with pytest.raises(RelayRegistryError) as current_retry:
                await registry.renew(identity=current_identity, **renewal_kwargs)
            assert current_retry.value.code == "relay_renewal_conflict"
            assert current_retry.value.status_code == 409
            assert active_node.heartbeat_sequence == 0
            assert active_node.previous_identity_sequence is None
            assert active_node.updated_at == now
            previous_retry = await registry.renew(
                identity=previous_identity, **renewal_kwargs
            )
            assert previous_retry.certificate.certificate_pem == (
                "CACHED RENEWED CERTIFICATE"
            )
            assert active_node.heartbeat_sequence == 0
            assert active_node.previous_identity_sequence == 1
            assert active_node.updated_at == now
            renewed_audits = await verification_session.scalar(
                select(func.count())
                .select_from(RelayAuditEvent)
                .where(RelayAuditEvent.action == "relay_certificate_renewed")
            )
            assert renewed_audits == 0

            expired_current = RelayIdentity(
                node_id=expired_node_id,
                certificate_fingerprint=expired_node.certificate_fingerprint,
                signing_public_key=b"c" * 32,
                state=expired_node.state,
            )
            with pytest.raises(RelayRegistryError) as expired_retry:
                await registry.renew(
                    identity=expired_current,
                    sequence=1,
                    renewal_id=f"renewal-{expired_node_id}",
                    csr_pem=expired_csr,
                    ca_certificate_pem="must-not-be-used",
                    ca_private_key_pem="must-not-be-used",
                    ca_private_key_password="",
                    validity_seconds=3600,
                    renew_before_seconds=3600,
                    previous_auth_grace_seconds=300,
                    renewal_record_retention_seconds=3600,
                    now=now,
                )
            assert expired_retry.value.code == "relay_renewal_conflict"
