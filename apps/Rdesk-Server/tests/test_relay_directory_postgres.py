from __future__ import annotations

import asyncio
import os
import re
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

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
            enrollment = RelayEnrollment(
                id="pg-enrollment", token_digest="a" * 64,
                expires_at=NOW + timedelta(hours=1), used_at=NOW,
                enrolled_node_id="relay-only", created_at=NOW,
            )
            node = RelayNode(
                node_id="relay-only", region="ap-east", failure_domain="rack-only",
                state="available",
                endpoints=["turn:relay-only.example.test:3478?transport=udp"],
                certificate_fingerprint="sha256:" + "b" * 64,
                encrypted_turn_secret=cipher.encrypt(
                    b"real-postgres-node-secret", associated_data=b"relay-only"
                ),
                max_allocations=1, active_allocations=0,
                max_egress_bps=1_000_000, current_egress_bps=0,
                heartbeat_sequence=3, healthy_heartbeat_streak=3,
                lease_expires_at=NOW + timedelta(seconds=15),
                created_at=NOW, updated_at=NOW,
            )
            registration = RelayNodeRegistration(
                node_id=node.node_id, enrollment_id=enrollment.id,
                region=node.region, failure_domain=node.failure_domain,
                endpoints=node.endpoints, max_allocations=1,
                max_egress_bps=1_000_000, csr_pem=b"fixture",
                signing_public_key=b"2" * 32, status="approved",
                certificate_pem=b"fixture", certificate_expires_at=NOW + timedelta(hours=1),
                created_at=NOW, approved_at=NOW,
            )
            setup.add_all([enrollment, node, registration])
            for suffix in ("a", "b"):
                user = User(
                    id=f"pg-user-{suffix}", username=f"pg-user-{suffix}",
                    email=f"pg-{suffix}@example.test", password_hash="unused", role="user",
                )
                device = Device(
                    id=f"pg-device-{suffix}", name="target",
                    device_id=f"pg-device-public-{suffix}", os="linux",
                    is_bound=True, bound_user_id=user.id,
                )
                setup.add_all([user, device])
                await setup.flush()
                grant = SessionRequest(
                    id=f"pg-session-{suffix}", requester_user_id=user.id,
                    target_device_id=device.id, signaling_room=f"pg-room-{suffix}",
                    status="approved", grant_expires_at=NOW + timedelta(minutes=5),
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
        failures = [result for result in results if isinstance(result, RelayAccessError)]
        assert len(successes) == 1
        assert len(failures) == 1 and failures[0].code == "relay_capacity_unavailable"
        assert len(successes[0].directory.payload.candidates) == 1
        assert len(successes[0].credentials) == 1
        async with sessions() as verification:
            count = await verification.scalar(
                select(func.count()).select_from(RelayReservation)
            )
            assert count == 1
    finally:
        await engine.dispose()
        async with admin_engine.begin() as connection:
            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin_engine.dispose()
