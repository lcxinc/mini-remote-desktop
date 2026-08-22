from __future__ import annotations

import asyncio
import os
import re
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.db.migrate_add_relay_control import migrate
from app.models.relay_reservation import RelayReservation
from app.services.relay_repository import AesGcmRelaySecretCipher, RelayRepository


DATABASE_URL = os.getenv("MRD_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="MRD_TEST_DATABASE_URL is not configured; PostgreSQL row-lock test skipped",
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def asyncpg_url(url: str) -> str:
    if url.startswith("postgresql://"):
        return "postgresql+asyncpg://" + url.removeprefix("postgresql://")
    return url


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
            await repository.enroll_node(
                token="postgres-one-use-enrollment-token",
                node_id="relay-only",
                region="ap-east",
                failure_domain="rack-only",
                certificate_fingerprint="sha256:postgres-only",
                endpoints=["turn:relay.example.test:3478?transport=udp"],
                max_allocations=1,
                max_egress_bps=1_000_000,
                turn_secret="postgres-turn-secret",
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
