from __future__ import annotations

import asyncio
import os
import re
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import AsyncIterator
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from app.db.migrate_add_relay_control import migrate
from app.models.relay_reservation import RelayReservation
from app.services.relay_repository import (
    AesGcmRelaySecretCipher,
    RelayRepository,
    RelayRepositoryError,
)


DATABASE_URL = os.getenv("MRD_TEST_DATABASE_URL")
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


async def enroll_postgres_node(
    repository: RelayRepository,
    *,
    token: str,
    node_id: str,
    certificate_fingerprint: str,
    now: datetime,
    max_allocations: int = 10,
) -> None:
    await repository.store_enrollment_token(
        token=token,
        expires_at=now + timedelta(minutes=5),
        now=now,
    )
    await repository.enroll_node(
        token=token,
        node_id=node_id,
        region="ap-east",
        failure_domain=f"rack-{node_id}",
        certificate_fingerprint=certificate_fingerprint,
        endpoints=["turn:relay.example.test:3478?transport=udp"],
        max_allocations=max_allocations,
        max_egress_bps=1_000_000,
        turn_secret=f"turn-secret-{node_id}",
        now=now,
    )


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
                certificate_fingerprint="sha256:postgres-active",
                now=now,
                max_allocations=1,
            )
            node = await repository.record_heartbeat(
                node_id="relay-active",
                certificate_fingerprint="sha256:postgres-active",
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
                    certificate_fingerprint=f"sha256:postgres-disjoint-{index}",
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
async def test_concurrent_enrollment_conflicts_are_stable_and_transactions_recover() -> None:
    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    pepper = bytes.fromhex("44" * 32)
    cipher = AesGcmRelaySecretCipher(bytes.fromhex("33" * 32))
    async with isolated_postgres_engine() as engine:
        sessions = async_sessionmaker(engine, expire_on_commit=False)

        async def store_same_token() -> tuple[str, str]:
            async with sessions() as session:
                repository = RelayRepository(
                    session,
                    enrollment_token_pepper=pepper,
                    secret_cipher=cipher,
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

        token_results = await asyncio.gather(store_same_token(), store_same_token())
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
                        turn_secret=f"sensitive-secret-{token}",
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
                fingerprint="sha256:sensitive-node-a",
            ),
            concurrent_enroll(
                token="concurrent-enrollment-token-node-b",
                node_id="relay-shared-node",
                fingerprint="sha256:sensitive-node-b",
            ),
        )
        assert sorted(code for code, _ in node_results) == ["NODE_ALREADY_EXISTS", "ok"]
        assert all("sensitive" not in message for _, message in node_results)

        adversarial_fingerprint = "sha256:relay_enrollments_token_digest_key"
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
