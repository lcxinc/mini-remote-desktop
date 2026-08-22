from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.session import Base
from app.models.relay_enrollment import RelayEnrollment
from app.models.relay_node import RelayNode
from app.models.relay_reservation import RelayReservation
from app.services.relay_repository import (
    AesGcmRelaySecretCipher,
    RelayRepository,
    RelayRepositoryError,
)


NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
CERTIFICATE = "sha256:01aabbcc"
TURN_SECRET = "node-unique-turn-rest-secret"
ENDPOINTS = [
    "turn:relay.example.test:3478?transport=udp",
    "turns:relay.example.test:5349?transport=tcp",
]


class AsyncSessionShim:
    """Exercise async repository code against SQLite without weakening Postgres tests."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def add(self, instance: object) -> None:
        self.session.add(instance)

    async def get(self, *args: object, **kwargs: object) -> object:
        return self.session.get(*args, **kwargs)

    async def scalar(self, *args: object, **kwargs: object) -> object:
        return self.session.scalar(*args, **kwargs)

    async def scalars(self, *args: object, **kwargs: object) -> object:
        return self.session.scalars(*args, **kwargs)

    async def execute(self, *args: object, **kwargs: object) -> object:
        return self.session.execute(*args, **kwargs)

    async def flush(self) -> None:
        self.session.flush()

    async def commit(self) -> None:
        self.session.commit()

    async def rollback(self) -> None:
        self.session.rollback()

    async def delete(self, instance: object) -> None:
        self.session.delete(instance)

    async def refresh(self, instance: object) -> None:
        self.session.refresh(instance)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def db_session() -> AsyncSessionShim:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        yield AsyncSessionShim(session)
    engine.dispose()


@pytest.fixture
def cipher() -> AesGcmRelaySecretCipher:
    return AesGcmRelaySecretCipher(bytes.fromhex("11" * 32))


@pytest.fixture
def repository(
    db_session: AsyncSessionShim, cipher: AesGcmRelaySecretCipher
) -> RelayRepository:
    return RelayRepository(
        db_session,
        enrollment_token_pepper=bytes.fromhex("22" * 32),
        secret_cipher=cipher,
        max_reservations_per_session=2,
    )


async def enroll(
    repository: RelayRepository,
    *,
    node_id: str = "relay-a",
    token: str = "one-use-high-entropy-token-a",
    max_allocations: int = 2,
) -> RelayNode:
    await repository.store_enrollment_token(
        token=token,
        expires_at=NOW + timedelta(minutes=5),
        now=NOW,
    )
    return await repository.enroll_node(
        token=token,
        node_id=node_id,
        region="ap-east",
        failure_domain=f"rack-{node_id}",
        certificate_fingerprint=CERTIFICATE + node_id,
        endpoints=ENDPOINTS,
        max_allocations=max_allocations,
        max_egress_bps=1_000_000,
        turn_secret=TURN_SECRET + node_id,
        now=NOW,
    )


@pytest.mark.anyio
async def test_enrollment_tokens_are_hashed_one_use_and_never_repr_raw(
    repository: RelayRepository, db_session: AsyncSessionShim
) -> None:
    raw = "one-use-high-entropy-token"
    await repository.store_enrollment_token(
        token=raw,
        expires_at=NOW + timedelta(minutes=5),
        now=NOW,
    )
    stored = await db_session.scalar(select(RelayEnrollment))
    assert stored is not None
    assert raw not in stored.token_digest
    assert raw not in repr(stored)

    await repository.enroll_node(
        token=raw,
        node_id="relay-a",
        region="ap-east",
        failure_domain="rack-a",
        certificate_fingerprint=CERTIFICATE,
        endpoints=ENDPOINTS,
        max_allocations=10,
        max_egress_bps=1_000_000,
        turn_secret=TURN_SECRET,
        now=NOW,
    )
    with pytest.raises(RelayRepositoryError) as error:
        await repository.enroll_node(
            token=raw,
            node_id="relay-b",
            region="ap-east",
            failure_domain="rack-b",
            certificate_fingerprint="sha256:other",
            endpoints=ENDPOINTS,
            max_allocations=10,
            max_egress_bps=1_000_000,
            turn_secret="another-secret",
            now=NOW,
        )
    assert error.value.code == "ENROLLMENT_TOKEN_USED"
    assert raw not in str(error.value)


@pytest.mark.anyio
async def test_turn_secret_is_encrypted_at_rest_and_not_in_repr_or_errors(
    repository: RelayRepository,
    db_session: AsyncSessionShim,
    cipher: AesGcmRelaySecretCipher,
) -> None:
    node = await enroll(repository)
    await db_session.refresh(node)
    ciphertext = bytes(node.encrypted_turn_secret)
    assert TURN_SECRET.encode() not in ciphertext
    assert TURN_SECRET not in repr(node)
    assert cipher.decrypt(ciphertext, associated_data=node.node_id.encode()).decode() == (
        TURN_SECRET + node.node_id
    )

    with pytest.raises(RelayRepositoryError) as error:
        await repository.enroll_node(
            token="not-a-real-token",
            node_id="relay-secret-error",
            region="ap-east",
            failure_domain="rack-z",
            certificate_fingerprint="sha256:z",
            endpoints=ENDPOINTS,
            max_allocations=1,
            max_egress_bps=1,
            turn_secret="must-not-leak",
            now=NOW,
        )
    assert "must-not-leak" not in repr(error.value)


@pytest.mark.anyio
async def test_heartbeat_is_monotonic_bound_to_certificate_and_lease_is_exact(
    repository: RelayRepository,
) -> None:
    node = await enroll(repository)
    fingerprint = node.certificate_fingerprint
    heartbeat = await repository.record_heartbeat(
        node_id=node.node_id,
        certificate_fingerprint=fingerprint,
        sequence=1,
        active_allocations=1,
        current_egress_bps=500,
        now=NOW,
    )
    assert heartbeat.lease_expires_at == NOW + timedelta(seconds=15)

    with pytest.raises(RelayRepositoryError) as replay:
        await repository.record_heartbeat(
            node_id=node.node_id,
            certificate_fingerprint=fingerprint,
            sequence=1,
            active_allocations=1,
            current_egress_bps=500,
            now=NOW + timedelta(seconds=1),
        )
    assert replay.value.code == "HEARTBEAT_SEQUENCE_REPLAY"

    with pytest.raises(RelayRepositoryError) as wrong_certificate:
        await repository.record_heartbeat(
            node_id=node.node_id,
            certificate_fingerprint="sha256:attacker",
            sequence=2,
            active_allocations=1,
            current_egress_bps=500,
            now=NOW + timedelta(seconds=1),
        )
    assert wrong_certificate.value.code == "CERTIFICATE_MISMATCH"

    still_live = await repository.live_nodes(
        now=NOW + timedelta(seconds=14, milliseconds=999)
    )
    assert [item.node_id for item in still_live] == [node.node_id]
    assert await repository.live_nodes(now=NOW + timedelta(seconds=15)) == []


@pytest.mark.anyio
async def test_revocation_cannot_be_undone_by_heartbeat_or_reenrollment(
    repository: RelayRepository,
) -> None:
    node = await enroll(repository)
    await repository.revoke_node(node_id=node.node_id, now=NOW + timedelta(seconds=1))

    with pytest.raises(RelayRepositoryError) as heartbeat:
        await repository.record_heartbeat(
            node_id=node.node_id,
            certificate_fingerprint=node.certificate_fingerprint,
            sequence=1,
            active_allocations=0,
            current_egress_bps=0,
            now=NOW + timedelta(seconds=2),
        )
    assert heartbeat.value.code == "NODE_REVOKED"

    await repository.store_enrollment_token(
        token="replacement-enrollment-token",
        expires_at=NOW + timedelta(minutes=5),
        now=NOW,
    )
    with pytest.raises(RelayRepositoryError) as reenroll:
        await repository.enroll_node(
            token="replacement-enrollment-token",
            node_id=node.node_id,
            region="ap-east",
            failure_domain="rack-new",
            certificate_fingerprint="sha256:replacement",
            endpoints=ENDPOINTS,
            max_allocations=10,
            max_egress_bps=1_000_000,
            turn_secret="replacement-secret",
            now=NOW,
        )
    assert reenroll.value.code == "NODE_REVOKED"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "endpoints",
    [
        [],
        ["http://relay.example.test:3478"],
        ["turn:relay.example.test:0"],
        ["turn:relay.example.test:70000"],
        ["turn:user@relay.example.test:3478"],
        ["turn:relay..example.test:3478"],
        [123],
        ["turn:relay.example.test:3478"] * 2,
        [f"turn:relay-{index}.example.test:3478" for index in range(5)],
    ],
)
async def test_invalid_endpoints_are_rejected_before_persistence(
    repository: RelayRepository,
    db_session: AsyncSessionShim,
    endpoints: list[str],
) -> None:
    token = "invalid-endpoint-token"
    await repository.store_enrollment_token(
        token=token,
        expires_at=NOW + timedelta(minutes=5),
        now=NOW,
    )
    with pytest.raises(RelayRepositoryError) as error:
        await repository.enroll_node(
            token=token,
            node_id="bad-node",
            region="ap-east",
            failure_domain="rack-bad",
            certificate_fingerprint="sha256:bad",
            endpoints=endpoints,
            max_allocations=1,
            max_egress_bps=1,
            turn_secret="not-stored",
            now=NOW,
        )
    assert error.value.code == "INVALID_ENDPOINTS"
    assert await db_session.get(RelayNode, "bad-node") is None


@pytest.mark.anyio
async def test_reservations_preserve_order_are_bounded_idempotent_and_expire(
    repository: RelayRepository,
) -> None:
    await enroll(repository, node_id="relay-a", max_allocations=1)
    await enroll(
        repository,
        node_id="relay-b",
        token="one-use-high-entropy-token-b",
        max_allocations=1,
    )
    await enroll(
        repository,
        node_id="relay-c",
        token="one-use-high-entropy-token-c",
        max_allocations=1,
    )

    first = await repository.reserve_capacity(
        session_id="session-1",
        user_id="user-1",
        ordered_node_ids=["relay-b", "relay-a", "relay-c"],
        now=NOW,
        ttl_seconds=30,
    )
    assert [reservation.node_id for reservation in first] == ["relay-b", "relay-a"]
    assert all(
        reservation.expires_at == NOW + timedelta(seconds=30)
        for reservation in first
    )

    repeated = await repository.reserve_capacity(
        session_id="session-1",
        user_id="user-1",
        ordered_node_ids=["relay-b", "relay-a", "relay-c"],
        now=NOW + timedelta(seconds=1),
    )
    assert [reservation.id for reservation in repeated] == [
        reservation.id for reservation in first
    ]

    changed_candidates = await repository.reserve_capacity(
        session_id="session-1",
        user_id="user-1",
        ordered_node_ids=["relay-c"],
        now=NOW + timedelta(seconds=1),
    )
    assert changed_candidates == []

    full = await repository.reserve_capacity(
        session_id="session-2",
        user_id="user-2",
        ordered_node_ids=["relay-b", "relay-a"],
        now=NOW + timedelta(seconds=29, milliseconds=999),
    )
    assert full == []

    boundary = await repository.reserve_capacity(
        session_id="session-2",
        user_id="user-2",
        ordered_node_ids=["relay-b", "relay-a"],
        now=NOW + timedelta(seconds=30),
    )
    assert [reservation.node_id for reservation in boundary] == ["relay-b", "relay-a"]


@pytest.mark.anyio
async def test_constraints_and_utc_aware_time_are_enforced(
    repository: RelayRepository,
    db_session: AsyncSessionShim,
) -> None:
    with pytest.raises(RelayRepositoryError) as naive:
        await repository.store_enrollment_token(
            token="naive-time-token",
            expires_at=datetime(2026, 8, 22, 12, 5),
            now=NOW,
        )
    assert naive.value.code == "UTC_REQUIRED"

    db_session.add(
        RelayNode(
            node_id="invalid-capacity",
            region="ap-east",
            failure_domain="rack-invalid",
            state="available",
            endpoints=ENDPOINTS,
            certificate_fingerprint="sha256:invalid",
            encrypted_turn_secret=b"ciphertext",
            max_allocations=0,
            active_allocations=-1,
            max_egress_bps=0,
            current_egress_bps=-1,
            heartbeat_sequence=-1,
        )
    )
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


def test_model_repr_does_not_expose_credential_fields() -> None:
    enrollment = RelayEnrollment(token_digest="super-secret-digest")
    reservation = RelayReservation(
        session_id="session-1",
        user_id="user-1",
        node_id="relay-a",
        expires_at=NOW,
    )
    assert "super-secret-digest" not in repr(enrollment)
    assert "token_digest" not in repr(enrollment)
    assert "password" not in repr(reservation).lower()
