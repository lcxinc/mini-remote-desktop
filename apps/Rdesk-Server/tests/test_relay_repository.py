from __future__ import annotations

import hashlib
import hmac
import base64
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
import app.services.relay_repository as relay_repository_module


NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)


def fingerprint(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


CERTIFICATE = fingerprint("default-certificate")
def turn_secret(label: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(label.encode()).digest()).rstrip(
        b"="
    ).decode("ascii")


TURN_SECRET = turn_secret("node-unique-turn-rest-secret")
# Deterministic URL-safe values in this module are test fixtures only. Production
# enrollment tokens are minted through the repository's injected CSPRNG source.
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

    async def begin_nested(self) -> "AsyncTransactionShim":
        return AsyncTransactionShim(self.session.begin_nested())

    @property
    def bind(self) -> object:
        return self.session.get_bind()


class AsyncTransactionShim:
    def __init__(self, transaction: object) -> None:
        self.transaction = transaction

    async def commit(self) -> None:
        self.transaction.commit()

    async def rollback(self) -> None:
        self.transaction.rollback()


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
    ready: bool = False,
) -> RelayNode:
    await repository.store_enrollment_token(
        token=token,
        expires_at=NOW + timedelta(minutes=5),
        now=NOW,
    )
    node = await repository.enroll_node(
        token=token,
        node_id=node_id,
        region="ap-east",
        failure_domain=f"rack-{node_id}",
        certificate_fingerprint=fingerprint(f"certificate:{node_id}"),
        endpoints=ENDPOINTS,
        max_allocations=max_allocations,
        max_egress_bps=1_000_000,
        turn_secret=turn_secret("node:" + node_id),
        now=NOW,
    )
    if ready:
        for sequence in (1, 2, 3):
            await repository.record_heartbeat(
                node_id=node.node_id,
                certificate_fingerprint=node.certificate_fingerprint,
                sequence=sequence,
                active_allocations=0,
                current_egress_bps=0,
                now=NOW,
            )
    return node


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
            certificate_fingerprint=fingerprint("other"),
            endpoints=ENDPOINTS,
            max_allocations=10,
            max_egress_bps=1_000_000,
            turn_secret=turn_secret("another-node-secret"),
            now=NOW,
        )
    assert error.value.code == "ENROLLMENT_TOKEN_USED"
    assert raw not in str(error.value)


@pytest.mark.anyio
async def test_issue_enrollment_token_requests_256_bits_and_returns_raw_once(
    db_session: AsyncSessionShim,
    cipher: AesGcmRelaySecretCipher,
) -> None:
    entropy_requests: list[int] = []
    raw = "A" * 43

    def token_source(byte_count: int) -> str:
        entropy_requests.append(byte_count)
        return raw

    repository = RelayRepository(
        db_session,
        enrollment_token_pepper=bytes.fromhex("22" * 32),
        secret_cipher=cipher,
        enrollment_token_source=token_source,
    )
    issued = await repository.issue_enrollment_token(
        expires_at=NOW + timedelta(minutes=5),
        now=NOW,
    )
    assert issued == raw
    assert entropy_requests == [32]

    stored = await db_session.scalar(select(RelayEnrollment))
    assert stored is not None
    assert raw not in stored.token_digest
    assert raw not in repr(stored)

    await repository.enroll_node(
        token=issued,
        node_id="relay-issued",
        region="ap-east",
        failure_domain="rack-issued",
        certificate_fingerprint=fingerprint("issued"),
        endpoints=ENDPOINTS,
        max_allocations=1,
        max_egress_bps=1,
        turn_secret=turn_secret("issued-node-secret"),
        now=NOW,
    )
    with pytest.raises(RelayRepositoryError) as reused:
        await repository.enroll_node(
            token=issued,
            node_id="relay-issued-again",
            region="ap-east",
            failure_domain="rack-issued-again",
            certificate_fingerprint=fingerprint("issued-again"),
            endpoints=ENDPOINTS,
            max_allocations=1,
            max_egress_bps=1,
            turn_secret=turn_secret("issued-node-secret-again"),
            now=NOW,
        )
    assert reused.value.code == "ENROLLMENT_TOKEN_USED"


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
    assert cipher.decrypt(ciphertext, associated_data=node.node_id.encode()) == (
        turn_secret("node:" + node.node_id).encode("ascii")
    )

    with pytest.raises(RelayRepositoryError) as error:
        await repository.enroll_node(
            token="not-a-real-token",
            node_id="relay-secret-error",
            region="ap-east",
            failure_domain="rack-z",
            certificate_fingerprint=fingerprint("z"),
            endpoints=ENDPOINTS,
            max_allocations=1,
            max_egress_bps=1,
            turn_secret=turn_secret("must-not-leak"),
            now=NOW,
        )
    assert "must-not-leak" not in repr(error.value)


def test_secret_envelope_supports_key_rotation_and_rejects_unknown_keys() -> None:
    old_key = bytes.fromhex("51" * 32)
    new_key = bytes.fromhex("52" * 32)
    old_cipher = AesGcmRelaySecretCipher(old_key, key_id="old-2026")
    encrypted = old_cipher.encrypt(b"rotating-secret", associated_data=b"relay-a")
    assert b"rotating-secret" not in encrypted

    rotated = AesGcmRelaySecretCipher(
        new_key,
        key_id="new-2026",
        read_keys={"old-2026": old_key},
    )
    assert rotated.decrypt(encrypted, associated_data=b"relay-a") == b"rotating-secret"

    without_old_key = AesGcmRelaySecretCipher(new_key, key_id="new-2026")
    with pytest.raises(relay_repository_module.RelaySecretCipherError) as unknown:
        without_old_key.decrypt(encrypted, associated_data=b"relay-a")
    assert unknown.value.code == "UNKNOWN_KEY_ID"
    assert "rotating-secret" not in str(unknown.value)


def test_legacy_secret_envelope_requires_an_explicit_read_key() -> None:
    old_key = bytes.fromhex("61" * 32)
    new_key = bytes.fromhex("62" * 32)
    nonce = bytes.fromhex("63" * 12)
    associated_data = b"relay-legacy"
    plaintext = b"legacy-rotating-secret"
    legacy_envelope = (
        b"\x01"
        + nonce
        + AESGCM(old_key).encrypt(nonce, plaintext, associated_data)
    )

    rotated = AesGcmRelaySecretCipher(
        new_key,
        key_id="new-2026",
        read_keys={"old-2025": old_key},
        legacy_key_id="old-2025",
    )
    assert rotated.decrypt(legacy_envelope, associated_data=associated_data) == plaintext

    for cipher in (
        AesGcmRelaySecretCipher(
            new_key,
            key_id="new-2026",
            read_keys={"old-2025": old_key},
        ),
        AesGcmRelaySecretCipher(
            new_key,
            key_id="new-2026",
            read_keys={"old-2025": old_key},
            legacy_key_id="missing-key",
        ),
    ):
        with pytest.raises(relay_repository_module.RelaySecretCipherError) as error:
            cipher.decrypt(legacy_envelope, associated_data=associated_data)
        assert error.value.code == "LEGACY_KEY_UNAVAILABLE"
        assert plaintext.decode() not in str(error.value)


@pytest.mark.anyio
async def test_heartbeat_is_monotonic_bound_to_certificate_and_lease_is_exact(
    repository: RelayRepository,
) -> None:
    node = await enroll(repository)
    node_fingerprint = node.certificate_fingerprint
    heartbeat = await repository.record_heartbeat(
        node_id=node.node_id,
        certificate_fingerprint=node_fingerprint,
        sequence=1,
        active_allocations=1,
        current_egress_bps=500,
        now=NOW,
    )
    assert heartbeat.lease_expires_at == NOW + timedelta(seconds=15)

    with pytest.raises(RelayRepositoryError) as replay:
        await repository.record_heartbeat(
            node_id=node.node_id,
            certificate_fingerprint=node_fingerprint,
            sequence=1,
            active_allocations=1,
            current_egress_bps=500,
            now=NOW + timedelta(seconds=1),
        )
    assert replay.value.code == "HEARTBEAT_SEQUENCE_REPLAY"

    with pytest.raises(RelayRepositoryError) as wrong_certificate:
        await repository.record_heartbeat(
            node_id=node.node_id,
            certificate_fingerprint=fingerprint("attacker"),
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
            certificate_fingerprint=fingerprint("replacement"),
            endpoints=ENDPOINTS,
            max_allocations=10,
            max_egress_bps=1_000_000,
            turn_secret=turn_secret("replacement-secret"),
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
            certificate_fingerprint=fingerprint("bad"),
            endpoints=endpoints,
            max_allocations=1,
            max_egress_bps=1,
            turn_secret=turn_secret("not-stored"),
            now=NOW,
        )
    assert error.value.code == "INVALID_ENDPOINTS"
    assert await db_session.get(RelayNode, "bad-node") is None


@pytest.mark.anyio
async def test_endpoints_are_canonicalized_before_duplicate_detection(
    repository: RelayRepository,
) -> None:
    token = "canonical-endpoint-token"
    await repository.store_enrollment_token(
        token=token,
        expires_at=NOW + timedelta(minutes=5),
        now=NOW,
    )
    node = await repository.enroll_node(
        token=token,
        node_id="canonical-node",
        region="ap-east",
        failure_domain="rack-canonical",
        certificate_fingerprint=fingerprint("canonical"),
        endpoints=[
            "turn:Relay.Example.Test.:3478",
            "turns:[2001:0DB8::1]:5349",
        ],
        max_allocations=1,
        max_egress_bps=1,
        turn_secret=turn_secret("canonical-turn-secret"),
        now=NOW,
    )
    assert node.endpoints == [
        "turn:relay.example.test:3478?transport=udp",
        "turns:[2001:db8::1]:5349?transport=tcp",
    ]

    duplicate_token = "canonical-duplicate-token"
    await repository.store_enrollment_token(
        token=duplicate_token,
        expires_at=NOW + timedelta(minutes=5),
        now=NOW,
    )
    with pytest.raises(RelayRepositoryError) as duplicate:
        await repository.enroll_node(
            token=duplicate_token,
            node_id="canonical-duplicate-node",
            region="ap-east",
            failure_domain="rack-canonical-duplicate",
            certificate_fingerprint=fingerprint("canonical-duplicate"),
            endpoints=[
                "turn:Relay.Example.Test.:3478",
                "turn:relay.example.test:3478?transport=udp",
            ],
            max_allocations=1,
            max_egress_bps=1,
            turn_secret=turn_secret("canonical-duplicate-secret"),
            now=NOW,
        )
    assert duplicate.value.code == "INVALID_ENDPOINTS"


@pytest.mark.anyio
async def test_turns_udp_is_rejected(
    repository: RelayRepository,
) -> None:
    await repository.store_enrollment_token(
        token="turns-udp-invalid-token",
        expires_at=NOW + timedelta(minutes=5),
        now=NOW,
    )
    with pytest.raises(RelayRepositoryError) as error:
        await repository.enroll_node(
            token="turns-udp-invalid-token",
            node_id="turns-udp-node",
            region="ap-east",
            failure_domain="rack-turns-udp",
            certificate_fingerprint=fingerprint("turns-udp"),
            endpoints=["turns:relay.example.test:5349?transport=udp"],
            max_allocations=1,
            max_egress_bps=1,
            turn_secret=turn_secret("turns-udp-secret"),
            now=NOW,
        )
    assert error.value.code == "INVALID_ENDPOINTS"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "fingerprint",
    [
        "raw-fingerprint",
        "sha256:",
        "sha256:contains spaces",
        "sha256:unicode-指纹",
        "sha256:relay_enrollments_token_digest_key",
        "sha256:" + "A" * 64,
        "sha256:" + "a" * 63,
        "sha256:" + "a" * 129,
    ],
)
async def test_certificate_fingerprint_is_bounded_and_structurally_valid(
    repository: RelayRepository,
    db_session: AsyncSessionShim,
    fingerprint: str,
) -> None:
    token = "invalid-certificate-token"
    await repository.store_enrollment_token(
        token=token,
        expires_at=NOW + timedelta(minutes=5),
        now=NOW,
    )
    with pytest.raises(RelayRepositoryError) as error:
        await repository.enroll_node(
            token=token,
            node_id="invalid-certificate-node",
            region="ap-east",
            failure_domain="rack-invalid-certificate",
            certificate_fingerprint=fingerprint,
            endpoints=ENDPOINTS,
            max_allocations=1,
            max_egress_bps=1,
            turn_secret=turn_secret("not-persisted"),
            now=NOW,
        )
    assert error.value.code == "INVALID_CERTIFICATE"
    assert await db_session.get(RelayNode, "invalid-certificate-node") is None


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("overrides", "expected_code"),
    [
        ({"node_id": "n" * 129}, "INVALID_NODE_ID"),
        ({"node_id": "node with spaces"}, "INVALID_NODE_ID"),
        ({"region": "r" * 65}, "INVALID_NODE_LOCATION"),
        ({"region": "Region Upper"}, "INVALID_NODE_LOCATION"),
        ({"failure_domain": "f" * 129}, "INVALID_NODE_LOCATION"),
        ({"max_allocations": 2**31}, "INVALID_CAPACITY"),
        ({"max_egress_bps": 2**63}, "INVALID_CAPACITY"),
        ({"turn_secret": "short"}, "INVALID_TURN_SECRET"),
        ({"turn_secret": "s" * 513}, "INVALID_TURN_SECRET"),
        ({"turn_secret": "\ud800" * 16}, "INVALID_TURN_SECRET"),
    ],
)
async def test_enrollment_validates_database_widths_and_numeric_ranges(
    repository: RelayRepository,
    overrides: dict[str, object],
    expected_code: str,
) -> None:
    token = "bounded-enrollment-token"
    await repository.store_enrollment_token(
        token=token,
        expires_at=NOW + timedelta(minutes=5),
        now=NOW,
    )
    arguments = {
        "token": token,
        "node_id": "bounded-enrollment-node",
        "region": "ap-east",
        "failure_domain": "rack-bounded",
        "certificate_fingerprint": fingerprint("bounded-enrollment"),
        "endpoints": ENDPOINTS,
        "max_allocations": 1,
        "max_egress_bps": 1,
        "turn_secret": "bounded-turn-secret",
        "now": NOW,
    }
    arguments.update(overrides)
    with pytest.raises(RelayRepositoryError) as error:
        await repository.enroll_node(**arguments)
    assert error.value.code == expected_code


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("sequence", "active", "egress"),
    [
        (2**63, 0, 0),
        (1, -1, 0),
        (1, 0, -1),
        (1, 0, 2**63),
    ],
)
async def test_heartbeat_validates_bigint_and_metric_ranges(
    repository: RelayRepository,
    sequence: int,
    active: int,
    egress: int,
) -> None:
    node = await enroll(repository, node_id="heartbeat-bounds-node")
    with pytest.raises(RelayRepositoryError) as error:
        await repository.record_heartbeat(
            node_id=node.node_id,
            certificate_fingerprint=node.certificate_fingerprint,
            sequence=sequence,
            active_allocations=active,
            current_egress_bps=egress,
            now=NOW,
        )
    assert error.value.code in {"HEARTBEAT_SEQUENCE_REPLAY", "INVALID_METRICS"}


@pytest.mark.anyio
async def test_reservations_preserve_order_are_bounded_idempotent_and_expire(
    repository: RelayRepository,
) -> None:
    await enroll(repository, node_id="relay-a", max_allocations=1, ready=True)
    await enroll(
        repository,
        node_id="relay-b",
        token="one-use-high-entropy-token-b",
        max_allocations=1,
        ready=True,
    )
    await enroll(
        repository,
        node_id="relay-c",
        token="one-use-high-entropy-token-c",
        max_allocations=1,
        ready=True,
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

    for node_id in ("relay-a", "relay-b"):
        for sequence in (4, 5, 6):
            await repository.record_heartbeat(
                node_id=node_id,
                certificate_fingerprint=fingerprint(f"certificate:{node_id}"),
                sequence=sequence,
                active_allocations=0,
                current_egress_bps=0,
                now=NOW + timedelta(seconds=29),
            )

    boundary = await repository.reserve_capacity(
        session_id="session-2",
        user_id="user-2",
        ordered_node_ids=["relay-b", "relay-a"],
        now=NOW + timedelta(seconds=30),
    )
    assert [reservation.node_id for reservation in boundary] == ["relay-b", "relay-a"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("state", "lease_offset_seconds", "eligible"),
    [
        ("available", 15, True),
        ("degraded", 15, True),
        ("draining", 15, False),
        ("unavailable", 15, False),
        ("revoked", 15, False),
        ("available", 0, False),
        ("degraded", -1, False),
    ],
)
async def test_reservation_rechecks_locked_node_state_and_exact_lease_boundary(
    repository: RelayRepository,
    state: str,
    lease_offset_seconds: int,
    eligible: bool,
) -> None:
    node = await enroll(repository, node_id="eligibility-node", ready=True)
    node.state = state
    node.lease_expires_at = NOW + timedelta(seconds=lease_offset_seconds)
    result = await repository.reserve_capacity(
        session_id="eligibility-session",
        user_id="eligibility-user",
        ordered_node_ids=[node.node_id],
        now=NOW,
    )
    assert bool(result) is eligible


@pytest.mark.anyio
@pytest.mark.parametrize("state", ["draining", "unavailable", "revoked"])
async def test_existing_pending_reservation_is_not_returned_after_node_ineligible(
    repository: RelayRepository,
    state: str,
) -> None:
    node = await enroll(repository, node_id="pending-state-node", ready=True)
    first = await repository.reserve_capacity(
        session_id="pending-state-session",
        user_id="pending-state-user",
        ordered_node_ids=[node.node_id],
        now=NOW,
    )
    assert len(first) == 1
    node.state = state
    repeated = await repository.reserve_capacity(
        session_id="pending-state-session",
        user_id="pending-state-user",
        ordered_node_ids=[node.node_id],
        now=NOW + timedelta(seconds=1),
    )
    assert repeated == []


@pytest.mark.anyio
async def test_repository_validates_identifier_numeric_ttl_and_candidate_bounds(
    repository: RelayRepository,
) -> None:
    node = await enroll(repository, node_id="bounded-node", ready=True)
    invalid_reservations = [
        ({"session_id": "s" * 129}, "INVALID_SESSION_ID"),
        ({"user_id": "u" * 129}, "INVALID_USER_ID"),
        ({"ttl_seconds": 301}, "INVALID_RESERVATION_TTL"),
        (
            {"ordered_node_ids": [f"node-{index}" for index in range(9)]},
            "TOO_MANY_CANDIDATES",
        ),
        ({"ordered_node_ids": ["bad node"]}, "INVALID_NODE_ID"),
    ]
    for overrides, expected_code in invalid_reservations:
        arguments = {
            "session_id": "bounded-session",
            "user_id": "bounded-user",
            "ordered_node_ids": [node.node_id],
            "now": NOW,
            "ttl_seconds": 30,
        }
        arguments.update(overrides)
        with pytest.raises(RelayRepositoryError) as error:
            await repository.reserve_capacity(**arguments)
        assert error.value.code == expected_code

    with pytest.raises(RelayRepositoryError) as ttl_error:
        await repository.reserve_capacity(
            session_id="bounded-session",
            user_id="bounded-user",
            ordered_node_ids=[node.node_id],
            now=NOW,
            ttl_seconds=301,
        )
    assert ttl_error.value.code == "INVALID_RESERVATION_TTL"
    assert str(ttl_error.value) == "TTL must be between 1 and 300 seconds"

    node.lease_expires_at = datetime.max.replace(tzinfo=UTC)
    with pytest.raises(RelayRepositoryError) as overflow:
        await repository.reserve_capacity(
            session_id="overflow-session",
            user_id="overflow-user",
            ordered_node_ids=[node.node_id],
            now=datetime.max.replace(tzinfo=UTC) - timedelta(seconds=1),
            ttl_seconds=30,
        )
    assert overflow.value.code == "INVALID_RESERVATION_TTL"


@pytest.mark.anyio
async def test_reported_active_allocations_and_pending_reservations_share_capacity(
    repository: RelayRepository,
) -> None:
    node = await enroll(repository, node_id="relay-capacity", max_allocations=1)
    await repository.record_heartbeat(
        node_id=node.node_id,
        certificate_fingerprint=node.certificate_fingerprint,
        sequence=1,
        active_allocations=1,
        current_egress_bps=0,
        now=NOW,
    )
    assert await repository.reserve_capacity(
        session_id="session-full",
        user_id="user-full",
        ordered_node_ids=[node.node_id],
        now=NOW,
    ) == []

    node.active_allocations = 0
    for sequence in (2, 3):
        await repository.record_heartbeat(
            node_id=node.node_id,
            certificate_fingerprint=node.certificate_fingerprint,
            sequence=sequence,
            active_allocations=0,
            current_egress_bps=0,
            now=NOW,
        )
    existing = await repository.reserve_capacity(
        session_id="session-existing",
        user_id="user-existing",
        ordered_node_ids=[node.node_id],
        now=NOW,
    )
    assert len(existing) == 1
    node.active_allocations = 1
    repeated = await repository.reserve_capacity(
        session_id="session-existing",
        user_id="user-existing",
        ordered_node_ids=[node.node_id],
        now=NOW + timedelta(seconds=1),
    )
    assert [item.id for item in repeated] == [item.id for item in existing]
    assert await repository.reserve_capacity(
        session_id="session-rejected",
        user_id="user-rejected",
        ordered_node_ids=[node.node_id],
        now=NOW + timedelta(seconds=1),
    ) == []


class IntegrityConflictSession:
    def __init__(
        self,
        *,
        constraint_message: str,
        enrollment: RelayEnrollment | None = None,
        driver_error: Exception | None = None,
    ) -> None:
        self._enrollment = enrollment
        self._scalar_calls = 0
        self.outer_work = ["unrelated-work"]
        self.full_rolled_back = False
        self.nested_rolled_back = False
        self.error = IntegrityError(
            "INSERT INTO relay_nodes VALUES (...) ",
            {
                "certificate_fingerprint": fingerprint("sensitive-fingerprint"),
                "encrypted_turn_secret": b"ciphertext-not-plaintext",
            },
            driver_error or sqlite3.IntegrityError(constraint_message),
        )

    def add(self, instance: object) -> None:
        del instance

    async def get(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        return None

    async def scalar(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        self._scalar_calls += 1
        if self._enrollment is not None and self._scalar_calls == 1:
            return self._enrollment
        return None

    async def flush(self) -> None:
        raise self.error

    async def begin_nested(self) -> "IntegrityConflictSavepoint":
        return IntegrityConflictSavepoint(self)

    async def rollback(self) -> None:
        self.full_rolled_back = True
        self.outer_work.clear()


class IntegrityConflictSavepoint:
    def __init__(self, session: IntegrityConflictSession) -> None:
        self.session = session

    async def rollback(self) -> None:
        self.session.nested_rolled_back = True

    async def commit(self) -> None:
        raise AssertionError("conflicting savepoint must not commit")


class StructuredConstraintError(Exception):
    constraint_name = "relay_nodes_certificate_fingerprint_key"

    def __str__(self) -> str:
        return (
            "user value contains relay_enrollments_token_digest_key but the "
            "structured constraint is authoritative"
        )


@pytest.mark.anyio
async def test_structured_constraint_name_ignores_deceptive_error_detail(
    cipher: AesGcmRelaySecretCipher,
) -> None:
    pepper = bytes.fromhex("22" * 32)
    token = "structured-constraint-token"
    digest = hmac.new(
        pepper,
        b"MRD_RELAY_ENROLLMENT_V1\x00" + token.encode(),
        hashlib.sha256,
    ).hexdigest()
    session = IntegrityConflictSession(
        constraint_message="ignored",
        enrollment=RelayEnrollment(
            token_digest=digest,
            expires_at=NOW + timedelta(minutes=5),
            created_at=NOW,
        ),
        driver_error=StructuredConstraintError(),
    )
    repository = RelayRepository(
        session,
        enrollment_token_pepper=pepper,
        secret_cipher=cipher,
    )
    with pytest.raises(RelayRepositoryError) as error:
        await repository.enroll_node(
            token=token,
            node_id="structured-node",
            region="ap-east",
            failure_domain="rack-structured",
            certificate_fingerprint=fingerprint("structured"),
            endpoints=ENDPOINTS,
            max_allocations=1,
            max_egress_bps=1,
            turn_secret=turn_secret("structured-secret"),
            now=NOW,
        )
    assert error.value.code == "CERTIFICATE_ALREADY_BOUND"
    assert "relay_enrollments" not in str(error.value)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("constraint_message", "expected_code"),
    [
        ("UNIQUE constraint failed: relay_nodes.node_id", "NODE_ALREADY_EXISTS"),
        (
            "UNIQUE constraint failed: relay_nodes.certificate_fingerprint",
            "CERTIFICATE_ALREADY_BOUND",
        ),
    ],
)
async def test_enrollment_integrity_conflicts_are_stable_and_rollback(
    cipher: AesGcmRelaySecretCipher,
    constraint_message: str,
    expected_code: str,
) -> None:
    pepper = bytes.fromhex("22" * 32)
    token = "concurrent-enrollment-token"
    digest = hmac.new(
        pepper,
        b"MRD_RELAY_ENROLLMENT_V1\x00" + token.encode(),
        hashlib.sha256,
    ).hexdigest()
    enrollment = RelayEnrollment(
        token_digest=digest,
        expires_at=NOW + timedelta(minutes=5),
        created_at=NOW,
    )
    session = IntegrityConflictSession(
        constraint_message=constraint_message,
        enrollment=enrollment,
    )
    repository = RelayRepository(
        session,
        enrollment_token_pepper=pepper,
        secret_cipher=cipher,
    )
    with pytest.raises(RelayRepositoryError) as conflict:
        await repository.enroll_node(
            token=token,
            node_id="relay-conflict",
            region="ap-east",
            failure_domain="rack-conflict",
            certificate_fingerprint=fingerprint("sensitive-fingerprint"),
            endpoints=ENDPOINTS,
            max_allocations=1,
            max_egress_bps=1,
            turn_secret=turn_secret("sensitive-turn-secret"),
            now=NOW,
        )
    assert conflict.value.code == expected_code
    assert session.nested_rolled_back
    assert not session.full_rolled_back
    assert session.outer_work == ["unrelated-work"]
    assert "sensitive" not in str(conflict.value)


@pytest.mark.anyio
async def test_token_digest_integrity_conflict_is_stable_and_rolls_back(
    cipher: AesGcmRelaySecretCipher,
) -> None:
    session = IntegrityConflictSession(
        constraint_message="UNIQUE constraint failed: relay_enrollments.token_digest"
    )
    repository = RelayRepository(
        session,
        enrollment_token_pepper=bytes.fromhex("22" * 32),
        secret_cipher=cipher,
    )
    with pytest.raises(RelayRepositoryError) as conflict:
        await repository.store_enrollment_token(
            token="sensitive-concurrent-token",
            expires_at=NOW + timedelta(minutes=5),
            now=NOW,
        )
    assert conflict.value.code == "ENROLLMENT_TOKEN_EXISTS"
    assert session.nested_rolled_back
    assert not session.full_rolled_back
    assert session.outer_work == ["unrelated-work"]
    assert "sensitive" not in str(conflict.value)


@pytest.mark.anyio
async def test_unknown_integrity_error_rolls_back_without_misclassification(
    cipher: AesGcmRelaySecretCipher,
) -> None:
    session = IntegrityConflictSession(
        constraint_message=(
            "UNIQUE constraint failed: unrelated_table.unrelated_column"
        )
    )
    repository = RelayRepository(
        session,
        enrollment_token_pepper=bytes.fromhex("22" * 32),
        secret_cipher=cipher,
    )
    with pytest.raises(IntegrityError) as unknown:
        await repository.store_enrollment_token(
            token="unknown-constraint-token",
            expires_at=NOW + timedelta(minutes=5),
            now=NOW,
        )
    assert unknown.value is session.error
    assert session.nested_rolled_back
    assert not session.full_rolled_back
    assert session.outer_work == ["unrelated-work"]


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
            certificate_fingerprint=fingerprint("invalid"),
            encrypted_turn_secret=b"ciphertext",
            max_allocations=0,
            active_allocations=0,
            max_egress_bps=1,
            current_egress_bps=0,
            heartbeat_sequence=0,
            lease_expires_at=NOW,
            revoked_at=None,
            created_at=NOW,
            updated_at=NOW,
        )
    )
    with pytest.raises(IntegrityError, match="ck_relay_nodes_max_allocations"):
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


def test_startup_runs_relay_migration_before_legacy_metadata_bootstrap() -> None:
    main_source = (
        Path(__file__).parents[1] / "app" / "main.py"
    ).read_text(encoding="utf-8")
    migration_call = "await migrate_relay_control(conn)"
    legacy_bootstrap = "await conn.run_sync(Base.metadata.create_all)"
    assert migration_call in main_source
    assert legacy_bootstrap in main_source
    assert main_source.index(migration_call) < main_source.index(legacy_bootstrap)
    assert "legacy/dev bootstrap" in main_source
