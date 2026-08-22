from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import re
import secrets
import weakref
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.relay_enrollment import RelayEnrollment
from app.models.relay_node import RelayNode
from app.models.relay_reservation import RelayReservation


_TOKEN_CONTEXT = b"MRD_RELAY_ENROLLMENT_V1\x00"
_SESSION_LOCK_CONTEXT = b"MRD_RELAY_SESSION_LOCK_V1\x00"
_CIPHERTEXT_VERSION = b"\x01"
_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{20,512}$")
_ENDPOINT_PATTERN = re.compile(
    r"^(?:turn|turns):(?P<host>\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+):"
    r"(?P<port>[0-9]{1,5})(?:\?transport=(?:udp|tcp))?$"
)
_LOCAL_SESSION_LOCKS: weakref.WeakValueDictionary[
    tuple[int, str], asyncio.Lock
] = weakref.WeakValueDictionary()


class RelayRepositoryError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class RelaySecretCipher(Protocol):
    def encrypt(self, plaintext: bytes, *, associated_data: bytes) -> bytes: ...

    def decrypt(self, ciphertext: bytes, *, associated_data: bytes) -> bytes: ...


class AesGcmRelaySecretCipher:
    """Versioned AES-GCM boundary; callers must inject an application-managed key."""

    def __init__(self, key: bytes) -> None:
        if len(key) not in {16, 24, 32}:
            raise ValueError("relay secret encryption key must be 16, 24, or 32 bytes")
        self._aes_gcm = AESGCM(key)

    def encrypt(self, plaintext: bytes, *, associated_data: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        return (
            _CIPHERTEXT_VERSION
            + nonce
            + self._aes_gcm.encrypt(nonce, plaintext, associated_data)
        )

    def decrypt(self, ciphertext: bytes, *, associated_data: bytes) -> bytes:
        if len(ciphertext) < 30 or ciphertext[:1] != _CIPHERTEXT_VERSION:
            raise ValueError("unsupported relay secret ciphertext")
        nonce = ciphertext[1:13]
        return self._aes_gcm.decrypt(nonce, ciphertext[13:], associated_data)


class RelayRepository:
    def __init__(
        self,
        session: AsyncSession,
        *,
        enrollment_token_pepper: bytes,
        secret_cipher: RelaySecretCipher,
        max_reservations_per_session: int = 2,
        enrollment_token_source: Callable[[int], str] | None = None,
    ) -> None:
        if len(enrollment_token_pepper) < 32:
            raise ValueError("enrollment token pepper must contain at least 32 bytes")
        if not 1 <= max_reservations_per_session <= 8:
            raise ValueError("max reservations per session must be between 1 and 8")
        self._session = session
        self._token_pepper = enrollment_token_pepper
        self._secret_cipher = secret_cipher
        self._max_reservations = max_reservations_per_session
        self._enrollment_token_source = (
            enrollment_token_source or secrets.token_urlsafe
        )

    async def issue_enrollment_token(
        self, *, expires_at: datetime, now: datetime
    ) -> str:
        """Mint a 256-bit CSPRNG token and persist only its keyed digest."""
        token = self._enrollment_token_source(32)
        await self.store_enrollment_token(
            token=token,
            expires_at=expires_at,
            now=now,
        )
        return token

    async def store_enrollment_token(
        self, *, token: str, expires_at: datetime, now: datetime
    ) -> RelayEnrollment:
        _require_utc(expires_at)
        _require_utc(now)
        if expires_at <= now:
            raise RelayRepositoryError("INVALID_TOKEN_EXPIRY", "token must expire later")
        digest = self._token_digest(token)
        if await self._session.scalar(
            select(RelayEnrollment).where(RelayEnrollment.token_digest == digest)
        ):
            raise RelayRepositoryError("ENROLLMENT_TOKEN_EXISTS", "token already exists")
        enrollment = RelayEnrollment(
            token_digest=digest,
            expires_at=expires_at,
            created_at=now,
        )
        self._session.add(enrollment)
        try:
            await self._session.flush()
        except IntegrityError as error:
            if _integrity_conflict_code(error) != "ENROLLMENT_TOKEN_EXISTS":
                raise
            await self._session.rollback()
            raise RelayRepositoryError(
                "ENROLLMENT_TOKEN_EXISTS", "enrollment token already exists"
            ) from None
        return enrollment

    async def enroll_node(
        self,
        *,
        token: str,
        node_id: str,
        region: str,
        failure_domain: str,
        certificate_fingerprint: str,
        endpoints: list[str],
        max_allocations: int,
        max_egress_bps: int,
        turn_secret: str,
        now: datetime,
    ) -> RelayNode:
        _require_utc(now)
        validated_endpoints = _validate_endpoints(endpoints)
        if not node_id or len(node_id) > 128:
            raise RelayRepositoryError("INVALID_NODE_ID", "invalid relay node id")
        if not region or not failure_domain:
            raise RelayRepositoryError("INVALID_NODE_LOCATION", "invalid node location")
        if max_allocations <= 0 or max_egress_bps <= 0:
            raise RelayRepositoryError("INVALID_CAPACITY", "capacity must be positive")
        if not certificate_fingerprint:
            raise RelayRepositoryError("INVALID_CERTIFICATE", "certificate required")
        if not turn_secret:
            raise RelayRepositoryError("INVALID_TURN_SECRET", "TURN secret required")

        digest = self._token_digest(token)
        enrollment = await self._session.scalar(
            select(RelayEnrollment)
            .where(RelayEnrollment.token_digest == digest)
            .with_for_update()
        )
        if enrollment is None or not hmac.compare_digest(
            enrollment.token_digest, digest
        ):
            raise RelayRepositoryError(
                "ENROLLMENT_TOKEN_INVALID", "enrollment token is invalid"
            )
        if enrollment.used_at is not None:
            raise RelayRepositoryError(
                "ENROLLMENT_TOKEN_USED", "enrollment token was already used"
            )
        if _as_utc(enrollment.expires_at) <= now:
            raise RelayRepositoryError(
                "ENROLLMENT_TOKEN_EXPIRED", "enrollment token has expired"
            )

        existing = await self._session.get(RelayNode, node_id)
        if existing is not None:
            if existing.state == "revoked":
                raise RelayRepositoryError("NODE_REVOKED", "relay node is revoked")
            raise RelayRepositoryError("NODE_ALREADY_EXISTS", "relay node already exists")
        duplicate_certificate = await self._session.scalar(
            select(RelayNode.node_id).where(
                RelayNode.certificate_fingerprint == certificate_fingerprint
            )
        )
        if duplicate_certificate is not None:
            raise RelayRepositoryError(
                "CERTIFICATE_ALREADY_BOUND", "certificate is already bound"
            )

        node = RelayNode(
            node_id=node_id,
            region=region,
            failure_domain=failure_domain,
            state="unavailable",
            endpoints=validated_endpoints,
            certificate_fingerprint=certificate_fingerprint,
            encrypted_turn_secret=self._secret_cipher.encrypt(
                turn_secret.encode(), associated_data=node_id.encode()
            ),
            max_allocations=max_allocations,
            active_allocations=0,
            max_egress_bps=max_egress_bps,
            current_egress_bps=0,
            heartbeat_sequence=0,
            created_at=now,
            updated_at=now,
        )
        enrollment.used_at = now
        enrollment.enrolled_node_id = node_id
        self._session.add(node)
        try:
            await self._session.flush()
        except IntegrityError as error:
            code = _integrity_conflict_code(error)
            if code not in {"NODE_ALREADY_EXISTS", "CERTIFICATE_ALREADY_BOUND"}:
                raise
            await self._session.rollback()
            if code == "NODE_ALREADY_EXISTS":
                message = "relay node already exists"
            else:
                message = "certificate is already bound"
            raise RelayRepositoryError(code, message) from None
        return node

    async def record_heartbeat(
        self,
        *,
        node_id: str,
        certificate_fingerprint: str,
        sequence: int,
        active_allocations: int,
        current_egress_bps: int,
        now: datetime,
    ) -> RelayNode:
        _require_utc(now)
        node = await self._locked_node(node_id)
        if node.state == "revoked":
            raise RelayRepositoryError("NODE_REVOKED", "relay node is revoked")
        if not hmac.compare_digest(
            node.certificate_fingerprint, certificate_fingerprint
        ):
            raise RelayRepositoryError(
                "CERTIFICATE_MISMATCH", "certificate does not match relay node"
            )
        if sequence <= node.heartbeat_sequence:
            raise RelayRepositoryError(
                "HEARTBEAT_SEQUENCE_REPLAY", "heartbeat sequence must increase"
            )
        if not 0 <= active_allocations <= node.max_allocations:
            raise RelayRepositoryError("INVALID_METRICS", "invalid allocation metric")
        if current_egress_bps < 0:
            raise RelayRepositoryError("INVALID_METRICS", "invalid egress metric")

        node.heartbeat_sequence = sequence
        node.active_allocations = active_allocations
        node.current_egress_bps = current_egress_bps
        node.lease_expires_at = now + timedelta(seconds=15)
        node.updated_at = now
        if node.state == "unavailable":
            node.state = "available"
        await self._session.flush()
        return node

    async def live_nodes(self, *, now: datetime) -> list[RelayNode]:
        _require_utc(now)
        nodes = await self._session.scalars(
            select(RelayNode)
            .where(
                RelayNode.state != "revoked",
                RelayNode.lease_expires_at.is_not(None),
                RelayNode.lease_expires_at > now,
            )
            .order_by(RelayNode.node_id)
        )
        return list(nodes)

    async def revoke_node(self, *, node_id: str, now: datetime) -> RelayNode:
        _require_utc(now)
        node = await self._locked_node(node_id)
        if node.state != "revoked":
            node.state = "revoked"
            node.revoked_at = now
            node.lease_expires_at = now
            node.updated_at = now
            await self._session.flush()
        return node

    async def reserve_capacity(
        self,
        *,
        session_id: str,
        user_id: str,
        ordered_node_ids: list[str],
        now: datetime,
        ttl_seconds: int = 30,
    ) -> list[RelayReservation]:
        """Reserve up to primary plus one backup, preserving candidate order.

        An unexpired reservation for the same session/node is returned unchanged and
        does not consume capacity twice. Expiry is exclusive: expires_at == now is
        deleted before admission.
        """
        _require_utc(now)
        if not session_id or not user_id:
            raise RelayRepositoryError("INVALID_RESERVATION_SCOPE", "scope required")
        if ttl_seconds <= 0:
            raise RelayRepositoryError("INVALID_RESERVATION_TTL", "TTL must be positive")
        ordered_unique = list(dict.fromkeys(ordered_node_ids))
        if not ordered_unique:
            return []

        if _session_dialect_name(self._session) == "postgresql":
            # A 64-bit hash collision only serializes unrelated sessions; it cannot
            # weaken the reservation bound. PostgreSQL releases this at transaction end.
            await self._session.execute(
                text("SELECT pg_advisory_xact_lock(:lock_key)"),
                {"lock_key": _session_advisory_lock_key(session_id)},
            )
            return await self._reserve_capacity_locked(
                session_id=session_id,
                user_id=user_id,
                ordered_node_ids=ordered_unique,
                now=now,
                ttl_seconds=ttl_seconds,
            )

        # This lock is only an equivalent for single-process unit stores. It is not
        # a cross-process production guarantee; PostgreSQL uses the transaction lock.
        lock = _local_session_lock(session_id)
        async with lock:
            return await self._reserve_capacity_locked(
                session_id=session_id,
                user_id=user_id,
                ordered_node_ids=ordered_unique,
                now=now,
                ttl_seconds=ttl_seconds,
            )

    async def _reserve_capacity_locked(
        self,
        *,
        session_id: str,
        user_id: str,
        ordered_node_ids: list[str],
        now: datetime,
        ttl_seconds: int,
    ) -> list[RelayReservation]:

        locked_nodes = await self._session.scalars(
            select(RelayNode)
            .where(RelayNode.node_id.in_(ordered_node_ids))
            .order_by(RelayNode.node_id)
            .with_for_update()
        )
        nodes_by_id = {node.node_id: node for node in locked_nodes}

        await self._session.execute(
            delete(RelayReservation).where(
                RelayReservation.node_id.in_(ordered_node_ids),
                RelayReservation.expires_at <= now,
            )
        )
        await self._session.flush()

        current = await self._session.scalars(
            select(RelayReservation).where(
                RelayReservation.session_id == session_id,
                RelayReservation.expires_at > now,
            )
        )
        current_reservations = list(current)
        existing = {
            reservation.node_id: reservation for reservation in current_reservations
        }
        if any(
            reservation.user_id != user_id for reservation in current_reservations
        ):
            raise RelayRepositoryError(
                "SESSION_OWNER_MISMATCH", "reservation belongs to another user"
            )

        result: list[RelayReservation] = []
        for node_id in ordered_node_ids:
            if len(result) >= self._max_reservations:
                break
            if node_id in existing:
                result.append(existing[node_id])
                continue
            if len(current_reservations) >= self._max_reservations:
                continue
            node = nodes_by_id.get(node_id)
            if node is None or node.state == "revoked":
                continue
            used = await self._session.scalar(
                select(func.count())
                .select_from(RelayReservation)
                .where(
                    RelayReservation.node_id == node_id,
                    RelayReservation.expires_at > now,
                )
            )
            pending_reservations = int(used or 0)
            # Subtract before comparing instead of adding reported active and pending
            # counts. This is conservative for invalid/corrupt values and cannot wrap.
            if (
                node.max_allocations <= 0
                or node.active_allocations < 0
                or node.active_allocations >= node.max_allocations
            ):
                continue
            remaining_after_active = (
                node.max_allocations - node.active_allocations
            )
            if pending_reservations >= remaining_after_active:
                continue
            reservation = RelayReservation(
                session_id=session_id,
                user_id=user_id,
                node_id=node_id,
                expires_at=now + timedelta(seconds=ttl_seconds),
                created_at=now,
            )
            self._session.add(reservation)
            await self._session.flush()
            current_reservations.append(reservation)
            result.append(reservation)
        return result

    async def _locked_node(self, node_id: str) -> RelayNode:
        node = await self._session.scalar(
            select(RelayNode)
            .where(RelayNode.node_id == node_id)
            .with_for_update()
        )
        if node is None:
            raise RelayRepositoryError("NODE_NOT_FOUND", "relay node was not found")
        return node

    def _token_digest(self, token: str) -> str:
        # This validates external token structure only. Entropy is guaranteed by
        # issue_enrollment_token's 32-byte CSPRNG request, not by string length.
        if not isinstance(token, str) or _TOKEN_PATTERN.fullmatch(token) is None:
            raise RelayRepositoryError(
                "INVALID_ENROLLMENT_TOKEN", "enrollment token is invalid"
            )
        return hmac.new(
            self._token_pepper,
            _TOKEN_CONTEXT + token.encode(),
            hashlib.sha256,
        ).hexdigest()


def _require_utc(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise RelayRepositoryError("UTC_REQUIRED", "UTC-aware datetime required")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _validate_endpoints(endpoints: list[str]) -> list[str]:
    if (
        not isinstance(endpoints, list)
        or not 1 <= len(endpoints) <= 4
        or any(not isinstance(endpoint, str) for endpoint in endpoints)
        or len(set(endpoints)) != len(endpoints)
    ):
        raise RelayRepositoryError("INVALID_ENDPOINTS", "invalid relay endpoints")
    for endpoint in endpoints:
        matched = _ENDPOINT_PATTERN.fullmatch(endpoint)
        if (
            matched is None
            or not 1 <= int(matched.group("port")) <= 65535
            or not _valid_host(matched.group("host"))
        ):
            raise RelayRepositoryError("INVALID_ENDPOINTS", "invalid relay endpoints")
    return list(endpoints)


def _valid_host(host: str) -> bool:
    if host.startswith("["):
        try:
            return ipaddress.ip_address(host[1:-1]).version == 6
        except ValueError:
            return False
    if len(host) > 253:
        return False
    labels = host.split(".")
    return all(
        label
        and len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(character.isalnum() or character == "-" for character in label)
        for label in labels
    )


def _session_dialect_name(session: object) -> str | None:
    bind = getattr(session, "bind", None)
    if bind is None:
        get_bind = getattr(session, "get_bind", None)
        if get_bind is not None:
            bind = get_bind()
    dialect = getattr(bind, "dialect", None)
    return getattr(dialect, "name", None)


def _session_advisory_lock_key(session_id: str) -> int:
    digest = hashlib.sha256(
        _SESSION_LOCK_CONTEXT + session_id.encode()
    ).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=True)


def _local_session_lock(session_id: str) -> asyncio.Lock:
    loop_key = id(asyncio.get_running_loop())
    key = (loop_key, session_id)
    lock = _LOCAL_SESSION_LOCKS.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _LOCAL_SESSION_LOCKS[key] = lock
    return lock


def _integrity_conflict_code(error: IntegrityError) -> str | None:
    details: list[str] = []
    current: object | None = error.orig
    for _ in range(4):
        if current is None:
            break
        constraint_name = getattr(current, "constraint_name", None)
        if constraint_name:
            details.append(str(constraint_name).lower())
        details.append(str(current).lower())
        current = getattr(current, "__cause__", None)
    combined = " ".join(details)
    if (
        "relay_enrollments_token_digest_key" in combined
        or "relay_enrollments.token_digest" in combined
    ):
        return "ENROLLMENT_TOKEN_EXISTS"
    if "relay_nodes_pkey" in combined or "relay_nodes.node_id" in combined:
        return "NODE_ALREADY_EXISTS"
    if (
        "relay_nodes_certificate_fingerprint_key" in combined
        or "relay_nodes.certificate_fingerprint" in combined
    ):
        return "CERTIFICATE_ALREADY_BOUND"
    return None
