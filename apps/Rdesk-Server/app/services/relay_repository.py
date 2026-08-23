from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import ipaddress
import re
import secrets
import sqlite3
import weakref
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.relay_enrollment import RelayEnrollment
from app.models.relay_node import RelayNode
from app.models.relay_node_registration import RelayNodeRegistration
from app.models.relay_reservation import RelayReservation


_TOKEN_CONTEXT = b"MRD_RELAY_ENROLLMENT_V1\x00"
_SESSION_LOCK_CONTEXT = b"MRD_RELAY_SESSION_LOCK_V1\x00"
_LEGACY_CIPHERTEXT_VERSION = b"\x01"
_CIPHERTEXT_VERSION = b"\x02"
_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{20,512}$")
_CERTIFICATE_FINGERPRINT_PATTERN = re.compile(
    r"^sha256:[0-9a-f]{64}$"
)
_GENERAL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REGION_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_POSTGRES_INTEGER_MAX = 2**31 - 1
_POSTGRES_BIGINT_MAX = 2**63 - 1
_MAX_RESERVATION_TTL_SECONDS = 300
_SQLITE_UNIQUE_CONSTRAINT_PATTERN = re.compile(
    r"^UNIQUE constraint failed: "
    r"(?P<columns>[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*"
    r"(?:, [a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*)*)$"
)
_ENDPOINT_PATTERN = re.compile(
    r"^(?P<scheme>turn|turns):"
    r"(?P<host>\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+):"
    r"(?P<port>[0-9]{1,5})"
    r"(?:\?transport=(?P<transport>udp|tcp))?$",
    flags=re.IGNORECASE | re.ASCII,
)
_LOCAL_SESSION_LOCKS: weakref.WeakValueDictionary[
    tuple[int, str], asyncio.Lock
] = weakref.WeakValueDictionary()


class RelayRepositoryError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class RelaySecretCipherError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class RelaySecretCipher(Protocol):
    def encrypt(self, plaintext: bytes, *, associated_data: bytes) -> bytes: ...

    def decrypt(self, ciphertext: bytes, *, associated_data: bytes) -> bytes: ...

    def decrypt_mutable(
        self, ciphertext: bytes, *, associated_data: bytes
    ) -> bytearray: ...

    def needs_reencrypt(self, ciphertext: bytes) -> bool: ...


class AesGcmRelaySecretCipher:
    """Versioned AES-GCM boundary; callers must inject an application-managed key."""

    def __init__(
        self,
        key: bytes,
        *,
        key_id: str = "active",
        read_keys: dict[str, bytes] | None = None,
        legacy_key_id: str | None = None,
    ) -> None:
        _validate_encryption_key(key)
        if _KEY_ID_PATTERN.fullmatch(key_id) is None:
            raise ValueError("relay secret key id is invalid")
        keys = dict(read_keys or {})
        for read_key_id, read_key in keys.items():
            if _KEY_ID_PATTERN.fullmatch(read_key_id) is None:
                raise ValueError("relay secret read key id is invalid")
            _validate_encryption_key(read_key)
        if (
            legacy_key_id is not None
            and _KEY_ID_PATTERN.fullmatch(legacy_key_id) is None
        ):
            raise ValueError("relay legacy secret key id is invalid")
        keys[key_id] = key
        self._active_key_id = key_id
        self._legacy_key_id = legacy_key_id
        self._keys = keys
        self._active_aes_gcm = AESGCM(key)

    def encrypt(self, plaintext: bytes, *, associated_data: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        encoded_key_id = self._active_key_id.encode("ascii")
        return (
            _CIPHERTEXT_VERSION
            + bytes([len(encoded_key_id)])
            + encoded_key_id
            + nonce
            + self._active_aes_gcm.encrypt(nonce, plaintext, associated_data)
        )

    def decrypt(self, ciphertext: bytes, *, associated_data: bytes) -> bytes:
        if not ciphertext:
            raise RelaySecretCipherError(
                "INVALID_ENVELOPE", "relay secret envelope is invalid"
            )
        if ciphertext[:1] == _LEGACY_CIPHERTEXT_VERSION:
            if len(ciphertext) < 29:
                raise RelaySecretCipherError(
                    "INVALID_ENVELOPE", "relay secret envelope is invalid"
                )
            nonce = ciphertext[1:13]
            encrypted = ciphertext[13:]
            legacy_key = (
                self._keys.get(self._legacy_key_id)
                if self._legacy_key_id is not None
                else None
            )
            if legacy_key is None:
                raise RelaySecretCipherError(
                    "LEGACY_KEY_UNAVAILABLE",
                    "legacy relay secret key is unavailable",
                )
            aes_gcm = AESGCM(legacy_key)
        elif ciphertext[:1] == _CIPHERTEXT_VERSION:
            if len(ciphertext) < 30:
                raise RelaySecretCipherError(
                    "INVALID_ENVELOPE", "relay secret envelope is invalid"
                )
            key_id_length = ciphertext[1]
            nonce_offset = 2 + key_id_length
            if key_id_length == 0 or len(ciphertext) < nonce_offset + 28:
                raise RelaySecretCipherError(
                    "INVALID_ENVELOPE", "relay secret envelope is invalid"
                )
            try:
                key_id = ciphertext[2:nonce_offset].decode("ascii")
            except UnicodeDecodeError:
                raise RelaySecretCipherError(
                    "INVALID_ENVELOPE", "relay secret envelope is invalid"
                ) from None
            key = self._keys.get(key_id)
            if key is None:
                raise RelaySecretCipherError(
                    "UNKNOWN_KEY_ID", "relay secret key id is unavailable"
                )
            nonce = ciphertext[nonce_offset : nonce_offset + 12]
            encrypted = ciphertext[nonce_offset + 12 :]
            aes_gcm = AESGCM(key)
        else:
            raise RelaySecretCipherError(
                "INVALID_ENVELOPE", "relay secret envelope is invalid"
            )
        try:
            return aes_gcm.decrypt(nonce, encrypted, associated_data)
        except InvalidTag:
            raise RelaySecretCipherError(
                "AUTHENTICATION_FAILED", "relay secret authentication failed"
            ) from None

    def decrypt_mutable(
        self, ciphertext: bytes, *, associated_data: bytes
    ) -> bytearray:
        # AESGCM returns one unavoidable immutable bytes object. Convert it at the
        # cipher boundary and drop that reference immediately; callers own and
        # clear the only retained mutable copy.
        plaintext = self.decrypt(ciphertext, associated_data=associated_data)
        try:
            return bytearray(plaintext)
        finally:
            del plaintext

    def needs_reencrypt(self, ciphertext: bytes) -> bool:
        if not ciphertext:
            raise RelaySecretCipherError(
                "INVALID_ENVELOPE", "relay secret envelope is invalid"
            )
        if ciphertext[:1] == _LEGACY_CIPHERTEXT_VERSION:
            return True
        if ciphertext[:1] != _CIPHERTEXT_VERSION or len(ciphertext) < 3:
            raise RelaySecretCipherError(
                "INVALID_ENVELOPE", "relay secret envelope is invalid"
            )
        key_id_length = ciphertext[1]
        if key_id_length == 0 or len(ciphertext) < 2 + key_id_length + 28:
            raise RelaySecretCipherError(
                "INVALID_ENVELOPE", "relay secret envelope is invalid"
            )
        try:
            envelope_key_id = ciphertext[2 : 2 + key_id_length].decode("ascii")
        except UnicodeDecodeError:
            raise RelaySecretCipherError(
                "INVALID_ENVELOPE", "relay secret envelope is invalid"
            ) from None
        if envelope_key_id not in self._keys:
            raise RelaySecretCipherError(
                "UNKNOWN_KEY_ID", "relay secret key id is unavailable"
            )
        return envelope_key_id != self._active_key_id


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
        if (
            not isinstance(enrollment_token_pepper, bytes)
            or len(enrollment_token_pepper) < 32
        ):
            raise ValueError("enrollment token pepper must contain at least 32 bytes")
        if not _integer_in_range(
            max_reservations_per_session, minimum=1, maximum=8
        ):
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
        savepoint = await self._session.begin_nested()
        try:
            self._session.add(enrollment)
            await self._session.flush()
        except IntegrityError as error:
            code = _integrity_conflict_code(error)
            await savepoint.rollback()
            if code != "ENROLLMENT_TOKEN_EXISTS":
                raise
            raise RelayRepositoryError(
                "ENROLLMENT_TOKEN_EXISTS", "enrollment token already exists"
            ) from None
        await savepoint.commit()
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
        if not _valid_general_id(node_id):
            raise RelayRepositoryError("INVALID_NODE_ID", "invalid relay node id")
        if (
            not isinstance(region, str)
            or _REGION_PATTERN.fullmatch(region) is None
            or not _valid_general_id(failure_domain)
        ):
            raise RelayRepositoryError("INVALID_NODE_LOCATION", "invalid node location")
        if (
            not _integer_in_range(max_allocations, minimum=1, maximum=_POSTGRES_INTEGER_MAX)
            or not _integer_in_range(max_egress_bps, minimum=1, maximum=_POSTGRES_BIGINT_MAX)
        ):
            raise RelayRepositoryError("INVALID_CAPACITY", "capacity must be positive")
        if not _valid_certificate_fingerprint(certificate_fingerprint):
            raise RelayRepositoryError(
                "INVALID_CERTIFICATE", "certificate fingerprint is invalid"
            )
        turn_secret_bytes = _validated_turn_secret(turn_secret)

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
                turn_secret_bytes, associated_data=node_id.encode()
            ),
            max_allocations=max_allocations,
            active_allocations=0,
            max_egress_bps=max_egress_bps,
            current_egress_bps=0,
            heartbeat_sequence=0,
            healthy_heartbeat_streak=0,
            created_at=now,
            updated_at=now,
        )
        savepoint = await self._session.begin_nested()
        try:
            enrollment.used_at = now
            enrollment.enrolled_node_id = node_id
            self._session.add(node)
            await self._session.flush()
        except IntegrityError as error:
            code = _integrity_conflict_code(error)
            await savepoint.rollback()
            if code not in {"NODE_ALREADY_EXISTS", "CERTIFICATE_ALREADY_BOUND"}:
                raise
            if code == "NODE_ALREADY_EXISTS":
                message = "relay node already exists"
            else:
                message = "certificate is already bound"
            raise RelayRepositoryError(code, message) from None
        await savepoint.commit()
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
        if not _valid_certificate_fingerprint(certificate_fingerprint):
            raise RelayRepositoryError(
                "INVALID_CERTIFICATE", "certificate fingerprint is invalid"
            )
        if not hmac.compare_digest(
            node.certificate_fingerprint, certificate_fingerprint
        ):
            raise RelayRepositoryError(
                "CERTIFICATE_MISMATCH", "certificate does not match relay node"
            )
        if (
            not _integer_in_range(sequence, minimum=0, maximum=_POSTGRES_BIGINT_MAX)
            or sequence <= node.heartbeat_sequence
        ):
            raise RelayRepositoryError(
                "HEARTBEAT_SEQUENCE_REPLAY", "heartbeat sequence must increase"
            )
        if (
            not _integer_in_range(
                active_allocations,
                minimum=0,
                maximum=_POSTGRES_INTEGER_MAX,
            )
            or active_allocations > node.max_allocations
        ):
            raise RelayRepositoryError("INVALID_METRICS", "invalid allocation metric")
        if not _integer_in_range(
            current_egress_bps,
            minimum=0,
            maximum=_POSTGRES_BIGINT_MAX,
        ):
            raise RelayRepositoryError("INVALID_METRICS", "invalid egress metric")

        was_fresh_ready = (
            node.state in {"available", "degraded"}
            and node.lease_expires_at is not None
            and _as_utc(node.lease_expires_at) > now
        )
        previous_state = node.state
        node.heartbeat_sequence = sequence
        node.active_allocations = active_allocations
        node.current_egress_bps = current_egress_bps
        node.lease_expires_at = _checked_add_seconds(
            now,
            seconds=15,
            code="INVALID_HEARTBEAT_TIME",
        )
        node.updated_at = now
        if previous_state == "draining":
            pass
        elif was_fresh_ready:
            node.healthy_heartbeat_streak = 3
        elif previous_state == "unavailable":
            node.healthy_heartbeat_streak = min(
                node.healthy_heartbeat_streak + 1, 3
            )
            node.state = (
                "available"
                if node.healthy_heartbeat_streak >= 3
                else "unavailable"
            )
        else:
            node.healthy_heartbeat_streak = 1
            node.state = "unavailable"
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
            node.healthy_heartbeat_streak = 0
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
        expires_at: datetime | None = None,
        directory_generation: str | None = None,
        require_registration: bool = False,
        result_limit: int | None = None,
    ) -> list[RelayReservation]:
        """Reserve up to primary plus one backup, preserving candidate order.

        An unexpired reservation for the same session/node is returned unchanged and
        does not consume capacity twice. Expiry is exclusive: expires_at == now is
        deleted before admission.
        """
        _require_utc(now)
        if not _valid_general_id(session_id):
            raise RelayRepositoryError("INVALID_SESSION_ID", "invalid session id")
        if not _valid_general_id(user_id):
            raise RelayRepositoryError("INVALID_USER_ID", "invalid user id")
        if expires_at is not None:
            _require_utc(expires_at)
            exact_ttl = (expires_at - now).total_seconds()
            if not 0 < exact_ttl <= _MAX_RESERVATION_TTL_SECONDS:
                raise RelayRepositoryError(
                    "INVALID_RESERVATION_TTL",
                    f"TTL must be between 1 and {_MAX_RESERVATION_TTL_SECONDS} seconds",
                )
        elif not _integer_in_range(
            ttl_seconds, minimum=1, maximum=_MAX_RESERVATION_TTL_SECONDS
        ):
            raise RelayRepositoryError(
                "INVALID_RESERVATION_TTL",
                f"TTL must be between 1 and {_MAX_RESERVATION_TTL_SECONDS} seconds",
            )
        if not isinstance(ordered_node_ids, list):
            raise RelayRepositoryError("INVALID_NODE_ID", "invalid candidate nodes")
        if result_limit is None:
            result_limit = self._max_reservations
        if not _integer_in_range(result_limit, minimum=1, maximum=8):
            raise RelayRepositoryError(
                "INVALID_RESULT_LIMIT", "result limit must be between 1 and 8"
            )
        if len(ordered_node_ids) > 8:
            raise RelayRepositoryError(
                "TOO_MANY_CANDIDATES", "at most eight relay candidates are allowed"
            )
        if any(not _valid_general_id(node_id) for node_id in ordered_node_ids):
            raise RelayRepositoryError("INVALID_NODE_ID", "invalid candidate node id")
        if directory_generation is not None and not _valid_general_id(
            directory_generation
        ):
            raise RelayRepositoryError(
                "INVALID_DIRECTORY_GENERATION", "invalid directory generation"
            )
        ordered_unique = list(dict.fromkeys(ordered_node_ids))
        if not ordered_unique:
            return []
        reservation_expires_at = expires_at or _checked_add_seconds(
            now, seconds=ttl_seconds, code="INVALID_RESERVATION_TTL"
        )

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
                expires_at=reservation_expires_at,
                directory_generation=directory_generation,
                require_registration=require_registration,
                result_limit=result_limit,
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
                expires_at=reservation_expires_at,
                directory_generation=directory_generation,
                require_registration=require_registration,
                result_limit=result_limit,
            )

    async def _reserve_capacity_locked(
        self,
        *,
        session_id: str,
        user_id: str,
        ordered_node_ids: list[str],
        now: datetime,
        expires_at: datetime,
        directory_generation: str | None,
        require_registration: bool,
        result_limit: int,
    ) -> list[RelayReservation]:
        if directory_generation is not None:
            # A new generation atomically retires the previous directory's current
            # slots. The rows remain live and continue to consume node capacity until
            # their credential expiry. Any later failure rolls this update back.
            await self._session.execute(
                update(RelayReservation)
                .where(
                    RelayReservation.session_id == session_id,
                    RelayReservation.expires_at > now,
                    RelayReservation.superseded_at.is_(None),
                    RelayReservation.directory_generation != directory_generation,
                )
                .values(superseded_at=now)
                .execution_options(synchronize_session=False)
            )
            await self._session.flush()

        active_rows = list(await self._session.scalars(
            select(RelayReservation)
            .where(
                RelayReservation.session_id == session_id,
                RelayReservation.expires_at > now,
            )
            .execution_options(populate_existing=True)
        ))
        existing = {
            reservation.node_id: reservation for reservation in active_rows
        }
        if any(
            reservation.user_id != user_id for reservation in active_rows
        ):
            raise RelayRepositoryError(
                "SESSION_OWNER_MISMATCH", "reservation belongs to another user"
            )

        result: list[RelayReservation] = []
        for node_id in ordered_node_ids:
            if len(result) >= result_limit:
                break
            if require_registration:
                locked = await self._session.execute(
                    select(RelayNode, RelayNodeRegistration)
                    .join(
                        RelayNodeRegistration,
                        RelayNodeRegistration.node_id == RelayNode.node_id,
                    )
                    .where(RelayNode.node_id == node_id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
                row = locked.first()
                if row is None:
                    continue
                node, registration = row
                eligible = _node_and_registration_accept_pending_reservation(
                    node, registration, now=now
                )
            else:
                node = await self._session.scalar(
                    select(RelayNode)
                    .where(RelayNode.node_id == node_id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
                if node is None:
                    continue
                eligible = _node_accepts_pending_reservation(node, now=now)
            await self._session.execute(
                delete(RelayReservation).where(
                    RelayReservation.node_id == node_id,
                    RelayReservation.expires_at <= now,
                ).execution_options(synchronize_session=False)
            )
            await self._session.flush()
            same_session = existing.get(node_id)
            if not eligible:
                if same_session is not None and directory_generation is None:
                    await self._session.delete(same_session)
                    existing.pop(node_id, None)
                    active_rows.remove(same_session)
                    await self._session.flush()
                continue
            if same_session is not None:
                if directory_generation is not None:
                    same_session.superseded_at = None
                    same_session.directory_generation = directory_generation
                result.append(same_session)
                continue
            current_count = sum(
                reservation.superseded_at is None for reservation in active_rows
            )
            if current_count >= self._max_reservations:
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
                or node.max_egress_bps <= 0
                or node.current_egress_bps < 0
                or node.current_egress_bps >= node.max_egress_bps
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
                expires_at=expires_at,
                superseded_at=None,
                directory_generation=directory_generation or "legacy",
                created_at=now,
            )
            self._session.add(reservation)
            await self._session.flush()
            active_rows.append(reservation)
            existing[node_id] = reservation
            result.append(reservation)
        return result

    async def _locked_node(self, node_id: str) -> RelayNode:
        if not _valid_general_id(node_id):
            raise RelayRepositoryError("INVALID_NODE_ID", "invalid relay node id")
        node = await self._session.scalar(
            select(RelayNode)
            .where(RelayNode.node_id == node_id)
            .with_for_update()
            .execution_options(populate_existing=True)
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
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
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
    ):
        raise RelayRepositoryError("INVALID_ENDPOINTS", "invalid relay endpoints")
    canonical: list[str] = []
    for endpoint in endpoints:
        matched = _ENDPOINT_PATTERN.fullmatch(endpoint)
        if matched is None or not 1 <= int(matched.group("port")) <= 65535:
            raise RelayRepositoryError("INVALID_ENDPOINTS", "invalid relay endpoints")
        scheme = matched.group("scheme").lower()
        transport = (matched.group("transport") or "").lower()
        if not transport:
            transport = "udp" if scheme == "turn" else "tcp"
        if scheme == "turns" and transport != "tcp":
            raise RelayRepositoryError("INVALID_ENDPOINTS", "invalid relay endpoints")
        host = _canonical_host(matched.group("host"))
        if host is None:
            raise RelayRepositoryError("INVALID_ENDPOINTS", "invalid relay endpoints")
        port = int(matched.group("port"))
        # turns over transport=tcp is TLS; plain turn maps directly to UDP/TCP.
        canonical.append(f"{scheme}:{host}:{port}?transport={transport}")
    if len(set(canonical)) != len(canonical):
        raise RelayRepositoryError("INVALID_ENDPOINTS", "invalid relay endpoints")
    return canonical


def _canonical_host(host: str) -> str | None:
    if host.startswith("["):
        try:
            address = ipaddress.ip_address(host[1:-1])
            if address.version != 6:
                return None
            return f"[{address.compressed}]"
        except ValueError:
            return None
    ascii_host = host.rstrip(".").lower()
    if not ascii_host or len(ascii_host) > 253 or not ascii_host.isascii():
        return None
    try:
        address = ipaddress.ip_address(ascii_host)
        if address.version == 4:
            return address.compressed
    except ValueError:
        pass
    labels = ascii_host.split(".")
    if not all(
        label
        and len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(character.isalnum() or character == "-" for character in label)
        for label in labels
    ):
        return None
    return ascii_host


def _valid_certificate_fingerprint(fingerprint: str) -> bool:
    # Canonical representation: lowercase sha256 prefix and exactly 64 lowercase hex.
    return (
        isinstance(fingerprint, str)
        and _CERTIFICATE_FINGERPRINT_PATTERN.fullmatch(fingerprint) is not None
    )


def _valid_general_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and _GENERAL_ID_PATTERN.fullmatch(value) is not None
    )


def _validated_turn_secret(value: object) -> bytes:
    """Accept only the node-agent's canonical 32-byte base64url secret."""

    if (
        not isinstance(value, str)
        or len(value) != 43
        or not value.isascii()
        or re.fullmatch(r"[A-Za-z0-9_-]{43}", value) is None
    ):
        raise RelayRepositoryError("INVALID_TURN_SECRET", "TURN secret required")
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (ValueError, binascii.Error):
        raise RelayRepositoryError(
            "INVALID_TURN_SECRET", "TURN secret required"
        ) from None
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if (
        len(decoded) != 32
        or not hmac.compare_digest(canonical, value)
        or not _turn_secret_has_minimum_quality(decoded)
    ):
        raise RelayRepositoryError("INVALID_TURN_SECRET", "TURN secret required")
    return decoded


def _turn_secret_has_minimum_quality(secret: bytes | bytearray) -> bool:
    # This is not an entropy estimator. It rejects deterministic deployment
    # placeholders and repeated-byte material while generation remains CSPRNG-only.
    lowered = bytes(secret).lower()
    return (
        len(secret) == 32
        and len(set(secret)) >= 8
        and not any(
            marker in lowered
            for marker in (b"placeholder", b"changeme", b"change-me")
        )
    )


def _integer_in_range(value: object, *, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _checked_add_seconds(now: datetime, *, seconds: int, code: str) -> datetime:
    try:
        return now + timedelta(seconds=seconds)
    except OverflowError:
        raise RelayRepositoryError(code, "timestamp exceeds supported range") from None


def _node_accepts_pending_reservation(node: RelayNode, *, now: datetime) -> bool:
    return (
        node.state in {"available", "degraded"}
        and node.lease_expires_at is not None
        and _as_utc(node.lease_expires_at) > now
    )


def _node_and_registration_accept_pending_reservation(
    node: RelayNode,
    registration: RelayNodeRegistration,
    *,
    now: datetime,
) -> bool:
    return (
        _node_accepts_pending_reservation(node, now=now)
        and node.revoked_at is None
        and registration.status == "approved"
        and registration.certificate_expires_at is not None
        and _as_utc(registration.certificate_expires_at) > now
        and registration.topology_approved_at is not None
        and registration.physical_host_id is not None
        and registration.physical_host_id == node.physical_host_id
        and registration.failure_domain == node.failure_domain
        and registration.encrypted_turn_secret is not None
    )


def _validate_encryption_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) not in {16, 24, 32}:
        raise ValueError("relay secret encryption key must be 16, 24, or 32 bytes")


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
    constraint_codes = {
        "relay_enrollments_token_digest_key": "ENROLLMENT_TOKEN_EXISTS",
        "relay_nodes_pkey": "NODE_ALREADY_EXISTS",
        "relay_nodes_certificate_fingerprint_key": "CERTIFICATE_ALREADY_BOUND",
    }
    sqlite_column_codes = {
        ("relay_enrollments.token_digest",): "ENROLLMENT_TOKEN_EXISTS",
        ("relay_nodes.node_id",): "NODE_ALREADY_EXISTS",
        ("relay_nodes.certificate_fingerprint",): "CERTIFICATE_ALREADY_BOUND",
    }

    pending: list[tuple[object, int]] = [(error.orig, 0)]
    visited: set[int] = set()
    while pending:
        current, depth = pending.pop()
        identity = id(current)
        if identity in visited or depth > 8:
            continue
        visited.add(identity)

        names = [getattr(current, "constraint_name", None)]
        diagnostic = getattr(current, "diag", None)
        if diagnostic is not None:
            names.append(getattr(diagnostic, "constraint_name", None))
        for name in names:
            if isinstance(name, str):
                code = constraint_codes.get(name)
                if code is not None:
                    return code

        if isinstance(current, sqlite3.IntegrityError):
            matched = _SQLITE_UNIQUE_CONSTRAINT_PATTERN.fullmatch(str(current))
            if matched is not None:
                columns = tuple(matched.group("columns").split(", "))
                code = sqlite_column_codes.get(columns)
                if code is not None:
                    return code

        if depth < 8:
            for attribute in ("orig", "__cause__", "__context__"):
                linked = getattr(current, attribute, None)
                if linked is not None:
                    pending.append((linked, depth + 1))
    return None
