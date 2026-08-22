from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.relay_enrollment import RelayEnrollment
from app.models.relay_node import RelayNode
from app.models.relay_reservation import RelayReservation


_TOKEN_CONTEXT = b"MRD_RELAY_ENROLLMENT_V1\x00"
_CIPHERTEXT_VERSION = b"\x01"
_ENDPOINT_PATTERN = re.compile(
    r"^(?:turn|turns):(?P<host>\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+):"
    r"(?P<port>[0-9]{1,5})(?:\?transport=(?:udp|tcp))?$"
)


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
    ) -> None:
        if len(enrollment_token_pepper) < 32:
            raise ValueError("enrollment token pepper must contain at least 32 bytes")
        if not 1 <= max_reservations_per_session <= 8:
            raise ValueError("max reservations per session must be between 1 and 8")
        self._session = session
        self._token_pepper = enrollment_token_pepper
        self._secret_cipher = secret_cipher
        self._max_reservations = max_reservations_per_session

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
        await self._session.flush()
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
        await self._session.flush()
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

        locked_nodes = await self._session.scalars(
            select(RelayNode)
            .where(RelayNode.node_id.in_(ordered_unique))
            .order_by(RelayNode.node_id)
            .with_for_update()
        )
        nodes_by_id = {node.node_id: node for node in locked_nodes}

        await self._session.execute(
            delete(RelayReservation).where(
                RelayReservation.node_id.in_(ordered_unique),
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
        for node_id in ordered_unique:
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
            if int(used or 0) >= node.max_allocations:
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
        if len(token) < 20:
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
