from __future__ import annotations

import base64
import hashlib
import hmac
import re
import time
from dataclasses import dataclass, field as dataclass_field
from typing import Callable, Protocol

from app.core.mutable_base64url import (
    decode_canonical_base64url,
    encode_unpadded_base64url,
    zeroize,
)


SCOPE_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class TurnCredentialExpired(ValueError):
    pass


class TurnCredentialConfigurationError(RuntimeError):
    pass


class RelaySecretDecryptor(Protocol):
    def decrypt_mutable(
        self, ciphertext: bytes, *, associated_data: bytes
    ) -> bytearray: ...

    def encrypt(self, plaintext: bytes, *, associated_data: bytes) -> bytes: ...

    def needs_reencrypt(self, ciphertext: bytes) -> bool: ...


@dataclass(frozen=True)
class TurnCredential:
    urls: tuple[str, ...]
    username: str = dataclass_field(repr=False)
    credential: str = dataclass_field(repr=False)
    expires_at_unix_seconds: int
    ttl_seconds: int
    transport_policy: str = "relay"


@dataclass(frozen=True)
class NodeTurnCredential:
    node_id: str
    urls: tuple[str, ...]
    username: str = dataclass_field(repr=False)
    credential: str = dataclass_field(repr=False)
    expires_at_unix_seconds: int
    reencrypted_secret: bytes | None = dataclass_field(
        default=None, repr=False, compare=False
    )


class TurnCredentialService:
    def __init__(
        self,
        *,
        auth_secret: str,
        urls: list[str],
        ttl_seconds: int,
        now: Callable[[], int] | None = None,
    ) -> None:
        if not auth_secret:
            raise TurnCredentialConfigurationError("TURN auth secret is not configured")
        if not urls or any(
            not url.startswith(("turn:", "turns:")) for url in urls
        ):
            raise TurnCredentialConfigurationError("TURN URLs are not configured correctly")
        if not 1 <= ttl_seconds <= 86_400:
            raise TurnCredentialConfigurationError(
                "TURN credential TTL must be between 1 and 86400 seconds"
            )
        self._auth_secret = auth_secret.encode("utf-8")
        self._urls = tuple(urls)
        self._ttl_seconds = ttl_seconds
        self._now = now or (lambda: int(time.time()))

    def issue(
        self,
        *,
        user_id: str,
        session_id: str,
        credential_deadline_unix_seconds: int,
    ) -> TurnCredential:
        self._validate_scope("user_id", user_id)
        self._validate_scope("session_id", session_id)
        now = self._now()
        if credential_deadline_unix_seconds <= now:
            raise TurnCredentialExpired("session authorization has expired")
        expires_at = min(
            credential_deadline_unix_seconds, now + self._ttl_seconds
        )
        username = f"{expires_at}:{user_id}:{session_id}"
        credential = base64.b64encode(
            hmac.new(self._auth_secret, username.encode("utf-8"), hashlib.sha1).digest()
        ).decode("ascii")
        return TurnCredential(
            urls=self._urls,
            username=username,
            credential=credential,
            expires_at_unix_seconds=expires_at,
            ttl_seconds=expires_at - now,
        )

    def verify(self, username: str, credential: str, now: int | None = None) -> bool:
        try:
            expires_at = int(username.split(":", 1)[0])
        except (ValueError, IndexError):
            return False
        if expires_at <= (self._now() if now is None else now):
            return False
        expected = base64.b64encode(
            hmac.new(self._auth_secret, username.encode("utf-8"), hashlib.sha1).digest()
        ).decode("ascii")
        return hmac.compare_digest(expected, credential)

    @staticmethod
    def _validate_scope(name: str, value: str) -> None:
        if not SCOPE_PATTERN.fullmatch(value):
            raise ValueError(
                f"{name} must contain only letters, digits, '.', '_' or '-'"
            )


class NodeTurnCredentialService:
    """Issue coturn REST credentials from one encrypted, node-bound secret."""

    def __init__(
        self,
        *,
        cipher: RelaySecretDecryptor,
        ttl_seconds: int = 600,
        now: Callable[[], int] | None = None,
    ) -> None:
        if not 1 <= ttl_seconds <= 86_400:
            raise TurnCredentialConfigurationError(
                "TURN credential TTL must be between 1 and 86400 seconds"
            )
        self._cipher = cipher
        self._ttl_seconds = ttl_seconds
        self._now = now or (lambda: int(time.time()))

    def issue(
        self,
        *,
        user_id: str,
        session_id: str,
        node_id: str,
        urls: list[str],
        encrypted_secret: bytes,
        grant_deadline_unix_seconds: int,
        directory_deadline_unix_seconds: int,
        policy_deadline_unix_seconds: int,
        node_deadline_unix_seconds: int,
    ) -> NodeTurnCredential:
        for name, value in (
            ("user_id", user_id),
            ("session_id", session_id),
            ("node_id", node_id),
        ):
            TurnCredentialService._validate_scope(name, value)
        if not urls or len(urls) > 4 or any(
            not isinstance(url, str) or not url.startswith(("turn:", "turns:"))
            for url in urls
        ):
            raise TurnCredentialConfigurationError("TURN URLs are invalid")
        now = self._now()
        expires_at = min(
            now + self._ttl_seconds,
            grant_deadline_unix_seconds,
            directory_deadline_unix_seconds,
            policy_deadline_unix_seconds,
            node_deadline_unix_seconds,
        )
        if expires_at <= now:
            raise TurnCredentialExpired("relay authorization has expired")
        username = f"{expires_at}:{user_id}:{session_id}:{node_id}"
        secret = self._cipher.decrypt_mutable(
            encrypted_secret, associated_data=node_id.encode("utf-8")
        )
        wire_secret: bytearray | None = None
        try:
            if not isinstance(secret, bytearray):
                raise TurnCredentialConfigurationError(
                    "relay credential material is unavailable"
                )
            wire_secret, legacy_raw_envelope = _coturn_wire_secret(secret)
            credential = base64.b64encode(
                hmac.new(
                    wire_secret, username.encode("utf-8"), hashlib.sha1
                ).digest()
            ).decode("ascii")
            reencrypted_secret = (
                self._cipher.encrypt(
                    bytes(wire_secret), associated_data=node_id.encode("utf-8")
                )
                if legacy_raw_envelope
                or self._cipher.needs_reencrypt(encrypted_secret)
                else None
            )
        finally:
            if wire_secret is not None and wire_secret is not secret:
                for index in range(len(wire_secret)):
                    wire_secret[index] = 0
            for index in range(len(secret)):
                secret[index] = 0
        return NodeTurnCredential(
            node_id=node_id,
            urls=tuple(urls),
            username=username,
            credential=credential,
            expires_at_unix_seconds=expires_at,
            reencrypted_secret=reencrypted_secret,
        )

    @staticmethod
    def verify_with_secret(
        username: str, credential: str, secret: bytes, *, now: int
    ) -> bool:
        try:
            expires_at = int(username.split(":", 1)[0])
        except (TypeError, ValueError, IndexError):
            return False
        if expires_at <= now:
            return False
        expected = base64.b64encode(
            hmac.new(secret, username.encode("utf-8"), hashlib.sha1).digest()
        ).decode("ascii")
        return hmac.compare_digest(expected, credential)


def _coturn_wire_secret(secret: bytearray) -> tuple[bytearray, bool]:
    """Return canonical string bytes and whether a legacy raw envelope was read."""

    if len(secret) == 32 and _raw_turn_secret_has_minimum_quality(secret):
        return encode_unpadded_base64url(memoryview(secret)), True
    if len(secret) != 43:
        raise TurnCredentialConfigurationError(
            "relay credential material is unavailable"
        )
    try:
        decoded = decode_canonical_base64url(
            memoryview(secret), expected_length=32
        )
        if not _raw_turn_secret_has_minimum_quality(decoded):
            raise TurnCredentialConfigurationError(
                "relay credential material is unavailable"
            )
        return secret, False
    except ValueError:
        raise TurnCredentialConfigurationError(
            "relay credential material is unavailable"
        ) from None
    finally:
        if "decoded" in locals():
            zeroize(decoded)


def _raw_turn_secret_has_minimum_quality(secret: bytes | bytearray) -> bool:
    def contains_case_insensitive(marker: bytes) -> bool:
        if len(marker) > len(secret):
            return False
        for offset in range(len(secret) - len(marker) + 1):
            if all(
                (
                    secret[offset + index] + 32
                    if 65 <= secret[offset + index] <= 90
                    else secret[offset + index]
                )
                == marker[index]
                for index in range(len(marker))
            ):
                return True
        return False

    unique_count = 0
    for index in range(len(secret)):
        if all(secret[prior] != secret[index] for prior in range(index)):
            unique_count += 1

    return (
        len(secret) == 32
        and unique_count >= 8
        and not any(
            contains_case_insensitive(marker)
            for marker in (b"placeholder", b"changeme", b"change-me")
        )
    )
