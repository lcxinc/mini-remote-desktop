from __future__ import annotations

import base64
import hashlib
import hmac
import re
import time
from dataclasses import dataclass, field as dataclass_field
from typing import Callable, Protocol


SCOPE_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class TurnCredentialExpired(ValueError):
    pass


class TurnCredentialConfigurationError(RuntimeError):
    pass


class RelaySecretDecryptor(Protocol):
    def decrypt(self, ciphertext: bytes, *, associated_data: bytes) -> bytes: ...


@dataclass(frozen=True)
class TurnCredential:
    urls: tuple[str, ...]
    username: str
    credential: str
    expires_at_unix_seconds: int
    ttl_seconds: int
    transport_policy: str = "relay"


@dataclass(frozen=True)
class NodeTurnCredential:
    node_id: str
    urls: tuple[str, ...]
    username: str
    credential: str = dataclass_field(repr=False)
    expires_at_unix_seconds: int


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
        plaintext = self._cipher.decrypt(
            encrypted_secret, associated_data=node_id.encode("utf-8")
        )
        secret = bytearray(plaintext)
        del plaintext
        try:
            if not 16 <= len(secret) <= 512:
                raise TurnCredentialConfigurationError(
                    "relay credential material is unavailable"
                )
            credential = base64.b64encode(
                hmac.new(secret, username.encode("utf-8"), hashlib.sha1).digest()
            ).decode("ascii")
        finally:
            for index in range(len(secret)):
                secret[index] = 0
        return NodeTurnCredential(
            node_id=node_id,
            urls=tuple(urls),
            username=username,
            credential=credential,
            expires_at_unix_seconds=expires_at,
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
