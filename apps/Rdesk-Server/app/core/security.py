from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import os
from typing import Annotated, Optional

from fastapi import Depends, Header, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db
from app.models.user import User
from app.services.relay_node_auth import (
    RelayAuthError,
    parse_relay_auth_headers,
    require_trusted_proxy,
    verify_request_signature,
)
from app.services.relay_registry import (
    RelayIdentity,
    RelayRegistry,
    RelayRegistryError,
)

_PASSWORD_SCHEME = "pbkdf2_sha256"
_PASSWORD_VERSION = "v2"
_PASSWORD_MIN_ITERATIONS = 600_000
_PASSWORD_MAX_VERIFY_ITERATIONS = 2_000_000
_LEGACY_PASSWORD_ITERATIONS = 100_000


def hash_password(password: str) -> str:
    iterations = settings.password_pbkdf2_iterations
    if not isinstance(iterations, int) or not (
        _PASSWORD_MIN_ITERATIONS <= iterations <= _PASSWORD_MAX_VERIFY_ITERATIONS
    ):
        raise ValueError("password hashing configuration is unavailable")
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return "%s$%s$%d$%s$%s" % (
        _PASSWORD_SCHEME,
        _PASSWORD_VERSION,
        iterations,
        base64.b64encode(salt).decode("utf-8"),
        base64.b64encode(digest).decode("utf-8"),
    )


def verify_password(password: str, password_hash: str) -> bool:
    try:
        parts = password_hash.split("$")
        if len(parts) == 3 and parts[0] == "pbkdf2":
            iterations = _LEGACY_PASSWORD_ITERATIONS
            salt_b64, digest_b64 = parts[1:]
        elif (
            len(parts) == 5
            and parts[0] == _PASSWORD_SCHEME
            and parts[1] == _PASSWORD_VERSION
        ):
            iterations = int(parts[2])
            salt_b64, digest_b64 = parts[3:]
        else:
            return False
        if not 1 <= iterations <= _PASSWORD_MAX_VERIFY_ITERATIONS:
            return False
        salt = base64.b64decode(salt_b64.encode("ascii"), validate=True)
        expected = base64.b64decode(digest_b64.encode("ascii"), validate=True)
        if not 8 <= len(salt) <= 64 or len(expected) != 32:
            return False
    except (ValueError, TypeError, UnicodeEncodeError):
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return hmac.compare_digest(actual, expected)


def password_needs_rehash(password_hash: str) -> bool:
    try:
        scheme, version, iterations, _, _ = password_hash.split("$", 4)
        return (
            scheme != _PASSWORD_SCHEME
            or version != _PASSWORD_VERSION
            or int(iterations) != settings.password_pbkdf2_iterations
        )
    except (ValueError, TypeError):
        return True


def create_access_token(user_id: str, username: str, role: str) -> str:
    configured = _configured_jwt()
    if configured is None:
        raise _relay_http_exception(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "authentication_unavailable",
            "authentication service is not configured",
        )
    secret, issuer, audience, max_lifetime_seconds = configured
    configured_minutes = settings.jwt_expire_minutes
    if not isinstance(configured_minutes, int) or isinstance(configured_minutes, bool):
        configured_minutes = 0
    lifetime_seconds = configured_minutes * 60
    if not 0 < lifetime_seconds <= max_lifetime_seconds:
        raise _relay_http_exception(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "authentication_unavailable",
            "authentication service is not configured",
        )
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=configured_minutes)
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "iss": issuer,
        "aud": audience,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


security = HTTPBearer()
trusted_mtls_proxy_scheme = APIKeyHeader(
    name="X-Rdesk-Client-TLS",
    scheme_name="TrustedMTLSProxy",
    description=(
        "Proxy-only marker asserted by a configured trusted mTLS terminator; "
        "clients must never supply or be trusted for this value directly."
    ),
    auto_error=False,
)
relay_ed25519_scheme = APIKeyHeader(
    name="X-Relay-Signature",
    scheme_name="RelayEd25519",
    description=(
        "Base64 Ed25519 signature over the MRD_RELAY_REQUEST_V1 canonical request."
    ),
    auto_error=False,
)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        configured = _configured_jwt()
        if configured is None:
            raise credentials_exception
        payload = _decode_access_token(credentials.credentials, configured)
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except jwt.JWTError:
        raise credentials_exception

    user = await db.scalar(select(User).where(User.id == user_id))
    if user is None:
        raise credentials_exception

    return user


async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    if not credentials:
        return None

    try:
        configured = _configured_jwt()
        if configured is None:
            return None
        payload = _decode_access_token(credentials.credentials, configured)
        user_id: str = payload.get("sub")
        if user_id is None:
            return None
    except jwt.JWTError:
        return None

    user = await db.scalar(select(User).where(User.id == user_id))
    return user


async def require_admin(
    current_user: Optional[User] = Depends(get_current_user_optional),
) -> User:
    """Authorize relay administration through the existing JWT/user role path."""

    if current_user is None or current_user.role != "admin":
        raise _relay_http_exception(
            status.HTTP_403_FORBIDDEN,
            "relay_admin_required",
            "relay administrator role required",
        )
    return current_user


async def get_verified_relay_node(
    request: Request,
    x_rdesk_client_certificate: Annotated[
        str | None,
        Header(
            alias="X-Rdesk-Client-Cert-Sha256",
            description="Canonical SHA-256 client-certificate fingerprint set by the trusted proxy.",
        ),
    ] = None,
    x_relay_node_id: Annotated[
        str | None,
        Header(
            alias="X-Relay-Node-Id",
            description="Relay node ID; it must exactly match the route node_id.",
        ),
    ] = None,
    x_relay_signature: Annotated[
        str | None,
        Header(
            alias="X-Relay-Signature",
            description="Bounded canonical Base64 Ed25519 request signature.",
        ),
    ] = None,
    x_relay_timestamp: Annotated[
        str | None,
        Header(
            alias="X-Relay-Timestamp",
            description="Fresh Unix timestamp in decimal seconds.",
        ),
    ] = None,
    x_relay_sequence: Annotated[
        str | None,
        Header(
            alias="X-Relay-Sequence",
            description="Strictly increasing unsigned heartbeat sequence.",
        ),
    ] = None,
    _trusted_proxy_marker: Annotated[
        str | None, Security(trusted_mtls_proxy_scheme)
    ] = None,
    _relay_signature_marker: Annotated[
        str | None, Security(relay_ed25519_scheme)
    ] = None,
    db: AsyncSession = Depends(get_db),
) -> RelayIdentity:
    """Verify proxy mTLS metadata and the node's body-bound Ed25519 signature.

    The monotonic sequence is intentionally not changed here.  The registry
    advances it with the heartbeat metrics in one conditional database update,
    removing the signature-check/update TOCTOU replay window.
    """

    # Header values are declared explicitly for OpenAPI, while the raw Request
    # remains the single canonical parsing source so duplicate/bounds handling
    # cannot diverge between documentation and cryptographic verification.
    _ = (
        x_rdesk_client_certificate,
        x_relay_node_id,
        x_relay_signature,
        x_relay_timestamp,
        x_relay_sequence,
        _trusted_proxy_marker,
        _relay_signature_marker,
    )
    return await _verify_relay_request(request, db, allow_previous=False)


async def get_verified_relay_renewal_node(
    request: Request,
    _trusted_proxy_marker: Annotated[
        str | None, Security(trusted_mtls_proxy_scheme)
    ] = None,
    _relay_signature_marker: Annotated[
        str | None, Security(relay_ed25519_scheme)
    ] = None,
    db: AsyncSession = Depends(get_db),
) -> RelayIdentity:
    _ = (_trusted_proxy_marker, _relay_signature_marker)
    return await _verify_relay_request(request, db, allow_previous=True)


async def _verify_relay_request(
    request: Request, db: AsyncSession, *, allow_previous: bool
) -> RelayIdentity:
    try:
        require_trusted_proxy(request, settings.trusted_mtls_proxy)
        headers = parse_relay_auth_headers(request)
        path_node_id = request.path_params.get("node_id")
        if path_node_id != headers.node_id or headers.sequence > 2**63 - 1:
            raise RelayAuthError(
                "relay_signature_invalid", 401, "relay request signature invalid"
            )
        raw_body = getattr(request.state, "relay_raw_body", None)
        if raw_body is None:
            raw_body = await request.body()
        if len(raw_body) > 65_536:
            raise RelayAuthError(
                "relay_request_too_large", 413, "relay request too large"
            )
        registry = RelayRegistry(
            db, enrollment_token_pepper=settings.relay_enrollment_token_pepper
        )
        identity = await registry.identity(
            node_id=headers.node_id,
            certificate_fingerprint=headers.certificate_fingerprint,
            allow_previous=allow_previous,
            now=datetime.now(timezone.utc),
        )
        verify_request_signature(
            request=request,
            headers=headers,
            raw_body=raw_body,
            signing_public_key=identity.signing_public_key,
            now=datetime.now(timezone.utc),
            max_clock_skew_seconds=settings.relay_max_clock_skew_seconds,
        )
        if identity.state == "revoked":
            raise RelayRegistryError(
                "relay_node_revoked", 403, "relay node revoked"
            )
        request.state.relay_sequence = headers.sequence
        return identity
    except (RelayAuthError, RelayRegistryError) as error:
        raise _relay_http_exception(error.status_code, error.code, str(error)) from None


def _relay_http_exception(
    status_code: int, code: str, message: str
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message},
    )


def _configured_jwt_secret() -> str | None:
    configured = settings.jwt_secret
    secret = (
        configured.get_secret_value()
        if isinstance(configured, SecretStr)
        else configured
    )
    if not isinstance(secret, str):
        return None
    encoded = secret.encode("utf-8")
    if len(encoded) < 32 or len(set(secret)) < 16 or secret in {
        "change_me_for_production",
        "change-me",
        "secret",
    }:
        return None
    return secret


def _configured_jwt() -> tuple[str, str, str, int] | None:
    secret = _configured_jwt_secret()
    issuer = settings.jwt_issuer.strip()
    audience = settings.jwt_audience.strip()
    maximum_minutes = settings.jwt_max_lifetime_minutes
    future_skew = settings.jwt_future_iat_skew_seconds
    if (
        secret is None
        or not issuer
        or len(issuer) > 512
        or not audience
        or len(audience) > 256
        or not isinstance(maximum_minutes, int)
        or isinstance(maximum_minutes, bool)
        or not 1 <= maximum_minutes <= 60 * 24
        or not isinstance(future_skew, int)
        or isinstance(future_skew, bool)
        or not 0 <= future_skew <= 300
    ):
        return None
    return secret, issuer, audience, maximum_minutes * 60


def _decode_access_token(
    token: str, configured: tuple[str, str, str, int]
) -> dict[str, object]:
    secret, issuer, audience, max_lifetime_seconds = configured
    payload = jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        issuer=issuer,
        audience=audience,
    )
    required = ("sub", "iat", "exp", "iss", "aud")
    if any(name not in payload for name in required):
        raise jwt.JWTError("required claim missing")
    issued_at = payload["iat"]
    expires_at = payload["exp"]
    if (
        not isinstance(payload["sub"], str)
        or not 1 <= len(payload["sub"]) <= 128
        or not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or expires_at <= issued_at
        or expires_at - issued_at > max_lifetime_seconds
        or issued_at
        > int(datetime.now(timezone.utc).timestamp())
        + settings.jwt_future_iat_skew_seconds
    ):
        raise jwt.JWTError("token time context invalid")
    return payload
