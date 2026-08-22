from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import os
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt
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


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return "pbkdf2$%s$%s" % (
        base64.b64encode(salt).decode("utf-8"),
        base64.b64encode(digest).decode("utf-8"),
    )


def verify_password(password: str, password_hash: str) -> bool:
    try:
        scheme, salt_b64, digest_b64 = password_hash.split("$", 2)
        if scheme != "pbkdf2":
            return False
        salt = base64.b64decode(salt_b64.encode("utf-8"))
        expected = base64.b64decode(digest_b64.encode("utf-8"))
    except Exception:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return hmac.compare_digest(actual, expected)


def create_access_token(user_id: str, username: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


security = HTTPBearer()


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
        payload = jwt.decode(
            credentials.credentials, settings.jwt_secret, algorithms=["HS256"]
        )
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
        payload = jwt.decode(
            credentials.credentials, settings.jwt_secret, algorithms=["HS256"]
        )
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
    db: AsyncSession = Depends(get_db),
) -> RelayIdentity:
    """Verify proxy mTLS metadata and the node's body-bound Ed25519 signature.

    The monotonic sequence is intentionally not changed here.  The registry
    advances it with the heartbeat metrics in one conditional database update,
    removing the signature-check/update TOCTOU replay window.
    """

    try:
        require_trusted_proxy(request, settings.trusted_mtls_proxy)
        headers = parse_relay_auth_headers(request)
        path_node_id = request.path_params.get("node_id")
        if path_node_id != headers.node_id or headers.sequence > 2**63 - 1:
            raise RelayAuthError(
                "relay_signature_invalid", 401, "relay request signature invalid"
            )
        raw_body = await request.body()
        if len(raw_body) > 65_536:
            raise RelayAuthError(
                "relay_metrics_invalid", 400, "relay metrics invalid"
            )
        registry = RelayRegistry(
            db, enrollment_token_pepper=settings.relay_enrollment_token_pepper
        )
        identity = await registry.identity(
            node_id=headers.node_id,
            certificate_fingerprint=headers.certificate_fingerprint,
        )
        verify_request_signature(
            request=request,
            headers=headers,
            raw_body=raw_body,
            signing_public_key=identity.signing_public_key,
            now=datetime.now(timezone.utc),
            max_clock_skew_seconds=settings.relay_max_clock_skew_seconds,
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
