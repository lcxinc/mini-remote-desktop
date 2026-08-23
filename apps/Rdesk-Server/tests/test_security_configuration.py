from __future__ import annotations

import base64
import hashlib
import logging
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient
from jose import jwt
from pydantic import SecretStr
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.api.v1.auth import router as auth_router
from app.core.config import Settings, settings
from app.core.security import (
    create_access_token,
    get_current_user_optional,
    hash_password,
    verify_password,
)
from app.db.init_db import seed_initial_data
from app.db.session import Base, get_db
from app.models.user import User
from test_relay_node_api import AsyncSessionShim


class ScalarSession:
    def __init__(self, user: User) -> None:
        self.user = user
        self.commits = 0

    async def scalar(self, _: object) -> User:
        return self.user

    async def commit(self) -> None:
        self.commits += 1


def _user() -> User:
    return User(
        id="secure-admin-id",
        username="secure-admin",
        email="secure-admin@example.test",
        password_hash=hash_password("correct horse battery staple"),
        role="admin",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def test_production_jwt_default_is_empty_and_cannot_issue_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    default = Settings.model_fields["jwt_secret"].default
    default_value = (
        default.get_secret_value() if isinstance(default, SecretStr) else default
    )
    assert default_value == ""

    monkeypatch.setitem(settings.__dict__, "jwt_secret", SecretStr(""))
    with pytest.raises(HTTPException) as unavailable:
        create_access_token("user-id", "user", "user")
    assert unavailable.value.status_code == 503
    assert unavailable.value.detail["code"] == "authentication_unavailable"


@pytest.mark.anyio
async def test_known_default_cannot_forge_an_accepted_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    weak = "change_me_for_production"
    monkeypatch.setitem(settings.__dict__, "jwt_secret", weak)
    now = datetime.now(UTC)
    forged = jwt.encode(
        {
            "sub": "secure-admin-id",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
        },
        weak,
        algorithm="HS256",
    )
    result = await get_current_user_optional(
        credentials=HTTPAuthorizationCredentials(
            scheme="Bearer", credentials=forged
        ),
        db=ScalarSession(_user()),  # type: ignore[arg-type]
    )
    assert result is None


def test_login_returns_stable_unavailable_when_jwt_secret_is_weak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(settings.__dict__, "jwt_secret", "too-short")
    user = _user()

    async def override_db():
        yield ScalarSession(user)

    app = FastAPI()
    app.include_router(auth_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={
                "username": user.username,
                "password": "correct horse battery staple",
            },
        )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "authentication_unavailable"


@pytest.mark.parametrize("weak_secret", ["A" * 64, "ABCDEFGH" * 4])
def test_long_but_low_entropy_jwt_secret_is_rejected(
    monkeypatch: pytest.MonkeyPatch, weak_secret: str
) -> None:
    monkeypatch.setitem(settings.__dict__, "jwt_secret", weak_secret)
    with pytest.raises(HTTPException) as unavailable:
        create_access_token("user-id", "user", "user")
    assert unavailable.value.status_code == 503
    assert unavailable.value.detail["code"] == "authentication_unavailable"


@pytest.mark.anyio
async def test_strong_explicit_jwt_secret_still_roundtrips(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    jwt_secret = "vY7!qP2@kL9#sX4$mR8%tN6&wC3*eH5-zB1+uD0="
    monkeypatch.setitem(settings.__dict__, "jwt_secret", SecretStr(jwt_secret))
    monkeypatch.setitem(settings.__dict__, "jwt_issuer", "https://auth.rdesk.test")
    monkeypatch.setitem(settings.__dict__, "jwt_audience", "rdesk-api")
    caplog.set_level(logging.DEBUG)
    user = _user()
    token = create_access_token(user.id, user.username, user.role)
    accepted = await get_current_user_optional(
        credentials=HTTPAuthorizationCredentials(
            scheme="Bearer", credentials=token
        ),
        db=ScalarSession(user),  # type: ignore[arg-type]
    )
    assert accepted is user
    assert jwt_secret not in caplog.text
    assert jwt_secret not in repr(settings)


def test_sensitive_relay_and_ca_settings_are_secret_types_and_redacted() -> None:
    configured = Settings(
        relay_ca_private_key_pem="private-ca-key",
        relay_ca_private_key_password="private-ca-password",
        relay_enrollment_token_pepper="11" * 32,
        device_enrollment_token_pepper="22" * 32,
    )
    for name, secret in {
        "relay_ca_private_key_pem": "private-ca-key",
        "relay_ca_private_key_password": "private-ca-password",
        "relay_enrollment_token_pepper": "11" * 32,
        "device_enrollment_token_pepper": "22" * 32,
    }.items():
        value = getattr(configured, name)
        assert isinstance(value, SecretStr)
        assert secret not in repr(configured)


def test_env_example_documents_security_controls_without_shipping_secrets() -> None:
    example = Path(__file__).parents[1] / ".env.example"
    content = example.read_text(encoding="utf-8")
    configured = {
        key: value
        for line in content.splitlines()
        if line and not line.startswith("#") and "=" in line
        for key, value in (line.split("=", 1),)
    }
    for name in (
        "RDESK_DB_URL",
        "RDESK_JWT_SECRET",
        "RDESK_BOOTSTRAP_ADMIN_PASSWORD",
        "RDESK_TURN_AUTH_SECRET",
        "RDESK_DEVICE_ENROLLMENT_TOKEN_PEPPER",
        "RDESK_RELAY_ENROLLMENT_TOKEN_PEPPER",
        "RDESK_RELAY_CA_PRIVATE_KEY_PEM",
        "RDESK_RELAY_CA_PRIVATE_KEY_PASSWORD",
    ):
        assert configured[name] == ""
    assert {
        "RDESK_JWT_ISSUER",
        "RDESK_JWT_AUDIENCE",
        "RDESK_JWT_FUTURE_IAT_SKEW_SECONDS",
        "RDESK_PASSWORD_PBKDF2_ITERATIONS",
        "RDESK_DEVICE_ENROLLMENT_TTL_SECONDS",
        "RDESK_TRUSTED_MTLS_PROXY",
        "RDESK_RELAY_MAX_CLOCK_SKEW_SECONDS",
        "RDESK_RELAY_CERTIFICATE_VALIDITY_SECONDS",
        "RDESK_RELAY_CERTIFICATE_RENEW_BEFORE_SECONDS",
        "RDESK_RELAY_ENROLLMENT_RECEIPT_TTL_SECONDS",
        "RDESK_RELAY_PREVIOUS_AUTH_GRACE_SECONDS",
        "RDESK_RELAY_RENEWAL_RECORD_RETENTION_SECONDS",
    }.issubset(configured)
    assert "519223" not in content
    assert "change_me_for_production" not in content


def test_jwt_issuance_requires_explicit_issuer_and_audience(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        settings.__dict__,
        "jwt_secret",
        SecretStr("vY7!qP2@kL9#sX4$mR8%tN6&wC3*eH5-zB1+uD0="),
    )
    monkeypatch.setitem(settings.__dict__, "jwt_issuer", "")
    monkeypatch.setitem(settings.__dict__, "jwt_audience", "")
    with pytest.raises(HTTPException) as unavailable:
        create_access_token("user-id", "user", "user")
    assert unavailable.value.status_code == 503
    assert unavailable.value.detail["code"] == "authentication_unavailable"


def test_jwt_contains_pinned_context_and_bounded_lifetime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "vY7!qP2@kL9#sX4$mR8%tN6&wC3*eH5-zB1+uD0="
    monkeypatch.setitem(settings.__dict__, "jwt_secret", SecretStr(secret))
    monkeypatch.setitem(settings.__dict__, "jwt_issuer", "https://auth.rdesk.test")
    monkeypatch.setitem(settings.__dict__, "jwt_audience", "rdesk-api")
    monkeypatch.setitem(settings.__dict__, "jwt_expire_minutes", 30)
    monkeypatch.setitem(settings.__dict__, "jwt_max_lifetime_minutes", 60)
    token = create_access_token("user-id", "user", "user")
    claims = jwt.get_unverified_claims(token)
    assert claims["iss"] == "https://auth.rdesk.test"
    assert claims["aud"] == "rdesk-api"
    assert set(("sub", "role", "iat", "exp", "iss", "aud")).issubset(claims)
    assert 0 < claims["exp"] - claims["iat"] <= 3600
    assert jwt.get_unverified_header(token)["alg"] == "HS256"


@pytest.mark.parametrize(
    "mutation",
    ["missing_exp", "wrong_issuer", "wrong_audience", "future_iat", "long_lived"],
)
@pytest.mark.anyio
async def test_jwt_rejects_missing_or_wrong_context_and_unbounded_time(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    secret = "vY7!qP2@kL9#sX4$mR8%tN6&wC3*eH5-zB1+uD0="
    issuer = "https://auth.rdesk.test"
    audience = "rdesk-api"
    monkeypatch.setitem(settings.__dict__, "jwt_secret", SecretStr(secret))
    monkeypatch.setitem(settings.__dict__, "jwt_issuer", issuer)
    monkeypatch.setitem(settings.__dict__, "jwt_audience", audience)
    monkeypatch.setitem(settings.__dict__, "jwt_max_lifetime_minutes", 60)
    now = datetime.now(UTC)
    claims = {
        "sub": "secure-admin-id",
        "role": "admin",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "iss": issuer,
        "aud": audience,
    }
    user = _user()
    valid = jwt.encode(claims, secret, algorithm="HS256")
    valid_result = await get_current_user_optional(
        credentials=HTTPAuthorizationCredentials(
            scheme="Bearer", credentials=valid
        ),
        db=ScalarSession(user),  # type: ignore[arg-type]
    )
    assert valid_result is user
    if mutation == "missing_exp":
        del claims["exp"]
    elif mutation == "wrong_issuer":
        claims["iss"] = "https://other.test"
    elif mutation == "wrong_audience":
        claims["aud"] = "other-api"
    elif mutation == "future_iat":
        claims["iat"] = int((now + timedelta(minutes=5)).timestamp())
        claims["exp"] = int((now + timedelta(minutes=10)).timestamp())
    else:
        claims["exp"] = int((now + timedelta(hours=2)).timestamp())
    forged = jwt.encode(claims, secret, algorithm="HS256")
    accepted = await get_current_user_optional(
        credentials=HTTPAuthorizationCredentials(
            scheme="Bearer", credentials=forged
        ),
        db=ScalarSession(user),  # type: ignore[arg-type]
    )
    assert accepted is None


def test_password_hash_is_versioned_and_uses_production_cost() -> None:
    encoded = hash_password("correct horse battery staple")
    scheme, version, iterations, salt, digest = encoded.split("$", 4)
    assert (scheme, version) == ("pbkdf2_sha256", "v2")
    assert int(iterations) >= 600_000
    assert base64.b64decode(salt, validate=True)
    assert base64.b64decode(digest, validate=True)
    assert verify_password("correct horse battery staple", encoded)


def _legacy_password_hash(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, 100_000
    )
    return "pbkdf2$%s$%s" % (
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    )


def test_successful_legacy_password_login_rehashes_before_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password = "correct horse battery staple"
    user = _user()
    user.password_hash = _legacy_password_hash(password)
    session = ScalarSession(user)
    secret = "vY7!qP2@kL9#sX4$mR8%tN6&wC3*eH5-zB1+uD0="
    monkeypatch.setitem(settings.__dict__, "jwt_secret", SecretStr(secret))
    monkeypatch.setitem(settings.__dict__, "jwt_issuer", "https://auth.rdesk.test")
    monkeypatch.setitem(settings.__dict__, "jwt_audience", "rdesk-api")

    async def override_db():
        yield session

    app = FastAPI()
    app.include_router(auth_router, prefix="/api/v1")
    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"username": user.username, "password": password},
        )
    assert response.status_code == 200, response.text
    assert user.password_hash.startswith("pbkdf2_sha256$v2$")
    assert session.commits == 1


@pytest.fixture
def bootstrap_db() -> tuple[AsyncSessionShim, Session, object]:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = Session(engine, expire_on_commit=False)
    yield AsyncSessionShim(session), session, engine
    session.close()
    engine.dispose()


@pytest.mark.anyio
async def test_admin_bootstrap_is_disabled_by_default(
    bootstrap_db: tuple[AsyncSessionShim, Session, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async_session, session, _ = bootstrap_db
    monkeypatch.setitem(settings.__dict__, "bootstrap_admin_enabled", False)
    await seed_initial_data(async_session)  # type: ignore[arg-type]
    assert session.scalar(select(User)) is None


@pytest.mark.parametrize("weak_password", ["weak-password", "Aa1!" * 5])
@pytest.mark.anyio
async def test_admin_bootstrap_requires_all_high_entropy_inputs(
    bootstrap_db: tuple[AsyncSessionShim, Session, object],
    monkeypatch: pytest.MonkeyPatch,
    weak_password: str,
) -> None:
    async_session, session, _ = bootstrap_db
    monkeypatch.setitem(settings.__dict__, "bootstrap_admin_enabled", True)
    monkeypatch.setitem(settings.__dict__, "bootstrap_admin_username", "bootstrap")
    monkeypatch.setitem(
        settings.__dict__, "bootstrap_admin_email", "bootstrap@example.test"
    )
    monkeypatch.setitem(
        settings.__dict__, "bootstrap_admin_password", SecretStr(weak_password)
    )
    await seed_initial_data(async_session)  # type: ignore[arg-type]
    assert session.scalar(select(User)) is None


@pytest.mark.anyio
async def test_explicit_admin_bootstrap_hashes_secret_without_logging_it(
    bootstrap_db: tuple[AsyncSessionShim, Session, object],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async_session, session, _ = bootstrap_db
    bootstrap_secret = "N7!fQ2@vL9#sX4$kR8%pT6&w"
    monkeypatch.setitem(settings.__dict__, "bootstrap_admin_enabled", True)
    monkeypatch.setitem(settings.__dict__, "bootstrap_admin_username", "bootstrap")
    monkeypatch.setitem(
        settings.__dict__, "bootstrap_admin_email", "bootstrap@example.test"
    )
    monkeypatch.setitem(
        settings.__dict__, "bootstrap_admin_password", SecretStr(bootstrap_secret)
    )
    caplog.set_level(logging.DEBUG)
    await seed_initial_data(async_session)  # type: ignore[arg-type]
    admin = session.scalar(select(User))
    assert admin is not None
    assert admin.role == "admin"
    assert bootstrap_secret not in admin.password_hash
    assert verify_password(bootstrap_secret, admin.password_hash)
    assert bootstrap_secret not in caplog.text
    assert bootstrap_secret not in repr(settings)
