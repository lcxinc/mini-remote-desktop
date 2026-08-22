from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

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

    async def scalar(self, _: object) -> User:
        return self.user


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
