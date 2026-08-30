from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.api.v1.realtime import router
from app.core.security import get_current_user_optional
from app.models.user import User
from app.services.realtime_manager import RealtimeSidecarManager


class FakeProcess:
    def __init__(self, pid: int = 4242) -> None:
        self.pid = pid
        self.alive = True

    def poll(self):
        return None if self.alive else 0

    def terminate(self):
        self.alive = False

    def wait(self, timeout=None):
        self.alive = False
        return 0

    def kill(self):
        self.alive = False


def build_manager() -> RealtimeSidecarManager:
    def spawn(_command: list[str], _cwd: Path):
        return FakeProcess()

    manager = RealtimeSidecarManager(
        health_url="http://127.0.0.1:9532/health",
        command=["cargo", "run"],
        workdir=".",
        spawner=spawn,
    )

    manager.status = lambda: type(  # type: ignore[method-assign]
        "Status",
        (),
        {
            "running": bool(manager._process and manager._process.poll() is None),
            "reachable": True,
            "status": "ok",
            "pid": 4242 if manager._process else None,
        },
    )()
    return manager


def _user(user_id: str, role: str) -> User:
    return User(
        id=user_id,
        username=user_id,
        email=f"{user_id}@example.test",
        password_hash="unused",
        role=role,
        tenant_id="tenant-a",
    )


def build_test_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.realtime_manager = build_manager()
        yield

    ordinary_user = _user("ordinary-user", "user")
    administrator = _user("administrator", "admin")

    async def override_user(request: Request) -> User | None:
        authorization = request.headers.get("Authorization")
        if authorization == "Bearer user-token":
            return ordinary_user
        if authorization == "Bearer admin-token":
            return administrator
        return None

    app = FastAPI(lifespan=lifespan)
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_current_user_optional] = override_user
    return app


def test_realtime_routes_require_authentication_and_admin_for_mutations() -> None:
    with TestClient(build_test_app()) as client:
        paths = (
            ("GET", "/api/v1/realtime/status"),
            ("POST", "/api/v1/realtime/start"),
            ("POST", "/api/v1/realtime/stop"),
            ("POST", "/api/v1/realtime/restart"),
        )
        for method, path in paths:
            anonymous = client.request(method, path)
            assert anonymous.status_code == 401

        user_headers = {"Authorization": "Bearer user-token"}
        status = client.get("/api/v1/realtime/status", headers=user_headers)
        assert status.status_code == 200
        for path in ("start", "stop", "restart"):
            forbidden = client.post(f"/api/v1/realtime/{path}", headers=user_headers)
            assert forbidden.status_code == 403


def test_realtime_admin_start_stop_restart_roundtrip() -> None:
    admin_headers = {"Authorization": "Bearer admin-token"}
    with TestClient(build_test_app()) as client:
        start = client.post("/api/v1/realtime/start", headers=admin_headers)
        assert start.status_code == 200
        assert start.json()["running"] is True

        status = client.get("/api/v1/realtime/status", headers=admin_headers)
        assert status.status_code == 200
        assert status.json()["reachable"] is True

        restart = client.post("/api/v1/realtime/restart", headers=admin_headers)
        assert restart.status_code == 200
        assert restart.json()["running"] is True

        stop = client.post("/api/v1/realtime/stop", headers=admin_headers)
        assert stop.status_code == 200
        assert stop.json()["running"] is False
