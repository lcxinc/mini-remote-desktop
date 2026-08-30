from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.security import get_current_user_optional
from app.models.user import User
from app.services.realtime_manager import RealtimeSidecarManager

router = APIRouter(prefix="/realtime", tags=["realtime"])


def _manager(request: Request) -> RealtimeSidecarManager:
    return request.app.state.realtime_manager


async def _require_authenticated_user(
    current_user: User | None = Depends(get_current_user_optional),
) -> User:
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user


async def _require_realtime_admin(
    current_user: User = Depends(_require_authenticated_user),
) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="administrator role required",
        )
    return current_user


@router.get("/status")
async def realtime_status(
    request: Request,
    _current_user: User = Depends(_require_authenticated_user),
) -> dict:
    status = _manager(request).status()
    return {
        "running": status.running,
        "reachable": status.reachable,
        "status": status.status,
        "pid": status.pid,
    }


@router.post("/start")
async def realtime_start(
    request: Request,
    _administrator: User = Depends(_require_realtime_admin),
) -> dict:
    status = _manager(request).start()
    return {
        "running": status.running,
        "reachable": status.reachable,
        "status": status.status,
        "pid": status.pid,
    }


@router.post("/stop")
async def realtime_stop(
    request: Request,
    _administrator: User = Depends(_require_realtime_admin),
) -> dict:
    status = _manager(request).stop()
    return {
        "running": status.running,
        "reachable": status.reachable,
        "status": status.status,
        "pid": status.pid,
    }


@router.post("/restart")
async def realtime_restart(
    request: Request,
    _administrator: User = Depends(_require_realtime_admin),
) -> dict:
    status = _manager(request).restart()
    return {
        "running": status.running,
        "reachable": status.reachable,
        "status": status.status,
        "pid": status.pid,
    }
