from __future__ import annotations

from collections.abc import Callable, Coroutine

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_current_device
from app.db.session import get_db
from app.models.device import Device
from app.schemas.session import (
    DeviceSessionCreateIn,
    DeviceSessionId,
    DeviceSessionOut,
    DeviceSessionTransitionIn,
)
from app.services.device_sessions import (
    DeviceSessionError,
    DeviceSessionService,
    device_session_out,
)


class DeviceSessionAPIRoute(APIRoute):
    """Project validation failures without reflecting attacker-controlled input."""

    def get_route_handler(self) -> Callable[..., Coroutine[object, object, object]]:
        original = super().get_route_handler()

        async def stable_validation_handler(request: Request):
            try:
                return await original(request)
            except RequestValidationError:
                return JSONResponse(
                    status_code=400,
                    content={
                        "detail": {
                            "code": "wan_session_invalid",
                            "message": "WAN session request is invalid",
                        }
                    },
                )

        return stable_validation_handler


router = APIRouter(
    prefix="/device-sessions",
    tags=["device-sessions"],
    route_class=DeviceSessionAPIRoute,
)


def _service(db: AsyncSession) -> DeviceSessionService:
    return DeviceSessionService(db)


async def _commit(db: AsyncSession) -> None:
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise


def _raise(error: DeviceSessionError) -> None:
    raise HTTPException(
        status_code=error.status_code,
        detail={"code": error.code, "message": str(error)},
    ) from None


@router.post("", response_model=DeviceSessionOut)
async def create_device_session(
    payload: DeviceSessionCreateIn,
    current_device: Device = Depends(get_current_device),
    db: AsyncSession = Depends(get_db),
) -> DeviceSessionOut:
    try:
        row = await _service(db).create(
            current_device=current_device,
            payload=payload,
        )
        response = device_session_out(row)
        await _commit(db)
        return response
    except DeviceSessionError as error:
        await db.rollback()
        _raise(error)
    except IntegrityError:
        await db.rollback()
        _raise(
            DeviceSessionError(
                "wan_session_conflict", 409, "WAN session state conflicts"
            )
        )


@router.get("/{session_id}", response_model=DeviceSessionOut)
async def inspect_device_session(
    session_id: DeviceSessionId,
    current_device: Device = Depends(get_current_device),
    db: AsyncSession = Depends(get_db),
) -> DeviceSessionOut:
    try:
        row = await _service(db).inspect(
            session_id=session_id,
            current_device=current_device,
        )
        return device_session_out(row)
    except DeviceSessionError as error:
        await db.rollback()
        _raise(error)


async def _transition(
    *,
    session_id: str,
    action: str,
    current_device: Device,
    db: AsyncSession,
) -> DeviceSessionOut:
    try:
        row = await _service(db).transition(
            session_id=session_id,
            current_device=current_device,
            action=action,
        )
        response = device_session_out(row)
        await _commit(db)
        return response
    except DeviceSessionError as error:
        await db.rollback()
        _raise(error)


@router.post("/{session_id}/reject", response_model=DeviceSessionOut)
async def reject_device_session(
    session_id: DeviceSessionId,
    _: DeviceSessionTransitionIn,
    current_device: Device = Depends(get_current_device),
    db: AsyncSession = Depends(get_db),
) -> DeviceSessionOut:
    return await _transition(
        session_id=session_id,
        action="reject",
        current_device=current_device,
        db=db,
    )


@router.post("/{session_id}/close", response_model=DeviceSessionOut)
async def close_device_session(
    session_id: DeviceSessionId,
    _: DeviceSessionTransitionIn,
    current_device: Device = Depends(get_current_device),
    db: AsyncSession = Depends(get_db),
) -> DeviceSessionOut:
    return await _transition(
        session_id=session_id,
        action="close",
        current_device=current_device,
        db=db,
    )


@router.post("/{session_id}/revoke", response_model=DeviceSessionOut)
async def revoke_device_session(
    session_id: DeviceSessionId,
    _: DeviceSessionTransitionIn,
    current_device: Device = Depends(get_current_device),
    db: AsyncSession = Depends(get_db),
) -> DeviceSessionOut:
    return await _transition(
        session_id=session_id,
        action="revoke",
        current_device=current_device,
        db=db,
    )
