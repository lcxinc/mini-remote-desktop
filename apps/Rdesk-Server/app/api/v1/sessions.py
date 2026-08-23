from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import get_current_user
from app.db.session import get_db
from app.models.user import User
from app.schemas.session import (
    SessionApprovalIn,
    SessionApprovalOut,
    SessionRequestIn,
    SessionRequestOut,
)
from app.services.session_grants import (
    SessionGrantError,
    SessionGrantService,
    configured_session_grant_policy,
)

router = APIRouter(prefix="/sessions", tags=["sessions"])


def _service(db: AsyncSession) -> SessionGrantService:
    return SessionGrantService(
        db,
        policy=configured_session_grant_policy(settings),
        signaling_url=settings.signaling_ws_url,
    )


async def _commit(db: AsyncSession) -> None:
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise


def _raise(error: SessionGrantError) -> None:
    raise HTTPException(
        status_code=error.status_code,
        detail={"code": error.code, "message": str(error)},
    ) from None


@router.post("/request", response_model=SessionRequestOut)
async def request_session(
    payload: SessionRequestIn,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SessionRequestOut:
    try:
        service = _service(db)
        grant = await service.request(
            current_user_id=current_user.id,
            target_device_id=payload.target_device_id,
        )
        await _commit(db)
    except SessionGrantError as error:
        await db.rollback()
        _raise(error)
    return SessionRequestOut(
        request_id=grant.id,
        signaling_url=service.signaling_url,
        room=grant.signaling_room,
        status=grant.status,
    )


@router.post("/{session_id}/approve", response_model=SessionApprovalOut)
async def approve_session(
    session_id: str,
    _: SessionApprovalIn,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SessionApprovalOut:
    try:
        grant = await _service(db).approve(
            session_id=session_id,
            current_user_id=current_user.id,
        )
        await _commit(db)
    except SessionGrantError as error:
        await db.rollback()
        _raise(error)
    return SessionApprovalOut(
        request_id=grant.id,
        status=grant.status,
        grant_expires_at=grant.grant_expires_at,
        policy_revision=grant.policy_revision,
        policy_expires_at=grant.policy_expires_at,
        intended_peer_id=grant.intended_peer_id,
    )
