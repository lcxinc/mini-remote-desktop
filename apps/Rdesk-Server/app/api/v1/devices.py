import re
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.security import (
    create_access_token,
    get_current_device,
    get_current_device_optional,
    get_current_user,
    get_current_user_optional,
)
from app.db.session import get_db
from app.models.device import Device, generate_device_id_from_serial
from app.models.user import User
from app.schemas.device import (
    DeviceAutoBindRequest,
    DeviceAutoBindResponse,
    DeviceBindRequest,
    DeviceBindingStatus,
    DeviceOut,
    DeviceRegisterRequest,
    DeviceRegisterResponse,
    DeviceRenameRequest,
    DeviceRenameResponse,
    DeviceUnbindRequest,
)

router = APIRouter(prefix="/devices", tags=["devices"])
_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_DUAL_SECURITY = ({"HTTPBearer": [], "DeviceBearer": []},)


def _to_out(device: Device) -> DeviceOut:
    status = device.status
    return DeviceOut(
        id=device.id,
        name=device.name,
        device_id=device.device_id,
        os=device.os,
        icon=device.icon,
        status=status.status if status else "offline",
        location=device.location,
        ping=status.ping if status else None,
        last_seen=status.last_seen if status else "离线",
        cpu=status.cpu if status else None,
        ram=status.ram if status else None,
        disk=status.disk if status else None,
        ip=device.ip,
        group=device.group,
        favorite=device.favorite,
        is_bound=device.is_bound,
    )


@router.post("/register", response_model=DeviceRegisterResponse)
async def register_device(
    payload: DeviceRegisterRequest,
    current_user: User | None = Depends(get_current_user_optional),
    current_device: Device | None = Depends(get_current_device_optional),
    db: AsyncSession = Depends(get_db),
) -> DeviceRegisterResponse:
    """
    设备注册

    根据主板序列号生成设备ID。如果设备已存在，返回现有设备信息。
    如果设备不存在，创建新设备。
    """
    # 检查设备是否已存在
    existing = await db.scalar(
        select(Device)
        .where(Device.motherboard_serial == payload.motherboard_serial)
        .with_for_update()
        .execution_options(populate_existing=True)
    )

    # 根据 OS 版本确定 OS 类型
    os_type = payload.os_version.split()[0] if payload.os_version else "Unknown"

    if existing:
        if current_user is None or current_user.role != "admin":
            if current_device is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Device proof required",
                )
            if current_device.id != existing.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Device proof does not match",
                )
        # 设备已存在，更新信息
        if payload.hostname:
            existing.hostname = payload.hostname
        if payload.os_version:
            existing.os_version = payload.os_version
            existing.os = os_type
        if payload.cpu_info:
            existing.cpu_info = payload.cpu_info
        if payload.total_memory_mb:
            existing.total_memory_mb = payload.total_memory_mb
        if payload.gpu_info:
            existing.gpu_info = payload.gpu_info
        if payload.device_name:
            existing.name = payload.device_name

        await db.commit()
        await db.refresh(existing)

        # 生成访问令牌
        access_token = create_access_token(
            existing.device_id, existing.name, "device"
        )

        return DeviceRegisterResponse(
            device_id=existing.device_id,
            device_name=existing.name,
            access_token=access_token,
        )
    else:
        # 新设备，生成设备ID
        device_id = generate_device_id_from_serial(payload.motherboard_serial)

        # 检查 device_id 是否冲突（极小概率）
        id_conflict = await db.scalar(
            select(Device).where(Device.device_id == device_id)
        )
        if id_conflict:
            # 如果冲突，添加随机后缀
            import uuid
            device_id = f"{device_id}-{uuid.uuid4().hex[:4]}"

        device_name = payload.device_name or payload.hostname

        new_device = Device(
            name=device_name,
            device_id=device_id,
            os=os_type,
            os_version=payload.os_version,
            hostname=payload.hostname,
            motherboard_serial=payload.motherboard_serial,
            cpu_info=payload.cpu_info,
            total_memory_mb=payload.total_memory_mb,
            gpu_info=payload.gpu_info,
            is_bound=False,
        )
        db.add(new_device)
        await db.commit()
        await db.refresh(new_device)

        # 生成访问令牌
        access_token = create_access_token(
            new_device.device_id, new_device.name, "device"
        )

        return DeviceRegisterResponse(
            device_id=new_device.device_id,
            device_name=new_device.name,
            access_token=access_token,
        )


@router.get("/check/{motherboard_serial}")
async def check_device_registration(
    motherboard_serial: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    检查设备是否已注册
    """
    device = await db.scalar(
        select(Device).where(Device.motherboard_serial == motherboard_serial)
    )

    if device:
        return {
            "registered": True,
            "device_id": device.device_id,
            "device_name": device.name,
            "is_bound": device.is_bound,
        }
    else:
        return {"registered": False}


@router.post("/bind", openapi_extra={"security": _DUAL_SECURITY})
async def bind_device(
    payload: DeviceBindRequest,
    current_user: User = Depends(get_current_user),
    current_device: Device = Depends(get_current_device),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    绑定设备到用户

    将设备与用户账户绑定，绑定后只有该用户可以访问此设备。
    """
    _require_matching_device(current_device, payload.device_id)
    device, _ = await bind_device_owner(
        db,
        device_id=payload.device_id,
        current_user=current_user,
        now=datetime.now(UTC),
    )
    await _commit(db)

    return {
        "message": "Device bound successfully",
        "device_id": device.device_id,
        "user_id": current_user.id,
    }


@router.get("", response_model=list[DeviceOut])
async def list_devices(
    q: str | None = Query(default=None),
    status: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
) -> list[DeviceOut]:
    stmt: Select[tuple[Device]] = select(Device).options(selectinload(Device.status))
    if q:
        stmt = stmt.where(Device.name.ilike(f"%{q}%"))
    rows = (await db.scalars(stmt)).all()
    result = [_to_out(item) for item in rows]
    if status:
        result = [item for item in result if item.status == status]
    return result


@router.get("/{device_id}", response_model=DeviceOut)
async def get_device(device_id: str, db: AsyncSession = Depends(get_db)) -> DeviceOut:
    stmt = (
        select(Device)
        .where(Device.id == device_id)
        .options(selectinload(Device.status))
    )
    device = await db.scalar(stmt)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return _to_out(device)


@router.post(
    "/auto-bind",
    response_model=DeviceAutoBindResponse,
    openapi_extra={"security": _DUAL_SECURITY},
)
async def auto_bind_device(
    payload: DeviceAutoBindRequest,
    current_user: User = Depends(get_current_user),
    current_device: Device = Depends(get_current_device),
    db: AsyncSession = Depends(get_db),
) -> DeviceAutoBindResponse:
    """
    用户登录时自动绑定设备

    逻辑：
    1. 如果设备未绑定(is_bound=False)：直接绑定当前用户
    2. 如果设备已被其他用户绑定：强制迁移到当前用户
    3. 如果设备已被当前用户绑定：更新绑定时间（续期）

    返回：绑定状态、被踢出的用户信息（如有）
    """
    _require_matching_device(current_device, payload.device_id)
    _, is_new_binding = await bind_device_owner(
        db,
        device_id=payload.device_id,
        current_user=current_user,
        now=datetime.now(UTC),
    )
    await _commit(db)

    return DeviceAutoBindResponse(
        success=True,
        message="Device bound successfully",
        kicked_user=None,
        is_new_binding=is_new_binding,
    )


@router.post("/unbind", openapi_extra={"security": _DUAL_SECURITY})
async def unbind_device(
    payload: DeviceUnbindRequest,
    current_user: User = Depends(get_current_user),
    current_device: Device = Depends(get_current_device),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    用户登出时解除设备绑定

    逻辑：
    1. 验证设备确实绑定到该用户
    2. 解除绑定（is_bound=False, bound_user_id=None, bound_at=None）
    """
    _require_matching_device(current_device, payload.device_id)
    device = await db.scalar(
        select(Device)
        .where(Device.device_id == payload.device_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    if not device.is_bound and device.bound_user_id is None:
        # 设备未绑定，直接返回成功（幂等）
        return {"message": "Device not bound", "success": True}

    if (
        device.bound_user_id != current_user.id
        or device.tenant_id != current_user.tenant_id
    ):
        # 设备绑定到其他用户，不允许解绑
        raise HTTPException(
            status_code=403, detail="Device is bound to a different user"
        )

    # 解除绑定
    device.is_bound = False
    device.bound_user_id = None
    device.bound_at = None

    await _commit(db)

    return {
        "message": "Device unbound successfully",
        "success": True,
    }


async def bind_device_owner(
    db: AsyncSession,
    *,
    device_id: str,
    current_user: object,
    now: datetime,
) -> tuple[Device, bool]:
    user_id = getattr(current_user, "id", None)
    tenant_id = getattr(current_user, "tenant_id", None)
    if (
        not isinstance(user_id, str)
        or not user_id
        or not isinstance(tenant_id, str)
        or _TENANT.fullmatch(tenant_id) is None
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Device ownership denied",
        )
    device = await db.scalar(
        select(Device)
        .where(Device.device_id == device_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    if device.is_bound or device.bound_user_id is not None:
        if (
            not device.is_bound
            or device.bound_user_id != user_id
            or device.tenant_id != tenant_id
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Device ownership conflicts",
            )
        is_new_binding = False
    else:
        device.is_bound = True
        device.bound_user_id = user_id
        device.tenant_id = tenant_id
        is_new_binding = True
    device.bound_at = _naive_utc(now)
    await db.flush()
    return device, is_new_binding


def _require_matching_device(device: Device, requested_device_id: str) -> None:
    if device.device_id != requested_device_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device authentication credentials",
        )


async def _commit(db: AsyncSession) -> None:
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise


def _naive_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


@router.get("/{device_id}/binding-status", response_model=DeviceBindingStatus)
async def get_binding_status(
    device_id: str,
    db: AsyncSession = Depends(get_db),
) -> DeviceBindingStatus:
    """
    获取设备当前绑定状态

    返回：是否已绑定、绑定的用户信息、绑定时间
    """
    device = await db.scalar(
        select(Device).where(Device.device_id == device_id)
    )

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    bound_username = None
    if device.is_bound and device.bound_user_id:
        # 获取用户名（需要导入 User 模型）
        from app.models.user import User
        user = await db.scalar(
            select(User).where(User.id == device.bound_user_id)
        )
        bound_username = user.username if user else None

    return DeviceBindingStatus(
        is_bound=device.is_bound,
        bound_user_id=device.bound_user_id,
        bound_username=bound_username,
        bound_at=device.bound_at.isoformat() if device.bound_at else None,
    )


@router.patch("/{device_id}/rename", response_model=DeviceRenameResponse)
async def rename_device(
    device_id: str,
    payload: DeviceRenameRequest,
    current_user = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> DeviceRenameResponse:
    """
    重命名设备

    需要用户登录认证。用户只能重命名自己绑定的设备。
    """
    device = await db.scalar(
        select(Device).where(Device.device_id == device_id)
    )

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # 检查设备是否绑定到当前用户
    if device.is_bound and device.bound_user_id != current_user.id:
        raise HTTPException(
            status_code=403, detail="You can only rename devices bound to your account"
        )

    # 更新设备名称
    device.name = payload.name
    await db.commit()

    return DeviceRenameResponse(
        success=True,
        message="Device renamed successfully",
        device_id=device.device_id,
        new_name=device.name,
    )
