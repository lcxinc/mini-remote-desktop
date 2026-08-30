"""网络分组 API 端点

提供网络分组的 CRUD 操作和设备管理功能。
"""

from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.sql.elements import ColumnElement

from app.core.security import get_current_user
from app.db.session import get_db
from app.models.device import Device, DeviceStatus
from app.models.network_group import NetworkGroup
from app.models.device_network_group import DeviceNetworkGroup
from app.models.user import User
from app.schemas.network_group import (
    NetworkGroupCreate,
    NetworkGroupUpdate,
    NetworkGroupOut,
    DeviceInGroupOut,
    AddDevicesRequest,
    SetDeviceEnabledRequest,
)

router = APIRouter(prefix="/network-groups", tags=["network-groups"])


def _owned_bound_device_filters(
    user: User,
) -> tuple[ColumnElement[bool], ColumnElement[bool], ColumnElement[bool]]:
    return (
        Device.tenant_id == user.tenant_id,
        Device.is_bound.is_(True),
        Device.bound_user_id == user.id,
    )


async def _ensure_default_group(db: AsyncSession, user: User) -> NetworkGroup:
    """确保用户有默认网络分组，没有则创建"""
    existing = await db.scalar(
        select(NetworkGroup).where(
            NetworkGroup.user_id == user.id, NetworkGroup.name == "默认网络"
        )
    )
    if existing:
        return existing

    default_group = NetworkGroup(
        id=str(uuid4()),
        user_id=user.id,
        name="默认网络",
        description="新用户自动创建的默认网络分组",
        is_enabled=True,
    )
    db.add(default_group)
    await db.commit()
    await db.refresh(default_group)
    return default_group


def _to_out(
    group: NetworkGroup, device_count: int = 0, online_count: int = 0
) -> NetworkGroupOut:
    """转换为输出格式"""
    return NetworkGroupOut(
        id=group.id,
        user_id=group.user_id,
        name=group.name,
        description=group.description,
        is_enabled=group.is_enabled,
        device_count=device_count,
        online_device_count=online_count,
        created_at=group.created_at,
        updated_at=group.updated_at,
    )


@router.get("", response_model=list[NetworkGroupOut])
async def get_network_groups(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
) -> list[NetworkGroupOut]:
    """获取当前用户的所有网络分组"""
    # 确保有默认分组
    await _ensure_default_group(db, current_user)

    # 获取所有分组
    groups_result = await db.scalars(
        select(NetworkGroup)
        .where(NetworkGroup.user_id == current_user.id)
        .order_by(NetworkGroup.created_at)
    )
    groups = list(groups_result.all())

    # 获取每个分组的设备数和在线数
    result = []
    for group in groups:
        # 统计设备数
        device_count_stmt = (
            select(func.count(DeviceNetworkGroup.id))
            .join(Device, DeviceNetworkGroup.device_id == Device.id)
            .where(
                DeviceNetworkGroup.network_group_id == group.id,
                *_owned_bound_device_filters(current_user),
            )
        )
        device_count = (await db.scalar(device_count_stmt)) or 0

        # 统计在线设备数
        online_count_stmt = (
            select(func.count(DeviceNetworkGroup.id))
            .join(Device, DeviceNetworkGroup.device_id == Device.id)
            .join(DeviceStatus, Device.id == DeviceStatus.device_id)
            .where(
                DeviceNetworkGroup.network_group_id == group.id,
                DeviceNetworkGroup.is_enabled.is_(True),
                DeviceStatus.status == "online",
                *_owned_bound_device_filters(current_user),
            )
        )
        online_count = (await db.scalar(online_count_stmt)) or 0

        result.append(_to_out(group, device_count, online_count))

    return result


@router.post("", response_model=NetworkGroupOut, status_code=201)
async def create_network_group(
    data: NetworkGroupCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
) -> NetworkGroupOut:
    """创建新的网络分组"""
    # 检查名称是否重复
    existing = await db.scalar(
        select(NetworkGroup).where(
            NetworkGroup.user_id == current_user.id, NetworkGroup.name == data.name
        )
    )
    if existing:
        raise HTTPException(status_code=400, detail="分组名称已存在")

    group = NetworkGroup(
        id=str(uuid4()),
        user_id=current_user.id,
        name=data.name,
        description=data.description,
        is_enabled=True,
    )
    db.add(group)
    await db.commit()
    await db.refresh(group)

    return _to_out(group, 0, 0)


@router.get("/{group_id}", response_model=NetworkGroupOut)
async def get_network_group(
    group_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
) -> NetworkGroupOut:
    """获取分组详情"""
    group = await db.scalar(
        select(NetworkGroup).where(
            NetworkGroup.id == group_id, NetworkGroup.user_id == current_user.id
        )
    )
    if not group:
        raise HTTPException(status_code=404, detail="分组不存在")

    # 统计设备数
    device_count_stmt = (
        select(func.count(DeviceNetworkGroup.id))
        .join(Device, DeviceNetworkGroup.device_id == Device.id)
        .where(
            DeviceNetworkGroup.network_group_id == group_id,
            *_owned_bound_device_filters(current_user),
        )
    )
    device_count = (await db.scalar(device_count_stmt)) or 0

    # 统计在线设备数
    online_count_stmt = (
        select(func.count(DeviceNetworkGroup.id))
        .join(Device, DeviceNetworkGroup.device_id == Device.id)
        .join(DeviceStatus, Device.id == DeviceStatus.device_id)
        .where(
            DeviceNetworkGroup.network_group_id == group_id,
            DeviceNetworkGroup.is_enabled.is_(True),
            DeviceStatus.status == "online",
            *_owned_bound_device_filters(current_user),
        )
    )
    online_count = (await db.scalar(online_count_stmt)) or 0

    return _to_out(group, device_count, online_count)


@router.patch("/{group_id}", response_model=NetworkGroupOut)
async def update_network_group(
    group_id: str,
    data: NetworkGroupUpdate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
) -> NetworkGroupOut:
    """更新网络分组信息"""
    group = await db.scalar(
        select(NetworkGroup).where(
            NetworkGroup.id == group_id, NetworkGroup.user_id == current_user.id
        )
    )
    if not group:
        raise HTTPException(status_code=404, detail="分组不存在")

    # 检查是否修改名称与其他分组冲突
    if data.name and data.name != group.name:
        existing = await db.scalar(
            select(NetworkGroup).where(
                NetworkGroup.user_id == current_user.id,
                NetworkGroup.name == data.name,
                NetworkGroup.id != group_id,
            )
        )
        if existing:
            raise HTTPException(status_code=400, detail="分组名称已存在")

    # 更新字段
    if data.name is not None:
        group.name = data.name
    if data.description is not None:
        group.description = data.description
    if data.is_enabled is not None:
        group.is_enabled = data.is_enabled

    group.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(group)

    # 重新统计
    device_count_stmt = (
        select(func.count(DeviceNetworkGroup.id))
        .join(Device, DeviceNetworkGroup.device_id == Device.id)
        .where(
            DeviceNetworkGroup.network_group_id == group_id,
            *_owned_bound_device_filters(current_user),
        )
    )
    device_count = (await db.scalar(device_count_stmt)) or 0

    online_count_stmt = (
        select(func.count(DeviceNetworkGroup.id))
        .join(Device, DeviceNetworkGroup.device_id == Device.id)
        .join(DeviceStatus, Device.id == DeviceStatus.device_id)
        .where(
            DeviceNetworkGroup.network_group_id == group_id,
            DeviceNetworkGroup.is_enabled.is_(True),
            DeviceStatus.status == "online",
            *_owned_bound_device_filters(current_user),
        )
    )
    online_count = (await db.scalar(online_count_stmt)) or 0

    return _to_out(group, device_count, online_count)


@router.delete("/{group_id}", status_code=204)
async def delete_network_group(
    group_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
) -> None:
    """删除网络分组

    默认分组不允许删除
    """
    group = await db.scalar(
        select(NetworkGroup).where(
            NetworkGroup.id == group_id, NetworkGroup.user_id == current_user.id
        )
    )
    if not group:
        raise HTTPException(status_code=404, detail="分组不存在")

    if group.name == "默认网络":
        raise HTTPException(status_code=400, detail="默认分组不能删除")

    # 级联删除关联记录
    await db.execute(
        delete(DeviceNetworkGroup).where(
            DeviceNetworkGroup.network_group_id == group_id
        )
    )
    await db.commit()

    # 删除分组
    await db.delete(group)
    await db.commit()


@router.get("/{group_id}/devices", response_model=list[DeviceInGroupOut])
async def get_group_devices(
    group_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
) -> list[DeviceInGroupOut]:
    """获取分组内的设备列表"""
    # 验证分组归属
    group = await db.scalar(
        select(NetworkGroup).where(
            NetworkGroup.id == group_id, NetworkGroup.user_id == current_user.id
        )
    )
    if not group:
        raise HTTPException(status_code=404, detail="分组不存在")

    # 获取分组内的设备
    associations = await db.scalars(
        select(DeviceNetworkGroup)
        .join(Device, DeviceNetworkGroup.device_id == Device.id)
        .options(selectinload(DeviceNetworkGroup.device).selectinload(Device.status))
        .where(
            DeviceNetworkGroup.network_group_id == group_id,
            *_owned_bound_device_filters(current_user),
        )
    )
    associations_list = list(associations.all())

    result = []
    for assoc in associations_list:
        if assoc.device:
            device = assoc.device
            status = device.status.status if device.status else "offline"
            result.append(
                DeviceInGroupOut(
                    id=assoc.id,
                    device_id=device.device_id,
                    name=device.name,
                    status=status,
                    is_enabled=assoc.is_enabled,
                    ip=device.ip,
                )
            )

    return result


@router.post("/{group_id}/devices", status_code=201)
async def add_devices_to_group(
    group_id: str,
    data: AddDevicesRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
) -> None:
    """添加设备到分组

    支持批量添加，已存在的关联会跳过。
    """
    # 验证分组归属
    group = await db.scalar(
        select(NetworkGroup).where(
            NetworkGroup.id == group_id, NetworkGroup.user_id == current_user.id
        )
    )
    if not group:
        raise HTTPException(status_code=404, detail="分组不存在")

    for device_id_str in sorted(set(data.device_ids)):
        # 检查设备是否存在
        device = await db.scalar(
            select(Device)
            .where(
                Device.device_id == device_id_str,
                *_owned_bound_device_filters(current_user),
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if not device:
            continue

        # 检查是否已存在关联
        existing = await db.scalar(
            select(DeviceNetworkGroup).where(
                DeviceNetworkGroup.network_group_id == group_id,
                DeviceNetworkGroup.device_id == device.id,
            )
        )
        if existing:
            continue

        # 创建关联
        assoc = DeviceNetworkGroup(
            id=str(uuid4()),
            network_group_id=group_id,
            device_id=device.id,
            is_enabled=True,
        )
        db.add(assoc)

    await db.commit()


@router.delete("/{group_id}/devices/{device_id}", status_code=204)
async def remove_device_from_group(
    group_id: str,
    device_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
) -> None:
    """从分组移除设备"""
    # 验证分组归属
    group = await db.scalar(
        select(NetworkGroup).where(
            NetworkGroup.id == group_id, NetworkGroup.user_id == current_user.id
        )
    )
    if not group:
        raise HTTPException(status_code=404, detail="分组不存在")

    # 查找设备
    device = await db.scalar(
        select(Device)
        .where(
            Device.device_id == device_id,
            *_owned_bound_device_filters(current_user),
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if not device:
        raise HTTPException(status_code=404, detail="设备不存在")

    # 删除关联
    await db.execute(
        delete(DeviceNetworkGroup).where(
            DeviceNetworkGroup.network_group_id == group_id,
            DeviceNetworkGroup.device_id == device.id,
        )
    )
    await db.commit()


@router.patch("/{group_id}/devices/{device_id}", status_code=204)
async def set_device_enabled(
    group_id: str,
    device_id: str,
    data: SetDeviceEnabledRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
) -> None:
    """设置设备在分组中的启用状态"""
    # 验证分组归属
    group = await db.scalar(
        select(NetworkGroup).where(
            NetworkGroup.id == group_id, NetworkGroup.user_id == current_user.id
        )
    )
    if not group:
        raise HTTPException(status_code=404, detail="分组不存在")

    # 查找设备
    device = await db.scalar(
        select(Device)
        .where(
            Device.device_id == device_id,
            *_owned_bound_device_filters(current_user),
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if not device:
        raise HTTPException(status_code=404, detail="设备不存在")

    # 查找关联
    assoc = await db.scalar(
        select(DeviceNetworkGroup).where(
            DeviceNetworkGroup.network_group_id == group_id,
            DeviceNetworkGroup.device_id == device.id,
        )
    )
    if not assoc:
        raise HTTPException(status_code=404, detail="设备不在此分组中")

    assoc.is_enabled = data.is_enabled
    await db.commit()
