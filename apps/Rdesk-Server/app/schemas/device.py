from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field
from typing import Optional


class DeviceOut(BaseModel):
    id: str
    name: str
    device_id: str
    os: str
    icon: str
    status: str
    location: str
    ping: int | None
    last_seen: str
    cpu: int | None
    ram: int | None
    disk: int | None
    ip: str
    group: str
    favorite: bool
    is_bound: bool | None = None


class DeviceRegisterRequest(BaseModel):
    """设备注册请求"""
    model_config = ConfigDict(extra="forbid")

    motherboard_serial: str = Field(..., min_length=1, max_length=128, description="主板序列号")
    hostname: str = Field(..., min_length=1, max_length=128, description="主机名")
    os_version: str = Field(..., min_length=1, max_length=256, description="操作系统版本")
    device_name: Optional[str] = Field(None, min_length=1, max_length=128, description="设备显示名称")
    cpu_info: Optional[str] = Field(None, description="CPU 信息")
    total_memory_mb: Optional[int] = Field(None, description="内存总量(MB)")
    gpu_info: Optional[str] = Field(None, description="GPU 信息")


class DeviceRegisterResponse(BaseModel):
    """设备注册响应"""
    device_id: str = Field(..., description="分配的设备ID")
    device_name: str = Field(..., description="设备名称")
    access_token: str = Field(..., description="访问令牌", repr=False)


class DeviceEnrollmentTokenOut(BaseModel):
    enrollment_id: str
    token: str = Field(repr=False)
    expires_at: datetime


class DeviceBindRequest(BaseModel):
    """设备绑定请求"""
    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(..., description="设备ID")


class DeviceAutoBindRequest(BaseModel):
    """设备自动绑定请求（登录时使用）"""
    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(..., description="设备ID")


class DeviceUnbindRequest(BaseModel):
    """设备解绑请求（登出时使用）"""
    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(..., description="设备ID")


class DeviceBindingStatus(BaseModel):
    """设备绑定状态响应"""
    is_bound: bool
    bound_user_id: str | None = None
    bound_username: str | None = None
    bound_at: str | None = None


class DeviceAutoBindResponse(BaseModel):
    """设备自动绑定响应"""
    success: bool
    message: str
    kicked_user: dict | None = None  # 被踢出的用户信息（如有）
    is_new_binding: bool = False  # 是否是新绑定（从其他用户迁移过来）


class DeviceRenameRequest(BaseModel):
    """设备重命名请求"""
    name: str = Field(..., min_length=1, max_length=128, description="新设备名称")


class DeviceRenameResponse(BaseModel):
    """设备重命名响应"""
    success: bool
    message: str
    device_id: str
    new_name: str
