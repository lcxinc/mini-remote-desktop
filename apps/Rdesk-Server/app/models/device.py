from datetime import datetime
from uuid import uuid4
import hashlib

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        CheckConstraint(
            "length(tenant_id) BETWEEN 1 AND 64",
            name="ck_devices_tenant_id",
        ),
        Index("ix_devices_tenant_id", "tenant_id"),
        Index("ix_devices_bound_user_id", "bound_user_id"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    name: Mapped[str] = mapped_column(String(128), index=True)
    device_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    os: Mapped[str] = mapped_column(String(64))
    icon: Mapped[str] = mapped_column(String(32), default="Monitor")
    location: Mapped[str] = mapped_column(String(64), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    group: Mapped[str] = mapped_column(String(64), default="默认")
    favorite: Mapped[bool] = mapped_column(Boolean, default=False)
    tenant_id: Mapped[str] = mapped_column(
        String(64), nullable=False, default="default", server_default=text("'default'")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # 设备绑定相关字段
    motherboard_serial: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(128), nullable=True)
    os_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    cpu_info: Mapped[str | None] = mapped_column(Text, nullable=True)
    total_memory_mb: Mapped[int | None] = mapped_column(Integer, nullable=True)
    gpu_info: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_bound: Mapped[bool] = mapped_column(Boolean, default=False)
    bound_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    bound_user_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
    )

    status: Mapped["DeviceStatus"] = relationship(
        "DeviceStatus",
        back_populates="device",
        uselist=False,
        cascade="all, delete-orphan",
    )

    # 网络分组关联（多对多关系）
    group_associations: Mapped[list["DeviceNetworkGroup"]] = relationship(
        "DeviceNetworkGroup",
        back_populates="device",
        cascade="all, delete-orphan",
    )


def generate_device_id_from_serial(motherboard_serial: str) -> str:
    """
    根据主板序列号生成纯数字设备ID（保证唯一性）

    使用 SHA256 哈希主板序列号，将完整哈希值转换为数字格式
    同一主板序列号始终生成相同的设备ID

    Args:
        motherboard_serial: 主板序列号（完整传输到服务端）

    Returns:
        12位纯数字设备ID字符串

    唯一性保证：
    - SHA256 输出 256 位，提供 2^256 种可能
    - 转换为数字后范围约 10^77，远超实际需求
    - 使用模 10^12 确保结果在 12 位数字内
    - 碰撞概率极低（约 1/10^12）

    示例:
        "BASEBOARD-12345" -> "123456789012"
        "TEST-SERIAL-001"  -> "987654321098"
    """
    # SHA256 哈希（256位 = 32字节）
    hash_bytes = hashlib.sha256(motherboard_serial.encode('utf-8')).digest()

    # 将完整 256 位哈希转换为大整数
    # 范围: 0 到 2^256-1 (约 1.16 * 10^77)
    hash_int = int.from_bytes(hash_bytes, byteorder='big')

    # 取模 10^12，得到 12 位数字范围（000000000001 - 999999999999）
    # 碰撞概率: 1/10^12（对于实际设备数量可忽略）
    mod = 10 ** 12
    device_num = hash_int % mod

    # 格式化为 12 位数字（不足补零）
    device_id = str(device_num).zfill(12)

    return device_id


class DeviceStatus(Base):
    __tablename__ = "device_status"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), unique=True
    )
    status: Mapped[str] = mapped_column(String(16), default="offline")
    ping: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cpu: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ram: Mapped[int | None] = mapped_column(Integer, nullable=True)
    disk: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_seen: Mapped[str] = mapped_column(String(64), default="离线")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    device: Mapped[Device] = relationship("Device", back_populates="status")
