from datetime import datetime
from uuid import uuid4

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
        CheckConstraint(
            "(is_bound = FALSE AND bound_user_id IS NULL) OR "
            "(is_bound = TRUE AND bound_user_id IS NOT NULL)",
            name="ck_devices_bound_owner",
        ),
        CheckConstraint(
            "auth_version >= 1",
            name="ck_devices_auth_version",
        ),
        CheckConstraint(
            "motherboard_serial_digest IS NULL OR "
            "length(motherboard_serial_digest) = 64",
            name="ck_devices_serial_digest",
        ),
        CheckConstraint(
            "motherboard_serial IS NULL",
            name="ck_devices_plaintext_serial_cleared",
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
    # Upgrade-only bridge. New writes must leave plaintext serials NULL.
    motherboard_serial: Mapped[str | None] = mapped_column(String(128), nullable=True)
    motherboard_serial_digest: Mapped[str | None] = mapped_column(
        String(64), nullable=True, unique=True, index=True
    )
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
    auth_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default=text("1")
    )
    auth_revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
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


def generate_device_id_from_digest(serial_digest: str) -> str:
    """Derive the stable public numeric ID from the non-reversible HMAC digest."""

    if len(serial_digest) != 64:
        raise ValueError("device serial digest is invalid")
    return str(int(serial_digest, 16) % 10**12).zfill(12)


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
