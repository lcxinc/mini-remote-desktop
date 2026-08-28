from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class DeviceEnrollment(Base):
    __tablename__ = "device_enrollments"
    __table_args__ = (
        CheckConstraint(
            "length(token_digest) = 64",
            name="ck_device_enrollments_token_digest",
        ),
        CheckConstraint(
            "request_digest IS NULL OR length(request_digest) = 64",
            name="ck_device_enrollments_request_digest",
        ),
        CheckConstraint(
            "expires_at > issued_at",
            name="ck_device_enrollments_expiry",
        ),
        CheckConstraint(
            "(consumed_at IS NULL AND request_digest IS NULL AND "
            "registered_device_id IS NULL) OR "
            "(consumed_at IS NOT NULL AND request_digest IS NOT NULL AND "
            "registered_device_id IS NOT NULL)",
            name="ck_device_enrollments_consumed_bundle",
        ),
        Index("ix_device_enrollments_expiry", "expires_at"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    token_digest: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    request_digest: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    registered_device_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="RESTRICT"),
        nullable=True,
    )
    issued_by_user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
