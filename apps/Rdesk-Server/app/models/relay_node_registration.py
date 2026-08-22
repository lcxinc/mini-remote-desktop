from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    LargeBinary,
    String,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class RelayNodeRegistration(Base):
    """Public enrollment material held pending explicit administrator approval."""

    __tablename__ = "relay_node_registrations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'approved', 'revoked')",
            name="ck_relay_node_registrations_status",
        ),
    )

    node_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    enrollment_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("relay_enrollments.id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    failure_domain: Mapped[str] = mapped_column(String(128), nullable=False)
    endpoints: Mapped[list[str]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=False
    )
    max_allocations: Mapped[int] = mapped_column(Integer, nullable=False)
    max_egress_bps: Mapped[int] = mapped_column(BigInteger, nullable=False)
    csr_pem: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    signing_public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    certificate_pem: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    certificate_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
