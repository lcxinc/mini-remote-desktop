from datetime import datetime
from uuid import uuid4

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    JSON,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class SessionRequest(Base):
    __tablename__ = "session_requests"
    __table_args__ = (
        CheckConstraint(
            "length(tenant_id) BETWEEN 1 AND 64",
            name="ck_session_requests_tenant_id",
        ),
        CheckConstraint(
            "status IN ('requested', 'approved', 'rejected', 'expired', "
            "'closed', 'revoked')",
            name="ck_session_requests_status",
        ),
        CheckConstraint(
            "policy_revision IS NULL OR policy_revision > 0",
            name="ck_session_requests_policy_revision",
        ),
        CheckConstraint(
            "status <> 'approved' OR (grant_expires_at IS NOT NULL AND "
            "policy_revision IS NOT NULL AND policy_expires_at IS NOT NULL AND "
            "intended_peer_id IS NOT NULL AND relay_allowed_regions IS NOT NULL AND "
            "relay_preferred_regions IS NOT NULL AND "
            "relay_accepted_transports IS NOT NULL)",
            name="ck_session_requests_approved_bundle",
        ),
        Index("ix_session_requests_tenant_id", "tenant_id"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    requester_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    target_device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), index=True
    )
    signaling_room: Mapped[str] = mapped_column(String(128), index=True)
    tenant_id: Mapped[str] = mapped_column(
        String(64), nullable=False, default="default", server_default=text("'default'")
    )
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="requested", server_default=text("'requested'")
    )
    grant_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    policy_revision: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    policy_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    intended_peer_id: Mapped[str | None] = mapped_column(
        String(128),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=True,
    )
    relay_allowed_regions: Mapped[list[str] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    relay_preferred_regions: Mapped[list[str] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    relay_accepted_transports: Mapped[list[str] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
