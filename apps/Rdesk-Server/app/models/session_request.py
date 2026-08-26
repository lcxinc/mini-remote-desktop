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
        CheckConstraint(
            "(requester_device_id IS NULL AND request_payload IS NULL AND "
            "request_commitment IS NULL AND access_mode IS NULL AND "
            "route_policy IS NULL AND requested_scopes IS NULL AND "
            "requested_profile IS NULL AND approved_scopes IS NULL AND "
            "approved_profile IS NULL AND active_relay_generation IS NULL) OR "
            "(requester_device_id IS NOT NULL AND request_payload IS NOT NULL AND "
            "request_commitment IS NOT NULL AND length(request_commitment) = 64 AND "
            "access_mode IS NOT NULL AND route_policy IS NOT NULL AND "
            "requested_scopes IS NOT NULL)",
            name="ck_session_requests_wan_request_bundle",
        ),
        CheckConstraint(
            "requester_device_id IS NULL OR "
            "(requester_device_id <> target_device_id AND "
            "access_mode = 'attended' AND route_policy = 'relay_only')",
            name="ck_session_requests_wan_values",
        ),
        CheckConstraint(
            "active_relay_generation IS NULL OR "
            "(requester_device_id IS NOT NULL AND active_relay_generation >= 0)",
            name="ck_session_requests_active_relay_generation",
        ),
        CheckConstraint(
            "requester_device_id IS NULL OR status <> 'approved' OR "
            "(approved_scopes IS NOT NULL AND policy_expires_at IS NOT NULL AND "
            "active_relay_generation IS NOT NULL AND active_relay_generation >= 0)",
            name="ck_session_requests_wan_approval_bundle",
        ),
        Index("ix_session_requests_tenant_id", "tenant_id"),
        Index("ix_session_requests_active_relay_generation", "active_relay_generation"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    requester_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    requester_device_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
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
    request_payload: Mapped[dict[str, object] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    request_commitment: Mapped[str | None] = mapped_column(String(64), nullable=True)
    access_mode: Mapped[str | None] = mapped_column(String(24), nullable=True)
    route_policy: Mapped[str | None] = mapped_column(String(24), nullable=True)
    requested_scopes: Mapped[list[str] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    requested_profile: Mapped[dict[str, object] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    approved_scopes: Mapped[list[str] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    approved_profile: Mapped[dict[str, object] | None] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=True
    )
    active_relay_generation: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
