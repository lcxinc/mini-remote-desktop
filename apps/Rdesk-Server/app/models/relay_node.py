from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Integer, JSON, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class RelayNode(Base):
    __tablename__ = "relay_nodes"
    __table_args__ = (
        CheckConstraint(
            "state IN ('available', 'degraded', 'draining', 'unavailable', 'revoked')",
            name="ck_relay_nodes_state",
        ),
        CheckConstraint("max_allocations > 0", name="ck_relay_nodes_max_allocations"),
        CheckConstraint(
            "active_allocations >= 0 AND active_allocations <= max_allocations",
            name="ck_relay_nodes_active_allocations",
        ),
        CheckConstraint("max_egress_bps > 0", name="ck_relay_nodes_max_egress"),
        CheckConstraint(
            "current_egress_bps >= 0", name="ck_relay_nodes_current_egress"
        ),
        CheckConstraint(
            "heartbeat_sequence >= 0", name="ck_relay_nodes_heartbeat_sequence"
        ),
    )

    node_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    region: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    failure_domain: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(
        String(16), nullable=False, default="unavailable", index=True
    )
    endpoints: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    certificate_fingerprint: Mapped[str] = mapped_column(
        String(160), nullable=False, unique=True
    )
    encrypted_turn_secret: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    max_allocations: Mapped[int] = mapped_column(Integer, nullable=False)
    active_allocations: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    max_egress_bps: Mapped[int] = mapped_column(BigInteger, nullable=False)
    current_egress_bps: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )
    heartbeat_sequence: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
