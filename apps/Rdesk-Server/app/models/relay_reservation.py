from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class RelayReservation(Base):
    __tablename__ = "relay_reservations"
    __table_args__ = (
        UniqueConstraint(
            "session_id",
            "node_id",
            "directory_generation",
            name="uq_relay_reservations_session_node_generation",
        ),
        CheckConstraint(
            "reserved_egress_bps >= 0",
            name="ck_relay_reservations_reserved_egress",
        ),
        Index("ix_relay_reservations_session", "session_id"),
        Index("ix_relay_reservations_user", "user_id"),
        Index("ix_relay_reservations_node", "node_id"),
        Index("ix_relay_reservations_expiry", "expires_at"),
        Index("ix_relay_reservations_node_expiry", "node_id", "expires_at"),
        Index(
            "ix_relay_reservations_session_expiry",
            "session_id",
            "expires_at",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    node_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("relay_nodes.node_id", ondelete="CASCADE"),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    superseded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    directory_generation: Mapped[str] = mapped_column(
        String(64), nullable=False, default="legacy", server_default=text("'legacy'")
    )
    reserved_egress_bps: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=text("0")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
