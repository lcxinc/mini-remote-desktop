from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class RelayReservation(Base):
    __tablename__ = "relay_reservations"
    __table_args__ = (
        UniqueConstraint(
            "session_id", "node_id", name="uq_relay_reservations_session_node"
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    session_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    node_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("relay_nodes.node_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
