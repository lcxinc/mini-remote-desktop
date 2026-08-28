from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    JSON,
    PrimaryKeyConstraint,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class RelayAccessGeneration(Base):
    __tablename__ = "relay_access_generations"
    __table_args__ = (
        PrimaryKeyConstraint(
            "session_id",
            "generation",
            name="relay_access_generations_pkey",
        ),
        UniqueConstraint(
            "directory_id",
            name="relay_access_generations_directory_id_key",
        ),
        CheckConstraint(
            "generation >= 0",
            name="ck_relay_access_generations_generation",
        ),
        CheckConstraint(
            "length(relay_url_digest) = 64",
            name="ck_relay_access_generations_url_digest",
        ),
        CheckConstraint(
            "expires_at > created_at",
            name="ck_relay_access_generations_expiry",
        ),
        Index("ix_relay_access_generations_expiry", "expires_at"),
        Index("ix_relay_access_generations_primary_node", "primary_node_id"),
    )

    session_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("session_requests.id", ondelete="CASCADE"),
        nullable=False,
    )
    generation: Mapped[int] = mapped_column(BigInteger, nullable=False)
    directory_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signed_directory: Mapped[dict[str, object]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"),
        nullable=False,
        info={"public_only": True},
    )
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_b64: Mapped[str] = mapped_column(String(128), nullable=False)
    relay_url_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    primary_node_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("relay_nodes.node_id", ondelete="RESTRICT"),
        nullable=False,
    )
    reservation_ids: Mapped[list[str]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
