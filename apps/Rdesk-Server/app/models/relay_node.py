from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    JSON,
    LargeBinary,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
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
            "current_ingress_bps >= 0", name="ck_relay_nodes_current_ingress"
        ),
        CheckConstraint("identity_epoch >= 1", name="ck_relay_nodes_identity_epoch"),
        CheckConstraint(
            "process_health IN ('healthy', 'degraded', 'failed') AND "
            "listener_health IN ('healthy', 'degraded', 'failed') AND "
            "probe_health IN ('healthy', 'failed', 'non_evidence')",
            name="ck_relay_nodes_health",
        ),
        CheckConstraint(
            "packet_loss_bps >= 0 AND packet_loss_bps <= 10000 AND "
            "cpu_usage_bps >= 0 AND cpu_usage_bps <= 10000 AND "
            "memory_usage_bps >= 0 AND memory_usage_bps <= 10000",
            name="ck_relay_nodes_pressure",
        ),
        CheckConstraint(
            "active_secret_version >= 1 AND applied_secret_version >= 1 AND "
            "desired_secret_version >= active_secret_version",
            name="ck_relay_nodes_secret_versions",
        ),
        CheckConstraint(
            "(pending_secret_version IS NULL AND "
            "pending_encrypted_turn_secret IS NULL AND "
            "pending_secret_digest IS NULL AND pending_rotation_id IS NULL AND "
            "pending_secret_uploaded_at IS NULL) OR "
            "(pending_secret_version = desired_secret_version AND "
            "pending_encrypted_turn_secret IS NOT NULL AND "
            "length(pending_encrypted_turn_secret) >= 30 AND "
            "pending_secret_digest IS NOT NULL AND "
            "length(pending_secret_digest) = 32 AND "
            "pending_rotation_id IS NOT NULL AND "
            "pending_secret_uploaded_at IS NOT NULL)",
            name="ck_relay_nodes_rotation_pending",
        ),
        CheckConstraint(
            "heartbeat_sequence >= 0", name="ck_relay_nodes_heartbeat_sequence"
        ),
        CheckConstraint(
            "healthy_heartbeat_streak >= 0 AND healthy_heartbeat_streak <= 3",
            name="ck_relay_nodes_healthy_heartbeat_streak",
        ),
        CheckConstraint(
            "measured_rtt_ms IS NULL OR "
            "(measured_rtt_ms >= 0 AND measured_rtt_ms <= 4294967295)",
            name="ck_relay_nodes_measured_rtt",
        ),
        CheckConstraint(
            "recent_failure_bps >= 0 AND recent_failure_bps <= 10000",
            name="ck_relay_nodes_recent_failure",
        ),
        CheckConstraint(
            "physical_host_id IS NULL OR length(physical_host_id) BETWEEN 1 AND 128",
            name="ck_relay_nodes_physical_host",
        ),
        Index("ix_relay_nodes_region", "region"),
        Index("ix_relay_nodes_state", "state"),
        Index("ix_relay_nodes_lease", "lease_expires_at"),
        Index("ix_relay_nodes_physical_host", "physical_host_id"),
    )

    node_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    failure_domain: Mapped[str] = mapped_column(String(128), nullable=False)
    physical_host_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    state: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="unavailable",
        server_default=text("'unavailable'"),
    )
    endpoints: Mapped[list[str]] = mapped_column(
        JSON().with_variant(JSONB(), "postgresql"), nullable=False
    )
    certificate_fingerprint: Mapped[str] = mapped_column(
        String(71), nullable=False, unique=True
    )
    encrypted_turn_secret: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    max_allocations: Mapped[int] = mapped_column(Integer, nullable=False)
    active_allocations: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    max_egress_bps: Mapped[int] = mapped_column(BigInteger, nullable=False)
    current_egress_bps: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=text("0")
    )
    current_ingress_bps: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=text("0")
    )
    identity_epoch: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=1, server_default=text("1")
    )
    last_boot_id: Mapped[str | None] = mapped_column(String(22), nullable=True)
    last_heartbeat_nonce: Mapped[str | None] = mapped_column(String(43), nullable=True)
    process_health: Mapped[str] = mapped_column(
        String(16), nullable=False, default="failed", server_default=text("'failed'")
    )
    listener_health: Mapped[str] = mapped_column(
        String(16), nullable=False, default="failed", server_default=text("'failed'")
    )
    probe_health: Mapped[str] = mapped_column(
        String(16), nullable=False, default="non_evidence", server_default=text("'non_evidence'")
    )
    packet_loss_bps: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    cpu_usage_bps: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    memory_usage_bps: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    active_secret_version: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=1, server_default=text("1")
    )
    applied_secret_version: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=1, server_default=text("1")
    )
    desired_secret_version: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=1, server_default=text("1")
    )
    desired_draining: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    secret_not_before: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    old_credential_deadline: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    pending_secret_version: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )
    pending_encrypted_turn_secret: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True
    )
    pending_secret_digest: Mapped[bytes | None] = mapped_column(
        LargeBinary, nullable=True
    )
    pending_rotation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    pending_secret_uploaded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    committed_rotation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    heartbeat_sequence: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=text("0")
    )
    healthy_heartbeat_streak: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    measured_rtt_ms: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )
    recent_failure_bps: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
