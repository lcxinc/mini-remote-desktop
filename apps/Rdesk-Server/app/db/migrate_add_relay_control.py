from __future__ import annotations

import asyncio
import re

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.db.session import engine as default_engine


_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def _table(schema: str | None, name: str) -> str:
    if schema is None:
        return name
    if _IDENTIFIER.fullmatch(schema) is None:
        raise ValueError("invalid database schema identifier")
    return f'"{schema}".{name}'


async def migrate(
    engine: AsyncEngine = default_engine, *, schema: str | None = None
) -> None:
    """Create the relay-control schema in one idempotent transaction."""
    nodes = _table(schema, "relay_nodes")
    enrollments = _table(schema, "relay_enrollments")
    reservations = _table(schema, "relay_reservations")
    if schema is not None:
        schema_statement = f'CREATE SCHEMA IF NOT EXISTS "{schema}"'
    else:
        schema_statement = None

    statements = [
        f"""
        CREATE TABLE IF NOT EXISTS {nodes} (
            node_id VARCHAR(128) PRIMARY KEY,
            region VARCHAR(64) NOT NULL,
            failure_domain VARCHAR(128) NOT NULL,
            state VARCHAR(16) NOT NULL DEFAULT 'unavailable',
            endpoints JSONB NOT NULL,
            certificate_fingerprint VARCHAR(160) NOT NULL UNIQUE,
            encrypted_turn_secret BYTEA NOT NULL,
            max_allocations INTEGER NOT NULL,
            active_allocations INTEGER NOT NULL DEFAULT 0,
            max_egress_bps BIGINT NOT NULL,
            current_egress_bps BIGINT NOT NULL DEFAULT 0,
            heartbeat_sequence BIGINT NOT NULL DEFAULT 0,
            lease_expires_at TIMESTAMPTZ,
            revoked_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            CONSTRAINT ck_relay_nodes_state CHECK (
                state IN ('available', 'degraded', 'draining', 'unavailable', 'revoked')
            ),
            CONSTRAINT ck_relay_nodes_max_allocations CHECK (max_allocations > 0),
            CONSTRAINT ck_relay_nodes_active_allocations CHECK (
                active_allocations >= 0 AND active_allocations <= max_allocations
            ),
            CONSTRAINT ck_relay_nodes_max_egress CHECK (max_egress_bps > 0),
            CONSTRAINT ck_relay_nodes_current_egress CHECK (current_egress_bps >= 0),
            CONSTRAINT ck_relay_nodes_heartbeat_sequence CHECK (heartbeat_sequence >= 0)
        )
        """,
        f"""
        CREATE TABLE IF NOT EXISTS {enrollments} (
            id VARCHAR(36) PRIMARY KEY,
            token_digest VARCHAR(64) NOT NULL UNIQUE,
            expires_at TIMESTAMPTZ NOT NULL,
            used_at TIMESTAMPTZ,
            enrolled_node_id VARCHAR(128),
            created_at TIMESTAMPTZ NOT NULL
        )
        """,
        f"""
        CREATE TABLE IF NOT EXISTS {reservations} (
            id VARCHAR(36) PRIMARY KEY,
            session_id VARCHAR(128) NOT NULL,
            user_id VARCHAR(128) NOT NULL,
            node_id VARCHAR(128) NOT NULL REFERENCES {nodes}(node_id) ON DELETE CASCADE,
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            CONSTRAINT uq_relay_reservations_session_node UNIQUE (session_id, node_id)
        )
        """,
        f"CREATE INDEX IF NOT EXISTS ix_relay_nodes_region ON {nodes} (region)",
        f"CREATE INDEX IF NOT EXISTS ix_relay_nodes_state ON {nodes} (state)",
        f"CREATE INDEX IF NOT EXISTS ix_relay_nodes_lease ON {nodes} (lease_expires_at)",
        f"CREATE INDEX IF NOT EXISTS ix_relay_enrollments_expiry ON {enrollments} (expires_at)",
        f"CREATE INDEX IF NOT EXISTS ix_relay_reservations_session ON {reservations} (session_id)",
        f"CREATE INDEX IF NOT EXISTS ix_relay_reservations_user ON {reservations} (user_id)",
        f"CREATE INDEX IF NOT EXISTS ix_relay_reservations_node ON {reservations} (node_id)",
        f"CREATE INDEX IF NOT EXISTS ix_relay_reservations_expiry ON {reservations} (expires_at)",
    ]
    async with engine.begin() as connection:
        if schema_statement is not None:
            await connection.execute(text(schema_statement))
        for statement in statements:
            await connection.execute(text(statement))


if __name__ == "__main__":
    asyncio.run(migrate())
