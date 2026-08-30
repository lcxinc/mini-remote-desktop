from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.db.session import engine as default_engine


async def apply_reserved_egress_upgrade(
    connection: AsyncConnection,
    *,
    reservations_table: str,
) -> None:
    """Apply relay-control v9 inside its advisory-locked transaction."""

    await connection.execute(
        text(
            f"ALTER TABLE {reservations_table} ADD COLUMN IF NOT EXISTS "
            "reserved_egress_bps BIGINT NOT NULL DEFAULT 0"
        )
    )
    await connection.execute(
        text(
            f"ALTER TABLE {reservations_table} "
            "DROP CONSTRAINT IF EXISTS uq_relay_reservations_session_node"
        )
    )
    await connection.execute(
        text(
            f"""
            DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint
                    WHERE conrelid = '{reservations_table}'::regclass
                      AND conname =
                          'uq_relay_reservations_session_node_generation'
                ) THEN
                    ALTER TABLE {reservations_table}
                    ADD CONSTRAINT uq_relay_reservations_session_node_generation
                    UNIQUE (session_id, node_id, directory_generation);
                END IF;
            END $$
            """
        )
    )
    await connection.execute(
        text(
            f"""
            DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint
                    WHERE conrelid = '{reservations_table}'::regclass
                      AND conname = 'ck_relay_reservations_reserved_egress'
                ) THEN
                    ALTER TABLE {reservations_table}
                    ADD CONSTRAINT ck_relay_reservations_reserved_egress
                    CHECK (reserved_egress_bps >= 0);
                END IF;
            END $$
            """
        )
    )


async def migrate(
    bind: AsyncEngine | AsyncConnection = default_engine,
    *,
    schema: str | None = None,
) -> None:
    """Run the authoritative relay-control migration through reserved-egress v9."""

    # Import lazily because relay-control imports the isolated v9 SQL helper above.
    from app.db.migrate_add_relay_control import migrate as migrate_relay_control

    await migrate_relay_control(bind, schema=schema)
