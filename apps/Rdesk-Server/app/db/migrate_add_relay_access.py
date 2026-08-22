from __future__ import annotations

import asyncio
import hashlib
import re

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.db.session import engine as default_engine


_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_LOCK_CONTEXT = b"MRD_RELAY_ACCESS_SCHEMA_MIGRATION_V1\x00"
_VERSION = 1


class RelayAccessMigrationError(RuntimeError):
    pass


def _table(schema: str | None, name: str) -> str:
    if schema is None:
        return name
    if _IDENTIFIER.fullmatch(schema) is None:
        raise ValueError("invalid database schema identifier")
    return f'"{schema}".{name}'


async def migrate(
    bind: AsyncEngine | AsyncConnection = default_engine,
    *,
    schema: str | None = None,
) -> None:
    if isinstance(bind, AsyncEngine):
        async with bind.begin() as connection:
            await _migrate_connection(connection, schema=schema)
        return
    await _migrate_connection(bind, schema=schema)


async def _migrate_connection(
    connection: AsyncConnection, *, schema: str | None
) -> None:
    if connection.dialect.name != "postgresql":
        raise RelayAccessMigrationError("relay access migration requires PostgreSQL")
    effective_schema = schema or await connection.scalar(text("SELECT current_schema()"))
    if not isinstance(effective_schema, str) or _IDENTIFIER.fullmatch(effective_schema) is None:
        raise RelayAccessMigrationError("relay access schema is invalid")
    await connection.execute(
        text("SELECT pg_advisory_xact_lock(:lock_key)"),
        {"lock_key": _lock_key(effective_schema)},
    )
    sessions = _table(schema, "session_requests")
    relay_nodes = _table(schema, "relay_nodes")
    versions = _table(schema, "relay_access_schema_migrations")
    await connection.execute(
        text(
            f"CREATE TABLE IF NOT EXISTS {versions} ("
            "version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
    )
    exists = await connection.run_sync(
        lambda sync: inspect(sync).has_table("session_requests", schema=schema)
    )
    if not exists:
        raise RelayAccessMigrationError("session request table is unavailable")
    for statement in (
        f"ALTER TABLE {relay_nodes} ADD COLUMN IF NOT EXISTS measured_rtt_ms BIGINT",
        f"ALTER TABLE {relay_nodes} ADD COLUMN IF NOT EXISTS recent_failure_bps "
        "INTEGER NOT NULL DEFAULT 0",
        f"ALTER TABLE {sessions} ADD COLUMN IF NOT EXISTS grant_expires_at TIMESTAMPTZ",
        f"ALTER TABLE {sessions} ADD COLUMN IF NOT EXISTS policy_revision BIGINT",
        f"ALTER TABLE {sessions} ADD COLUMN IF NOT EXISTS policy_expires_at TIMESTAMPTZ",
        f"ALTER TABLE {sessions} ADD COLUMN IF NOT EXISTS intended_peer_id VARCHAR(128)",
        f"ALTER TABLE {sessions} ADD COLUMN IF NOT EXISTS relay_allowed_regions JSONB",
        f"ALTER TABLE {sessions} ADD COLUMN IF NOT EXISTS relay_preferred_regions JSONB",
        f"ALTER TABLE {sessions} ADD COLUMN IF NOT EXISTS relay_accepted_transports JSONB",
    ):
        await connection.execute(text(statement))
    await _add_check_constraint(
        connection,
        table=relay_nodes,
        regclass=f"{effective_schema}.relay_nodes",
        name="ck_relay_nodes_measured_rtt",
        expression=(
            "measured_rtt_ms IS NULL OR "
            "(measured_rtt_ms >= 0 AND measured_rtt_ms <= 4294967295)"
        ),
    )
    await _add_check_constraint(
        connection,
        table=relay_nodes,
        regclass=f"{effective_schema}.relay_nodes",
        name="ck_relay_nodes_recent_failure",
        expression="recent_failure_bps >= 0 AND recent_failure_bps <= 10000",
    )
    await connection.run_sync(lambda sync: _verify(sync, schema))
    await connection.execute(
        text(
            f"INSERT INTO {versions} (version) VALUES (:version) "
            "ON CONFLICT (version) DO NOTHING"
        ),
        {"version": _VERSION},
    )


def _verify(connection: object, schema: str | None) -> None:
    columns = {
        column["name"]: column
        for column in inspect(connection).get_columns("session_requests", schema=schema)
    }
    required = {
        "grant_expires_at",
        "policy_revision",
        "policy_expires_at",
        "intended_peer_id",
        "relay_allowed_regions",
        "relay_preferred_regions",
        "relay_accepted_transports",
    }
    if not required.issubset(columns) or any(
        columns[name]["nullable"] is not True for name in required
    ):
        raise RelayAccessMigrationError("relay access schema does not conform")
    node_columns = {
        column["name"]: column
        for column in inspect(connection).get_columns("relay_nodes", schema=schema)
    }
    if (
        "measured_rtt_ms" not in node_columns
        or node_columns["measured_rtt_ms"]["nullable"] is not True
        or "recent_failure_bps" not in node_columns
        or node_columns["recent_failure_bps"]["nullable"] is not False
    ):
        raise RelayAccessMigrationError("relay selection metric schema does not conform")
    checks = {
        constraint["name"]
        for constraint in inspect(connection).get_check_constraints(
            "relay_nodes", schema=schema
        )
    }
    if not {
        "ck_relay_nodes_measured_rtt",
        "ck_relay_nodes_recent_failure",
    }.issubset(checks):
        raise RelayAccessMigrationError("relay selection metric checks are unavailable")


async def _add_check_constraint(
    connection: AsyncConnection,
    *,
    table: str,
    regclass: str,
    name: str,
    expression: str,
) -> None:
    exists = await connection.scalar(
        text(
            "SELECT EXISTS (SELECT 1 FROM pg_constraint "
            "WHERE conname = :name AND conrelid = to_regclass(:table_name))"
        ),
        {"name": name, "table_name": regclass},
    )
    if not exists:
        await connection.execute(
            text(f"ALTER TABLE {table} ADD CONSTRAINT {name} CHECK ({expression})")
        )


def _lock_key(schema: str) -> int:
    digest = hashlib.sha256(_LOCK_CONTEXT + schema.encode("ascii")).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


if __name__ == "__main__":
    asyncio.run(migrate())
