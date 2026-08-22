from __future__ import annotations

import asyncio
import re

from sqlalchemy import BigInteger, DateTime, Integer, LargeBinary, String, inspect, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.db.session import engine as default_engine


_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_RELAY_SCHEMA_VERSION = 1


class RelaySchemaMismatchError(RuntimeError):
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
    """Apply and verify relay schema v1 in the caller's transaction when provided."""
    if isinstance(bind, AsyncEngine):
        async with bind.begin() as connection:
            await _migrate_connection(connection, schema=schema)
        return
    await _migrate_connection(bind, schema=schema)


async def _migrate_connection(
    connection: AsyncConnection, *, schema: str | None
) -> None:
    if schema is not None and _IDENTIFIER.fullmatch(schema) is None:
        raise ValueError("invalid database schema identifier")
    nodes = _table(schema, "relay_nodes")
    enrollments = _table(schema, "relay_enrollments")
    reservations = _table(schema, "relay_reservations")
    versions = _table(schema, "relay_schema_migrations")

    if schema is not None:
        await connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
    await connection.run_sync(
        lambda sync_connection: _preflight_existing_schema(sync_connection, schema)
    )

    statements = [
        f"""
        CREATE TABLE IF NOT EXISTS {nodes} (
            node_id VARCHAR(128) PRIMARY KEY,
            region VARCHAR(64) NOT NULL,
            failure_domain VARCHAR(128) NOT NULL,
            state VARCHAR(16) NOT NULL DEFAULT 'unavailable',
            endpoints JSONB NOT NULL,
            certificate_fingerprint VARCHAR(71) NOT NULL,
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
            CONSTRAINT relay_nodes_certificate_fingerprint_key
                UNIQUE (certificate_fingerprint),
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
            token_digest VARCHAR(64) NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            used_at TIMESTAMPTZ,
            enrolled_node_id VARCHAR(128),
            created_at TIMESTAMPTZ NOT NULL,
            CONSTRAINT relay_enrollments_token_digest_key UNIQUE (token_digest)
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
        f"""
        CREATE TABLE IF NOT EXISTS {versions} (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
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
        f"CREATE INDEX IF NOT EXISTS ix_relay_reservations_node_expiry ON {reservations} (node_id, expires_at)",
        f"CREATE INDEX IF NOT EXISTS ix_relay_reservations_session_expiry ON {reservations} (session_id, expires_at)",
    ]
    for statement in statements:
        await connection.execute(text(statement))

    await connection.run_sync(
        lambda sync_connection: _assert_schema_conforms(sync_connection, schema)
    )
    await connection.execute(
        text(
            f"INSERT INTO {versions} (version) VALUES (:version) "
            "ON CONFLICT (version) DO NOTHING"
        ),
        {"version": _RELAY_SCHEMA_VERSION},
    )


def _preflight_existing_schema(sync_connection: object, schema: str | None) -> None:
    inspector = inspect(sync_connection)
    required_columns = {
        "relay_nodes": {
            "node_id", "region", "failure_domain", "state", "endpoints",
            "certificate_fingerprint", "encrypted_turn_secret", "max_allocations",
            "active_allocations", "max_egress_bps", "current_egress_bps",
            "heartbeat_sequence", "lease_expires_at", "revoked_at", "created_at",
            "updated_at",
        },
        "relay_enrollments": {
            "id", "token_digest", "expires_at", "used_at", "enrolled_node_id",
            "created_at",
        },
        "relay_reservations": {
            "id", "session_id", "user_id", "node_id", "expires_at", "created_at",
        },
    }
    for table_name, expected in required_columns.items():
        if not inspector.has_table(table_name, schema=schema):
            continue
        actual = {
            column["name"]
            for column in inspector.get_columns(table_name, schema=schema)
        }
        if actual != expected:
            raise RelaySchemaMismatchError(
                f"relay schema mismatch for {table_name}: column set differs"
            )


def _type_matches(value: object, expected: tuple[type[object], int | None]) -> bool:
    expected_type, expected_length = expected
    if not isinstance(value, expected_type):
        return False
    if expected_length is not None and getattr(value, "length", None) != expected_length:
        return False
    if expected_type is DateTime and not getattr(value, "timezone", False):
        return False
    return True


def _assert_schema_conforms(sync_connection: object, schema: str | None) -> None:
    inspector = inspect(sync_connection)
    specs: dict[str, dict[str, tuple[type[object], int | None, bool]]] = {
        "relay_nodes": {
            "node_id": (String, 128, False),
            "region": (String, 64, False),
            "failure_domain": (String, 128, False),
            "state": (String, 16, False),
            "endpoints": (JSONB, None, False),
            "certificate_fingerprint": (String, 71, False),
            "encrypted_turn_secret": (LargeBinary, None, False),
            "max_allocations": (Integer, None, False),
            "active_allocations": (Integer, None, False),
            "max_egress_bps": (BigInteger, None, False),
            "current_egress_bps": (BigInteger, None, False),
            "heartbeat_sequence": (BigInteger, None, False),
            "lease_expires_at": (DateTime, None, True),
            "revoked_at": (DateTime, None, True),
            "created_at": (DateTime, None, False),
            "updated_at": (DateTime, None, False),
        },
        "relay_enrollments": {
            "id": (String, 36, False),
            "token_digest": (String, 64, False),
            "expires_at": (DateTime, None, False),
            "used_at": (DateTime, None, True),
            "enrolled_node_id": (String, 128, True),
            "created_at": (DateTime, None, False),
        },
        "relay_reservations": {
            "id": (String, 36, False),
            "session_id": (String, 128, False),
            "user_id": (String, 128, False),
            "node_id": (String, 128, False),
            "expires_at": (DateTime, None, False),
            "created_at": (DateTime, None, False),
        },
    }
    for table_name, expected_columns in specs.items():
        columns = {
            column["name"]: column
            for column in inspector.get_columns(table_name, schema=schema)
        }
        if set(columns) != set(expected_columns):
            raise RelaySchemaMismatchError(
                f"relay schema mismatch for {table_name}: column set differs"
            )
        for name, (expected_type, length, nullable) in expected_columns.items():
            column = columns[name]
            if column["nullable"] is not nullable or not _type_matches(
                column["type"], (expected_type, length)
            ):
                raise RelaySchemaMismatchError(
                    f"relay schema mismatch for {table_name}.{name}"
                )

    expected_primary_keys = {
        "relay_nodes": ("relay_nodes_pkey", ("node_id",)),
        "relay_enrollments": ("relay_enrollments_pkey", ("id",)),
        "relay_reservations": ("relay_reservations_pkey", ("id",)),
    }
    for table_name, (constraint_name, column_names) in expected_primary_keys.items():
        primary_key = inspector.get_pk_constraint(table_name, schema=schema)
        if (
            primary_key.get("name") != constraint_name
            or tuple(primary_key.get("constrained_columns") or ()) != column_names
        ):
            raise RelaySchemaMismatchError(
                f"relay schema mismatch for {table_name}: primary key differs"
            )

    node_columns = {
        column["name"]: column
        for column in inspector.get_columns("relay_nodes", schema=schema)
    }
    if "unavailable" not in str(node_columns["state"]["default"]):
        raise RelaySchemaMismatchError("relay node state default differs")
    for name in ("active_allocations", "current_egress_bps", "heartbeat_sequence"):
        if str(node_columns[name]["default"]).strip("()") != "0":
            raise RelaySchemaMismatchError(f"relay node {name} default differs")

    required_checks = {
        "ck_relay_nodes_state": (
            "available", "degraded", "draining", "unavailable", "revoked",
        ),
        "ck_relay_nodes_max_allocations": ("max_allocations > 0",),
        "ck_relay_nodes_active_allocations": (
            "active_allocations >= 0", "active_allocations <= max_allocations",
        ),
        "ck_relay_nodes_max_egress": ("max_egress_bps > 0",),
        "ck_relay_nodes_current_egress": ("current_egress_bps >= 0",),
        "ck_relay_nodes_heartbeat_sequence": ("heartbeat_sequence >= 0",),
    }
    checks = {
        constraint["name"]: " ".join(constraint["sqltext"].lower().split())
        for constraint in inspector.get_check_constraints("relay_nodes", schema=schema)
    }
    if any(
        name not in checks
        or any(fragment not in checks[name] for fragment in fragments)
        for name, fragments in required_checks.items()
    ):
        raise RelaySchemaMismatchError("relay node check constraints differ")

    expected_unique = {
        "relay_nodes": {
            "relay_nodes_certificate_fingerprint_key": ("certificate_fingerprint",),
        },
        "relay_enrollments": {
            "relay_enrollments_token_digest_key": ("token_digest",),
        },
        "relay_reservations": {
            "uq_relay_reservations_session_node": ("session_id", "node_id"),
        },
    }
    for table_name, required in expected_unique.items():
        actual = {
            constraint["name"]: tuple(constraint["column_names"])
            for constraint in inspector.get_unique_constraints(
                table_name, schema=schema
            )
        }
        if any(actual.get(name) != columns for name, columns in required.items()):
            raise RelaySchemaMismatchError(
                f"relay schema mismatch for {table_name}: unique constraints differ"
            )

    foreign_keys = inspector.get_foreign_keys("relay_reservations", schema=schema)
    if not any(
        tuple(key["constrained_columns"]) == ("node_id",)
        and key["referred_table"] == "relay_nodes"
        and tuple(key["referred_columns"]) == ("node_id",)
        and (key.get("options") or {}).get("ondelete") == "CASCADE"
        for key in foreign_keys
    ):
        raise RelaySchemaMismatchError("relay reservation foreign key differs")

    expected_indexes = {
        "relay_nodes": {
            "ix_relay_nodes_region": ("region",),
            "ix_relay_nodes_state": ("state",),
            "ix_relay_nodes_lease": ("lease_expires_at",),
        },
        "relay_enrollments": {
            "ix_relay_enrollments_expiry": ("expires_at",),
        },
        "relay_reservations": {
            "ix_relay_reservations_session": ("session_id",),
            "ix_relay_reservations_user": ("user_id",),
            "ix_relay_reservations_node": ("node_id",),
            "ix_relay_reservations_expiry": ("expires_at",),
            "ix_relay_reservations_node_expiry": ("node_id", "expires_at"),
            "ix_relay_reservations_session_expiry": ("session_id", "expires_at"),
        },
    }
    for table_name, required in expected_indexes.items():
        actual = {
            index["name"]: tuple(index["column_names"])
            for index in inspector.get_indexes(table_name, schema=schema)
        }
        if any(actual.get(name) != columns for name, columns in required.items()):
            raise RelaySchemaMismatchError(
                f"relay schema mismatch for {table_name}: indexes differ"
            )


if __name__ == "__main__":
    asyncio.run(migrate())
