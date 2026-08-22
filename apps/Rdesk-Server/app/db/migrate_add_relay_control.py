from __future__ import annotations

import asyncio
import hashlib
import re

from sqlalchemy import BigInteger, DateTime, Integer, LargeBinary, String, inspect, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.db.session import engine as default_engine


_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_CHECK_CAST = re.compile(
    r"::(?:character\s+varying|text|integer|bigint)(?:\[\])?",
    flags=re.IGNORECASE,
)
_MIGRATION_LOCK_CONTEXT = b"MRD_RELAY_SCHEMA_MIGRATION_V1\x00"
_RELAY_SCHEMA_VERSIONS = (1, 2, 3, 4)


class RelaySchemaMismatchError(RuntimeError):
    pass


class RelayMigrationBackendError(RuntimeError):
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
    """Apply and verify relay schema through v4 in the caller's transaction."""
    if isinstance(bind, AsyncEngine):
        async with bind.begin() as connection:
            await _migrate_connection(connection, schema=schema)
        return
    await _migrate_connection(bind, schema=schema)


async def _migrate_connection(
    connection: AsyncConnection, *, schema: str | None
) -> None:
    if connection.dialect.name != "postgresql":
        raise RelayMigrationBackendError(
            "relay schema migration requires PostgreSQL advisory transaction locks"
        )
    if schema is not None and _IDENTIFIER.fullmatch(schema) is None:
        raise ValueError("invalid database schema identifier")
    effective_schema = schema
    if effective_schema is None:
        effective_schema = await connection.scalar(text("SELECT current_schema()"))
    if (
        not isinstance(effective_schema, str)
        or _IDENTIFIER.fullmatch(effective_schema) is None
    ):
        raise RelaySchemaMismatchError(
            "relay schema migration requires a normalized database schema"
        )

    # This lock is acquired before inspecting or mutating the target schema. A rare
    # 64-bit hash collision can only serialize unrelated schema migrations.
    await connection.execute(
        text("SELECT pg_advisory_xact_lock(:lock_key)"),
        {"lock_key": _migration_advisory_lock_key(effective_schema)},
    )
    nodes = _table(schema, "relay_nodes")
    enrollments = _table(schema, "relay_enrollments")
    reservations = _table(schema, "relay_reservations")
    registrations = _table(schema, "relay_node_registrations")
    audit_events = _table(schema, "relay_audit_events")
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
            healthy_heartbeat_streak INTEGER NOT NULL DEFAULT 0,
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
            CONSTRAINT ck_relay_nodes_heartbeat_sequence CHECK (heartbeat_sequence >= 0),
            CONSTRAINT ck_relay_nodes_healthy_heartbeat_streak CHECK (
                healthy_heartbeat_streak >= 0 AND healthy_heartbeat_streak <= 3
            )
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
        f"""
        CREATE TABLE IF NOT EXISTS {registrations} (
            node_id VARCHAR(128) PRIMARY KEY,
            enrollment_id VARCHAR(36) NOT NULL REFERENCES {enrollments}(id) ON DELETE RESTRICT,
            region VARCHAR(64) NOT NULL,
            failure_domain VARCHAR(128) NOT NULL,
            endpoints JSONB NOT NULL,
            max_allocations INTEGER NOT NULL,
            max_egress_bps BIGINT NOT NULL,
            csr_pem BYTEA NOT NULL,
            signing_public_key BYTEA NOT NULL,
            status VARCHAR(16) NOT NULL DEFAULT 'pending',
            certificate_pem BYTEA,
            certificate_expires_at TIMESTAMPTZ,
            request_digest VARCHAR(64),
            receipt_digest VARCHAR(64),
            receipt_expires_at TIMESTAMPTZ,
            ca_certificate_pem BYTEA,
            previous_certificate_fingerprint VARCHAR(71),
            previous_signing_public_key BYTEA,
            previous_auth_expires_at TIMESTAMPTZ,
            previous_certificate_expires_at TIMESTAMPTZ,
            renewal_request_id VARCHAR(128),
            renewal_csr_sha256 VARCHAR(64),
            renewal_certificate_pem BYTEA,
            renewal_certificate_expires_at TIMESTAMPTZ,
            renewal_record_expires_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL,
            approved_at TIMESTAMPTZ,
            CONSTRAINT relay_node_registrations_enrollment_id_key UNIQUE (enrollment_id),
            CONSTRAINT ck_relay_node_registrations_status CHECK (
                status IN ('pending', 'approved', 'revoked')
            )
        )
        """,
        f"""
        CREATE TABLE IF NOT EXISTS {audit_events} (
            id VARCHAR(36) PRIMARY KEY,
            action VARCHAR(64) NOT NULL,
            node_id VARCHAR(128),
            actor_id VARCHAR(128),
            details JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL
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
        f"CREATE INDEX IF NOT EXISTS ix_relay_audit_events_node "
        f"ON {audit_events} (node_id)",
        f"CREATE INDEX IF NOT EXISTS ix_relay_audit_events_created "
        f"ON {audit_events} (created_at)",
    ]
    for statement in statements:
        await connection.execute(text(statement))

    # v3 is deliberately additive so an already deployed v2 schema upgrades in
    # place while the advisory transaction lock serializes concurrent starters.
    for statement in (
        f"ALTER TABLE {nodes} ADD COLUMN IF NOT EXISTS "
        "healthy_heartbeat_streak INTEGER NOT NULL DEFAULT 0",
        f"ALTER TABLE {registrations} ADD COLUMN IF NOT EXISTS receipt_digest VARCHAR(64)",
        f"ALTER TABLE {registrations} ADD COLUMN IF NOT EXISTS request_digest VARCHAR(64)",
        f"ALTER TABLE {registrations} ADD COLUMN IF NOT EXISTS receipt_expires_at TIMESTAMPTZ",
        f"ALTER TABLE {registrations} ADD COLUMN IF NOT EXISTS ca_certificate_pem BYTEA",
        f"ALTER TABLE {registrations} ADD COLUMN IF NOT EXISTS "
        "previous_certificate_fingerprint VARCHAR(71)",
        f"ALTER TABLE {registrations} ADD COLUMN IF NOT EXISTS previous_signing_public_key BYTEA",
        f"ALTER TABLE {registrations} ADD COLUMN IF NOT EXISTS "
        "previous_auth_expires_at TIMESTAMPTZ",
        f"ALTER TABLE {registrations} ADD COLUMN IF NOT EXISTS "
        "previous_certificate_expires_at TIMESTAMPTZ",
        f"ALTER TABLE {registrations} ADD COLUMN IF NOT EXISTS renewal_request_id VARCHAR(128)",
        f"ALTER TABLE {registrations} ADD COLUMN IF NOT EXISTS renewal_csr_sha256 VARCHAR(64)",
        f"ALTER TABLE {registrations} ADD COLUMN IF NOT EXISTS renewal_certificate_pem BYTEA",
        f"ALTER TABLE {registrations} ADD COLUMN IF NOT EXISTS "
        "renewal_certificate_expires_at TIMESTAMPTZ",
        f"ALTER TABLE {registrations} ADD COLUMN IF NOT EXISTS "
        "renewal_record_expires_at TIMESTAMPTZ",
    ):
        await connection.execute(text(statement))
    await connection.execute(
        text(
            f"""
            DO $$ BEGIN
                ALTER TABLE {nodes} ADD CONSTRAINT ck_relay_nodes_healthy_heartbeat_streak
                CHECK (healthy_heartbeat_streak >= 0 AND healthy_heartbeat_streak <= 3);
            EXCEPTION WHEN duplicate_object THEN NULL;
            END $$
            """
        )
    )

    await connection.run_sync(
        lambda sync_connection: _assert_schema_conforms(sync_connection, schema)
    )
    for version in _RELAY_SCHEMA_VERSIONS:
        await connection.execute(
            text(
                f"INSERT INTO {versions} (version) VALUES (:version) "
                "ON CONFLICT (version) DO NOTHING"
            ),
            {"version": version},
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
        "relay_node_registrations": {
            "node_id", "enrollment_id", "region", "failure_domain", "endpoints",
            "max_allocations", "max_egress_bps", "csr_pem", "signing_public_key",
            "status", "certificate_pem", "certificate_expires_at", "created_at",
            "approved_at",
        },
        "relay_audit_events": {
            "id", "action", "node_id", "actor_id", "details", "created_at",
        },
    }
    for table_name, expected in required_columns.items():
        if not inspector.has_table(table_name, schema=schema):
            continue
        actual = {
            column["name"]
            for column in inspector.get_columns(table_name, schema=schema)
        }
        v3_additions = {
            "relay_nodes": {"healthy_heartbeat_streak"},
            "relay_node_registrations": {
                "receipt_digest", "receipt_expires_at", "ca_certificate_pem",
                "previous_certificate_fingerprint", "previous_signing_public_key",
                "previous_auth_expires_at", "renewal_request_id", "renewal_csr_sha256",
                "renewal_certificate_pem", "renewal_certificate_expires_at",
            },
        }.get(table_name, set())
        v4_additions = {
            "relay_node_registrations": {
                "request_digest",
                "previous_certificate_expires_at",
                "renewal_record_expires_at",
            },
        }.get(table_name, set())
        if actual not in (
            expected,
            expected | v3_additions,
            expected | v3_additions | v4_additions,
        ):
            raise RelaySchemaMismatchError(
                f"relay schema mismatch for {table_name}: column set differs"
            )
        expected_primary_key = {
            "relay_nodes": ("node_id",),
            "relay_enrollments": ("id",),
            "relay_reservations": ("id",),
            "relay_node_registrations": ("node_id",),
            "relay_audit_events": ("id",),
        }[table_name]
        primary_key = inspector.get_pk_constraint(table_name, schema=schema)
        if tuple(primary_key.get("constrained_columns") or ()) != expected_primary_key:
            raise RelaySchemaMismatchError(
                f"relay schema mismatch for {table_name}: primary key differs"
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


def _migration_advisory_lock_key(schema: str) -> int:
    digest = hashlib.sha256(
        _MIGRATION_LOCK_CONTEXT + schema.encode("ascii")
    ).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=True)


def _normalize_check_expression(expression: object) -> str:
    if not isinstance(expression, str):
        return ""
    without_casts = _CHECK_CAST.sub("", expression.lower())
    return re.sub(r'[\s()"]+', "", without_casts)


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
            "healthy_heartbeat_streak": (Integer, None, False),
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
        "relay_node_registrations": {
            "node_id": (String, 128, False),
            "enrollment_id": (String, 36, False),
            "region": (String, 64, False),
            "failure_domain": (String, 128, False),
            "endpoints": (JSONB, None, False),
            "max_allocations": (Integer, None, False),
            "max_egress_bps": (BigInteger, None, False),
            "csr_pem": (LargeBinary, None, False),
            "signing_public_key": (LargeBinary, None, False),
            "status": (String, 16, False),
            "certificate_pem": (LargeBinary, None, True),
            "certificate_expires_at": (DateTime, None, True),
            "request_digest": (String, 64, True),
            "receipt_digest": (String, 64, True),
            "receipt_expires_at": (DateTime, None, True),
            "ca_certificate_pem": (LargeBinary, None, True),
            "previous_certificate_fingerprint": (String, 71, True),
            "previous_signing_public_key": (LargeBinary, None, True),
            "previous_auth_expires_at": (DateTime, None, True),
            "previous_certificate_expires_at": (DateTime, None, True),
            "renewal_request_id": (String, 128, True),
            "renewal_csr_sha256": (String, 64, True),
            "renewal_certificate_pem": (LargeBinary, None, True),
            "renewal_certificate_expires_at": (DateTime, None, True),
            "renewal_record_expires_at": (DateTime, None, True),
            "created_at": (DateTime, None, False),
            "approved_at": (DateTime, None, True),
        },
        "relay_audit_events": {
            "id": (String, 36, False),
            "action": (String, 64, False),
            "node_id": (String, 128, True),
            "actor_id": (String, 128, True),
            "details": (JSONB, None, False),
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
        "relay_node_registrations": (
            "relay_node_registrations_pkey", ("node_id",)
        ),
        "relay_audit_events": ("relay_audit_events_pkey", ("id",)),
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
    for name in (
        "active_allocations", "current_egress_bps", "heartbeat_sequence",
        "healthy_heartbeat_streak",
    ):
        if str(node_columns[name]["default"]).strip("()") != "0":
            raise RelaySchemaMismatchError(f"relay node {name} default differs")
    registration_columns = {
        column["name"]: column
        for column in inspector.get_columns(
            "relay_node_registrations", schema=schema
        )
    }
    if "pending" not in str(registration_columns["status"]["default"]):
        raise RelaySchemaMismatchError("relay registration status default differs")

    required_checks = {
        "ck_relay_nodes_state": (
            "state = ANY (ARRAY['available', 'degraded', 'draining', "
            "'unavailable', 'revoked'])"
        ),
        "ck_relay_nodes_max_allocations": "max_allocations > 0",
        "ck_relay_nodes_active_allocations": (
            "active_allocations >= 0 AND active_allocations <= max_allocations"
        ),
        "ck_relay_nodes_max_egress": "max_egress_bps > 0",
        "ck_relay_nodes_current_egress": "current_egress_bps >= 0",
        "ck_relay_nodes_heartbeat_sequence": "heartbeat_sequence >= 0",
        "ck_relay_nodes_healthy_heartbeat_streak": (
            "healthy_heartbeat_streak >= 0 AND healthy_heartbeat_streak <= 3"
        ),
    }
    checks = {
        constraint["name"]: _normalize_check_expression(constraint["sqltext"])
        for constraint in inspector.get_check_constraints("relay_nodes", schema=schema)
    }
    if any(
        name not in checks
        or checks[name] != _normalize_check_expression(expression)
        for name, expression in required_checks.items()
    ):
        raise RelaySchemaMismatchError("relay node check constraints differ")
    registration_checks = {
        constraint["name"]: _normalize_check_expression(constraint["sqltext"])
        for constraint in inspector.get_check_constraints(
            "relay_node_registrations", schema=schema
        )
    }
    expected_registration_check = _normalize_check_expression(
        "status = ANY (ARRAY['pending', 'approved', 'revoked'])"
    )
    if (
        registration_checks.get("ck_relay_node_registrations_status")
        != expected_registration_check
    ):
        raise RelaySchemaMismatchError("relay registration check constraints differ")

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
        "relay_node_registrations": {
            "relay_node_registrations_enrollment_id_key": ("enrollment_id",),
        },
        "relay_audit_events": {},
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
    expected_referred_schema = schema
    if expected_referred_schema is None:
        expected_referred_schema = sync_connection.scalar(
            text("SELECT current_schema()")
        )
    matching_foreign_keys = []
    for key in foreign_keys:
        options = key.get("options") or {}
        referred_schema = key.get("referred_schema") or expected_referred_schema
        if (
            key.get("name") == "relay_reservations_node_id_fkey"
            and tuple(key["constrained_columns"]) == ("node_id",)
            and referred_schema == expected_referred_schema
            and key["referred_table"] == "relay_nodes"
            and tuple(key["referred_columns"]) == ("node_id",)
            and options.get("ondelete") == "CASCADE"
            and options.get("deferrable") in {None, False}
            and options.get("initially") is None
        ):
            matching_foreign_keys.append(key)
    if len(foreign_keys) != 1 or len(matching_foreign_keys) != 1:
        raise RelaySchemaMismatchError("relay reservation foreign key differs")

    registration_foreign_keys = inspector.get_foreign_keys(
        "relay_node_registrations", schema=schema
    )
    if len(registration_foreign_keys) != 1:
        raise RelaySchemaMismatchError("relay registration foreign key differs")
    registration_key = registration_foreign_keys[0]
    registration_options = registration_key.get("options") or {}
    registration_schema = registration_key.get("referred_schema") or expected_referred_schema
    if (
        tuple(registration_key.get("constrained_columns") or ()) != ("enrollment_id",)
        or registration_schema != expected_referred_schema
        or registration_key.get("referred_table") != "relay_enrollments"
        or tuple(registration_key.get("referred_columns") or ()) != ("id",)
        or registration_options.get("ondelete") != "RESTRICT"
    ):
        raise RelaySchemaMismatchError("relay registration foreign key differs")

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
        "relay_node_registrations": {},
        "relay_audit_events": {
            "ix_relay_audit_events_node": ("node_id",),
            "ix_relay_audit_events_created": ("created_at",),
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
