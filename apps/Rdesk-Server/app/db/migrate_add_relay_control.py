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
_RELAY_SCHEMA_VERSIONS = (1, 2, 3, 4, 5, 6, 7)


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
    """Apply and verify relay schema through v6 in the caller's transaction."""
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
            physical_host_id VARCHAR(128),
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
            measured_rtt_ms BIGINT,
            recent_failure_bps INTEGER NOT NULL DEFAULT 0,
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
            ),
            CONSTRAINT ck_relay_nodes_measured_rtt CHECK (
                measured_rtt_ms IS NULL OR
                (measured_rtt_ms >= 0 AND measured_rtt_ms <= 4294967295)
            ),
            CONSTRAINT ck_relay_nodes_recent_failure CHECK (
                recent_failure_bps >= 0 AND recent_failure_bps <= 10000
            ),
            CONSTRAINT ck_relay_nodes_physical_host CHECK (
                physical_host_id IS NULL OR length(physical_host_id) BETWEEN 1 AND 128
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
            superseded_at TIMESTAMPTZ,
            directory_generation VARCHAR(64) NOT NULL DEFAULT 'legacy',
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
            physical_host_id VARCHAR(128),
            topology_approved_at TIMESTAMPTZ,
            endpoints JSONB NOT NULL,
            max_allocations INTEGER NOT NULL,
            max_egress_bps BIGINT NOT NULL,
            csr_pem BYTEA NOT NULL,
            signing_public_key BYTEA NOT NULL,
            encrypted_turn_secret BYTEA,
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
            ),
            CONSTRAINT ck_relay_node_registrations_topology CHECK (
                (topology_approved_at IS NULL AND physical_host_id IS NULL) OR
                (topology_approved_at IS NOT NULL AND physical_host_id IS NOT NULL)
            ),
            CONSTRAINT ck_relay_node_registrations_turn_secret CHECK (
                encrypted_turn_secret IS NULL OR length(encrypted_turn_secret) >= 30
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
        f"CREATE INDEX IF NOT EXISTS ix_relay_nodes_physical_host ON {nodes} (physical_host_id)",
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
    await connection.run_sync(
        lambda sync_connection: _assert_migration_ledger(
            sync_connection, schema, require_exact_versions=False
        )
    )
    v4_already_applied = bool(
        await connection.scalar(
            text(f"SELECT 1 FROM {versions} WHERE version = 4")
        )
    )

    # Later versions are deliberately additive so deployed schemas upgrade in
    # place while the advisory transaction lock serializes concurrent starters.
    for statement in (
        f"ALTER TABLE {nodes} ADD COLUMN IF NOT EXISTS "
        "healthy_heartbeat_streak INTEGER NOT NULL DEFAULT 0",
        f"ALTER TABLE {nodes} ADD COLUMN IF NOT EXISTS measured_rtt_ms BIGINT",
        f"ALTER TABLE {nodes} ADD COLUMN IF NOT EXISTS "
        "recent_failure_bps INTEGER NOT NULL DEFAULT 0",
        f"ALTER TABLE {nodes} ADD COLUMN IF NOT EXISTS physical_host_id VARCHAR(128)",
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
        f"ALTER TABLE {registrations} ADD COLUMN IF NOT EXISTS physical_host_id VARCHAR(128)",
        f"ALTER TABLE {registrations} ADD COLUMN IF NOT EXISTS topology_approved_at TIMESTAMPTZ",
        f"ALTER TABLE {registrations} ADD COLUMN IF NOT EXISTS encrypted_turn_secret BYTEA",
        f"ALTER TABLE {reservations} ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMPTZ",
        f"ALTER TABLE {reservations} ADD COLUMN IF NOT EXISTS "
        "directory_generation VARCHAR(64) NOT NULL DEFAULT 'legacy'",
    ):
        await connection.execute(text(statement))
    # v3 used previous_auth_expires_at for both old-certificate retry and
    # renewal-response retention. Preserve that exact (possibly already
    # expired) boundary for complete in-flight records when adding v4's split
    # clocks. Partial records stay fail-closed instead of becoming retryable.
    if not v4_already_applied:
        await connection.execute(
            text(
                f"""
                UPDATE {registrations}
                SET previous_certificate_expires_at = previous_auth_expires_at,
                    renewal_record_expires_at = previous_auth_expires_at
                WHERE previous_certificate_expires_at IS NULL
                  AND renewal_record_expires_at IS NULL
                  AND previous_auth_expires_at IS NOT NULL
                  AND renewal_request_id IS NOT NULL
                  AND renewal_csr_sha256 IS NOT NULL
                  AND renewal_certificate_pem IS NOT NULL
                  AND renewal_certificate_expires_at IS NOT NULL
                  AND ca_certificate_pem IS NOT NULL
                  AND previous_certificate_fingerprint IS NOT NULL
                  AND previous_signing_public_key IS NOT NULL
                """
            )
        )
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
    for name, expression in (
        (
            "ck_relay_nodes_measured_rtt",
            "measured_rtt_ms IS NULL OR "
            "(measured_rtt_ms >= 0 AND measured_rtt_ms <= 4294967295)",
        ),
        (
            "ck_relay_nodes_recent_failure",
            "recent_failure_bps >= 0 AND recent_failure_bps <= 10000",
        ),
        (
            "ck_relay_nodes_physical_host",
            "physical_host_id IS NULL OR length(physical_host_id) BETWEEN 1 AND 128",
        ),
    ):
        await connection.execute(
            text(
                f"""
                DO $$ BEGIN
                    ALTER TABLE {nodes} ADD CONSTRAINT {name} CHECK ({expression});
                EXCEPTION WHEN duplicate_object THEN NULL;
                END $$
                """
            )
        )
    for name, expression in (
        (
            "ck_relay_node_registrations_topology",
            "(topology_approved_at IS NULL AND physical_host_id IS NULL) OR "
            "(topology_approved_at IS NOT NULL AND physical_host_id IS NOT NULL)",
        ),
        (
            "ck_relay_node_registrations_turn_secret",
            "encrypted_turn_secret IS NULL OR length(encrypted_turn_secret) >= 30",
        ),
    ):
        await connection.execute(
            text(
                f"""
                DO $$ BEGIN
                    ALTER TABLE {registrations} ADD CONSTRAINT {name} CHECK ({expression});
                EXCEPTION WHEN duplicate_object THEN NULL;
                END $$
                """
            )
        )
    await connection.execute(
        text(
            f"CREATE INDEX IF NOT EXISTS ix_relay_nodes_physical_host "
            f"ON {nodes} (physical_host_id)"
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
    await connection.run_sync(
        lambda sync_connection: _assert_migration_ledger(
            sync_connection, schema, require_exact_versions=True
        )
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
        v5_additions = {
            "relay_nodes": {"measured_rtt_ms", "recent_failure_bps"},
        }.get(table_name, set())
        v6_additions = {
            "relay_nodes": {"physical_host_id"},
            "relay_node_registrations": {
                "physical_host_id", "topology_approved_at", "encrypted_turn_secret",
            },
        }.get(table_name, set())
        v7_additions = {
            "relay_reservations": {
                "superseded_at",
                "directory_generation",
            },
        }.get(table_name, set())
        allowed = (
            expected
            | v3_additions
            | v4_additions
            | v5_additions
            | v6_additions
            | v7_additions
        )
        if not expected.issubset(actual) or not actual.issubset(allowed):
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
    without_numeric_quotes = re.sub(r"'([0-9]+)'", r"\1", without_casts)
    return re.sub(r'[\s"]+', "", without_numeric_quotes)


def _normalize_server_default(value: object) -> str:
    if not isinstance(value, str):
        return ""
    normalized = _CHECK_CAST.sub("", value.strip().lower())
    while _has_single_outer_parentheses(normalized):
        normalized = normalized[1:-1].strip()
    normalized = re.sub(r"\s+", "", normalized)
    return "now()" if normalized == "current_timestamp" else normalized


def _has_single_outer_parentheses(value: str) -> bool:
    if len(value) < 2 or value[0] != "(" or value[-1] != ")":
        return False
    depth = 0
    for index, character in enumerate(value):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0 and index != len(value) - 1:
                return False
        if depth < 0:
            return False
    return depth == 0


def _assert_migration_ledger(
    sync_connection: object,
    schema: str | None,
    *,
    require_exact_versions: bool,
) -> None:
    inspector = inspect(sync_connection)
    table_name = "relay_schema_migrations"
    columns = {
        column["name"]: column
        for column in inspector.get_columns(table_name, schema=schema)
    }
    if set(columns) != {"version", "applied_at"}:
        raise RelaySchemaMismatchError("relay migration ledger columns differ")
    if (
        columns["version"]["nullable"] is not False
        or not isinstance(columns["version"]["type"], Integer)
        or isinstance(columns["version"]["type"], BigInteger)
        or columns["version"]["default"] is not None
        or columns["applied_at"]["nullable"] is not False
        or not _type_matches(columns["applied_at"]["type"], (DateTime, None))
        or _normalize_server_default(columns["applied_at"]["default"]) != "now()"
    ):
        raise RelaySchemaMismatchError("relay migration ledger columns differ")
    primary_key = inspector.get_pk_constraint(table_name, schema=schema)
    if (
        primary_key.get("name") != "relay_schema_migrations_pkey"
        or tuple(primary_key.get("constrained_columns") or ()) != ("version",)
    ):
        raise RelaySchemaMismatchError("relay migration ledger primary key differs")
    effective_schema = schema or sync_connection.scalar(
        text("SELECT current_schema()")
    )
    if not isinstance(effective_schema, str):
        raise RelaySchemaMismatchError("relay migration ledger schema differs")
    _assert_constraint_states(
        sync_connection,
        schema=effective_schema,
        table_name=table_name,
        expected_types={"relay_schema_migrations_pkey": "p"},
    )
    _assert_empty_semantic_objects(
        sync_connection,
        inspector,
        table_name,
        schema,
        current_schema=effective_schema,
    )
    table = _table(schema, table_name)
    actual_versions = set(
        sync_connection.execute(text(f"SELECT version FROM {table}")).scalars()
    )
    expected_versions = set(_RELAY_SCHEMA_VERSIONS)
    if (
        not actual_versions.issubset(expected_versions)
        or (require_exact_versions and actual_versions != expected_versions)
    ):
        raise RelaySchemaMismatchError("relay migration ledger versions differ")


def _index_matches(index: object, columns: tuple[str, ...]) -> bool:
    if not isinstance(index, dict):
        return False
    if tuple(index.get("column_names") or ()) != columns:
        return False
    if index.get("unique") is not False:
        return False
    sorting = index.get("column_sorting") or {}
    if any(
        any(option != "asc" for option in (options or ()))
        for options in sorting.values()
    ):
        return False
    dialect = index.get("dialect_options") or {}
    return not (
        index.get("include_columns")
        or dialect.get("postgresql_include")
        or dialect.get("postgresql_where") is not None
        or dialect.get("postgresql_ops")
    )


def _standalone_indexes(
    inspector: object, table_name: str, schema: str | None
) -> dict[str, dict[str, object]]:
    return {
        index["name"]: index
        for index in inspector.get_indexes(table_name, schema=schema)
        if not index.get("duplicates_constraint")
    }


def _index_access_method(
    connection: object, *, schema: str, index_name: str
) -> str | None:
    return connection.scalar(
        text(
            "SELECT am.amname FROM pg_class index_class "
            "JOIN pg_namespace namespace ON namespace.oid = index_class.relnamespace "
            "JOIN pg_am am ON am.oid = index_class.relam "
            "WHERE namespace.nspname = :schema AND index_class.relname = :name "
            "AND index_class.relkind = 'i'"
        ),
        {"schema": schema, "name": index_name},
    )


def _foreign_key_signature(
    key: dict[str, object], *, current_schema: str
) -> tuple[object, ...]:
    options = key.get("options") or {}
    return (
        key.get("name"),
        tuple(key.get("constrained_columns") or ()),
        key.get("referred_schema") or current_schema,
        key.get("referred_table"),
        tuple(key.get("referred_columns") or ()),
        str(options.get("ondelete") or "NO ACTION").upper(),
        str(options.get("onupdate") or "NO ACTION").upper(),
        bool(options.get("deferrable", False)),
        options.get("initially"),
        str(options.get("match") or "SIMPLE").upper(),
    )


def _assert_empty_semantic_objects(
    connection: object,
    inspector: object,
    table_name: str,
    schema: str | None,
    *,
    current_schema: str,
) -> None:
    if (
        inspector.get_check_constraints(table_name, schema=schema)
        or inspector.get_unique_constraints(table_name, schema=schema)
        or inspector.get_foreign_keys(table_name, schema=schema)
    ):
        raise RelaySchemaMismatchError(
            f"relay schema mismatch for {table_name}: semantic objects differ"
        )
    for name, index in _standalone_indexes(inspector, table_name, schema).items():
        columns = index.get("column_names")
        if (
            not isinstance(columns, list)
            or not columns
            or any(not isinstance(column, str) for column in columns)
            or not _index_matches(index, tuple(columns))
            or _index_access_method(
                connection, schema=current_schema, index_name=name
            )
            != "btree"
        ):
            raise RelaySchemaMismatchError(
                f"relay schema mismatch for {table_name}: semantic objects differ"
            )


def _constraint_states(
    connection: object, *, schema: str, table_name: str
) -> dict[str, tuple[str, bool, bool, bool]]:
    rows = connection.execute(
        text(
            "SELECT constraint_row.conname, constraint_row.contype, "
            "constraint_row.convalidated, constraint_row.condeferrable, "
            "constraint_row.condeferred FROM pg_constraint constraint_row "
            "JOIN pg_class table_row ON table_row.oid = constraint_row.conrelid "
            "JOIN pg_namespace namespace ON namespace.oid = table_row.relnamespace "
            "WHERE namespace.nspname = :schema AND table_row.relname = :table_name "
            "AND constraint_row.contype IN ('p', 'u', 'c', 'f', 'x')"
        ),
        {"schema": schema, "table_name": table_name},
    )
    return {
        str(row.conname): (
            row.contype.decode("ascii")
            if isinstance(row.contype, bytes)
            else str(row.contype),
            bool(row.convalidated),
            bool(row.condeferrable),
            bool(row.condeferred),
        )
        for row in rows
    }


def _assert_constraint_states(
    connection: object,
    *,
    schema: str,
    table_name: str,
    expected_types: dict[str, str],
) -> None:
    expected = {
        name: (constraint_type, True, False, False)
        for name, constraint_type in expected_types.items()
    }
    if _constraint_states(
        connection, schema=schema, table_name=table_name
    ) != expected:
        raise RelaySchemaMismatchError(
            f"relay schema mismatch for {table_name}: constraint states differ"
        )


def _assert_schema_conforms(sync_connection: object, schema: str | None) -> None:
    inspector = inspect(sync_connection)
    specs: dict[str, dict[str, tuple[type[object], int | None, bool]]] = {
        "relay_nodes": {
            "node_id": (String, 128, False),
            "region": (String, 64, False),
            "failure_domain": (String, 128, False),
            "physical_host_id": (String, 128, True),
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
            "measured_rtt_ms": (BigInteger, None, True),
            "recent_failure_bps": (Integer, None, False),
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
            "superseded_at": (DateTime, None, True),
            "directory_generation": (String, 64, False),
            "created_at": (DateTime, None, False),
        },
        "relay_node_registrations": {
            "node_id": (String, 128, False),
            "enrollment_id": (String, 36, False),
            "region": (String, 64, False),
            "failure_domain": (String, 128, False),
            "physical_host_id": (String, 128, True),
            "topology_approved_at": (DateTime, None, True),
            "endpoints": (JSONB, None, False),
            "max_allocations": (Integer, None, False),
            "max_egress_bps": (BigInteger, None, False),
            "csr_pem": (LargeBinary, None, False),
            "signing_public_key": (LargeBinary, None, False),
            "encrypted_turn_secret": (LargeBinary, None, True),
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

        expected_defaults: dict[str, str | None] = {
            name: None for name in expected_columns
        }
        if table_name == "relay_nodes":
            expected_defaults.update(
                {
                    "state": "'unavailable'",
                    "active_allocations": "0",
                    "current_egress_bps": "0",
                    "heartbeat_sequence": "0",
                    "healthy_heartbeat_streak": "0",
                    "recent_failure_bps": "0",
                }
            )
        elif table_name == "relay_node_registrations":
            expected_defaults["status"] = "'pending'"
        elif table_name == "relay_reservations":
            expected_defaults["directory_generation"] = "'legacy'"
        for name, expected_default in expected_defaults.items():
            actual_default = columns[name]["default"]
            if (
                actual_default is not None
                if expected_default is None
                else _normalize_server_default(actual_default) != expected_default
            ):
                raise RelaySchemaMismatchError(
                    f"relay schema mismatch for {table_name}.{name}: "
                    "server default differs"
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

    expected_checks = {
        "relay_nodes": {
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
            "ck_relay_nodes_measured_rtt": (
                "measured_rtt_ms IS NULL OR "
                "measured_rtt_ms >= 0 AND measured_rtt_ms <= 4294967295"
            ),
            "ck_relay_nodes_recent_failure": (
                "recent_failure_bps >= 0 AND recent_failure_bps <= 10000"
            ),
            "ck_relay_nodes_physical_host": (
                "physical_host_id IS NULL OR "
                "length(physical_host_id) >= 1 AND length(physical_host_id) <= 128"
            ),
        },
        "relay_enrollments": {},
        "relay_reservations": {},
        "relay_node_registrations": {
            "ck_relay_node_registrations_status": (
                "status = ANY (ARRAY['pending', 'approved', 'revoked'])"
            ),
            "ck_relay_node_registrations_topology": (
                "topology_approved_at IS NULL AND physical_host_id IS NULL OR "
                "topology_approved_at IS NOT NULL AND physical_host_id IS NOT NULL"
            ),
            "ck_relay_node_registrations_turn_secret": (
                "encrypted_turn_secret IS NULL OR length(encrypted_turn_secret) >= 30"
            ),
        },
        "relay_audit_events": {},
    }
    for table_name, expected in expected_checks.items():
        actual = {
            constraint["name"]: _normalize_check_expression(constraint["sqltext"])
            for constraint in inspector.get_check_constraints(
                table_name, schema=schema
            )
        }
        normalized_expected = {
            name: _normalize_check_expression(expression)
            for name, expression in expected.items()
        }
        if actual != normalized_expected:
            raise RelaySchemaMismatchError(
                f"relay schema mismatch for {table_name}: check constraints differ"
            )

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
        if actual != required:
            raise RelaySchemaMismatchError(
                f"relay schema mismatch for {table_name}: unique constraints differ"
            )

    expected_referred_schema = schema
    if expected_referred_schema is None:
        expected_referred_schema = sync_connection.scalar(
            text("SELECT current_schema()")
        )
    expected_foreign_keys = {
        "relay_nodes": set(),
        "relay_enrollments": set(),
        "relay_reservations": {
            (
                "relay_reservations_node_id_fkey", ("node_id",),
                expected_referred_schema, "relay_nodes", ("node_id",),
                "CASCADE", "NO ACTION", False, None, "SIMPLE",
            )
        },
        "relay_node_registrations": {
            (
                "relay_node_registrations_enrollment_id_fkey", ("enrollment_id",),
                expected_referred_schema, "relay_enrollments", ("id",),
                "RESTRICT", "NO ACTION", False, None, "SIMPLE",
            )
        },
        "relay_audit_events": set(),
    }
    for table_name, expected in expected_foreign_keys.items():
        actual = {
            _foreign_key_signature(key, current_schema=expected_referred_schema)
            for key in inspector.get_foreign_keys(table_name, schema=schema)
        }
        if actual != expected:
            raise RelaySchemaMismatchError(
                f"relay schema mismatch for {table_name}: foreign keys differ"
            )

    for table_name in specs:
        primary_key_name = expected_primary_keys[table_name][0]
        expected_constraint_types = {primary_key_name: "p"}
        expected_constraint_types.update(
            {name: "c" for name in expected_checks[table_name]}
        )
        expected_constraint_types.update(
            {name: "u" for name in expected_unique[table_name]}
        )
        expected_constraint_types.update(
            {
                str(signature[0]): "f"
                for signature in expected_foreign_keys[table_name]
            }
        )
        _assert_constraint_states(
            sync_connection,
            schema=expected_referred_schema,
            table_name=table_name,
            expected_types=expected_constraint_types,
        )

    expected_indexes = {
        "relay_nodes": {
            "ix_relay_nodes_region": ("region",),
            "ix_relay_nodes_state": ("state",),
            "ix_relay_nodes_lease": ("lease_expires_at",),
            "ix_relay_nodes_physical_host": ("physical_host_id",),
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
        actual = _standalone_indexes(inspector, table_name, schema)
        missing_or_changed = set(required) - set(actual) or any(
            not _index_matches(actual[name], columns)
            or _index_access_method(
                sync_connection,
                schema=expected_referred_schema,
                index_name=name,
            )
            != "btree"
            for name, columns in required.items()
        )
        operational_extras_are_safe = all(
            isinstance(index.get("column_names"), list)
            and bool(index["column_names"])
            and all(isinstance(column, str) for column in index["column_names"])
            and _index_matches(index, tuple(index["column_names"]))
            and _index_access_method(
                sync_connection,
                schema=expected_referred_schema,
                index_name=name,
            )
            == "btree"
            for name, index in actual.items()
            if name not in required
        )
        if missing_or_changed or not operational_extras_are_safe:
            raise RelaySchemaMismatchError(
                f"relay schema mismatch for {table_name}: indexes differ"
            )


def assert_relay_schema_conforms(
    sync_connection: object, schema: str | None = None
) -> None:
    """Validate the complete relay-control schema without mutating it."""
    _assert_schema_conforms(sync_connection, schema)


if __name__ == "__main__":
    asyncio.run(migrate())
