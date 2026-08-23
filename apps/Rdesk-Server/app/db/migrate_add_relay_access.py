from __future__ import annotations

import asyncio
import hashlib
import re

from sqlalchemy import BigInteger, Boolean, DateTime, Integer, LargeBinary, String, inspect, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from app.db.migrate_add_relay_control import (
    RelaySchemaMismatchError,
    assert_relay_schema_conforms,
)
from app.db.session import engine as default_engine


_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_CHECK_CAST = re.compile(
    r"::(?:character\s+varying|text|integer|bigint)(?:\[\])?",
    flags=re.IGNORECASE,
)
_LOCK_CONTEXT = b"MRD_RELAY_ACCESS_SCHEMA_MIGRATION_V1\x00"
_VERSIONS = (1, 2, 3)


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

    users = _table(schema, "users")
    devices = _table(schema, "devices")
    sessions = _table(schema, "session_requests")
    device_enrollments = _table(schema, "device_enrollments")
    versions = _table(schema, "relay_access_schema_migrations")
    await connection.execute(
        text(
            f"CREATE TABLE IF NOT EXISTS {versions} ("
            "version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
    )
    await connection.run_sync(
        lambda sync: _verify_migration_ledger(
            sync, schema, require_exact_versions=False
        )
    )
    required_tables = (
        "users", "devices", "session_requests", "relay_nodes",
        "relay_node_registrations", "relay_audit_events",
    )
    present = await connection.run_sync(
        lambda sync: {
            name: inspect(sync).has_table(name, schema=schema)
            for name in required_tables
        }
    )
    if not all(present.values()):
        raise RelayAccessMigrationError("relay access dependency table is unavailable")

    await connection.execute(
        text(
            f"""
            CREATE TABLE IF NOT EXISTS {device_enrollments} (
                id VARCHAR(36) PRIMARY KEY,
                token_digest VARCHAR(64) NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                consumed_at TIMESTAMPTZ,
                request_digest VARCHAR(64),
                registered_device_id VARCHAR(36),
                issued_by_user_id VARCHAR(36) NOT NULL,
                issued_at TIMESTAMPTZ NOT NULL,
                CONSTRAINT device_enrollments_token_digest_key
                    UNIQUE (token_digest),
                CONSTRAINT device_enrollments_registered_device_id_fkey
                    FOREIGN KEY (registered_device_id) REFERENCES {devices}(id)
                    ON DELETE RESTRICT,
                CONSTRAINT device_enrollments_issued_by_user_id_fkey
                    FOREIGN KEY (issued_by_user_id) REFERENCES {users}(id)
                    ON DELETE RESTRICT,
                CONSTRAINT ck_device_enrollments_token_digest
                    CHECK (length(token_digest) = 64),
                CONSTRAINT ck_device_enrollments_request_digest
                    CHECK (request_digest IS NULL OR length(request_digest) = 64),
                CONSTRAINT ck_device_enrollments_expiry
                    CHECK (expires_at > issued_at),
                CONSTRAINT ck_device_enrollments_consumed_bundle CHECK (
                    (consumed_at IS NULL AND request_digest IS NULL AND
                     registered_device_id IS NULL) OR
                    (consumed_at IS NOT NULL AND request_digest IS NOT NULL AND
                     registered_device_id IS NOT NULL)
                )
            )
            """
        )
    )
    await connection.execute(
        text(
            f"CREATE INDEX IF NOT EXISTS ix_device_enrollments_expiry "
            f"ON {device_enrollments} (expires_at)"
        )
    )

    for statement in (
        f"ALTER TABLE {users} ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64)",
        f"ALTER TABLE {devices} ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64)",
        f"ALTER TABLE {sessions} ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64)",
        f"ALTER TABLE {sessions} ADD COLUMN IF NOT EXISTS grant_expires_at TIMESTAMPTZ",
        f"ALTER TABLE {sessions} ADD COLUMN IF NOT EXISTS policy_revision BIGINT",
        f"ALTER TABLE {sessions} ADD COLUMN IF NOT EXISTS policy_expires_at TIMESTAMPTZ",
        f"ALTER TABLE {sessions} ADD COLUMN IF NOT EXISTS intended_peer_id VARCHAR(128)",
        f"ALTER TABLE {sessions} ADD COLUMN IF NOT EXISTS relay_allowed_regions JSONB",
        f"ALTER TABLE {sessions} ADD COLUMN IF NOT EXISTS relay_preferred_regions JSONB",
        f"ALTER TABLE {sessions} ADD COLUMN IF NOT EXISTS relay_accepted_transports JSONB",
    ):
        await connection.execute(text(statement))

    # Reject wrong historical types before any backfill can coerce or partially
    # rewrite a malformed deployment.
    await connection.run_sync(lambda sync: _verify_column_types(sync, schema))

    await connection.execute(text(f"UPDATE {users} SET tenant_id = 'default' WHERE tenant_id IS NULL"))
    await connection.execute(
        text(
            f"UPDATE {devices} d SET bound_user_id = NULL, is_bound = FALSE "
            f"WHERE d.bound_user_id IS NOT NULL AND NOT EXISTS ("
            f"SELECT 1 FROM {users} u WHERE u.id = d.bound_user_id)"
        )
    )
    # Historical rows with contradictory binding fields cannot establish a
    # trustworthy owner. Normalize them to unbound instead of elevating a
    # stale/caller-controlled owner reference into an active ownership grant.
    await connection.execute(
        text(
            f"UPDATE {devices} SET bound_user_id = NULL, is_bound = FALSE "
            "WHERE is_bound = FALSE AND bound_user_id IS NOT NULL"
        )
    )
    await connection.execute(
        text(
            f"UPDATE {devices} SET is_bound = FALSE "
            "WHERE is_bound = TRUE AND bound_user_id IS NULL"
        )
    )
    await connection.execute(
        text(
            f"UPDATE {devices} d SET tenant_id = u.tenant_id FROM {users} u "
            "WHERE d.bound_user_id = u.id AND d.tenant_id IS NULL"
        )
    )
    await connection.execute(text(f"UPDATE {devices} SET tenant_id = 'default' WHERE tenant_id IS NULL"))
    await connection.execute(
        text(
            f"UPDATE {sessions} s SET tenant_id = u.tenant_id FROM {users} u "
            "WHERE s.requester_user_id = u.id AND s.tenant_id IS NULL"
        )
    )
    await connection.execute(text(f"UPDATE {sessions} SET tenant_id = 'default' WHERE tenant_id IS NULL"))
    await connection.execute(text(f"UPDATE {sessions} SET status = 'requested' WHERE status IS NULL"))
    for table_name in (users, devices, sessions):
        await connection.execute(
            text(
                f"ALTER TABLE {table_name} ALTER COLUMN tenant_id SET DEFAULT 'default', "
                "ALTER COLUMN tenant_id SET NOT NULL"
            )
        )
    await connection.execute(
        text(
            f"ALTER TABLE {sessions} ALTER COLUMN status SET DEFAULT 'requested', "
            "ALTER COLUMN status SET NOT NULL"
        )
    )

    checks = (
        (users, f"{effective_schema}.users", "ck_users_tenant_id", "length(tenant_id) BETWEEN 1 AND 64"),
        (users, f"{effective_schema}.users", "ck_users_tenant_id_canonical", "tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'"),
        (devices, f"{effective_schema}.devices", "ck_devices_tenant_id", "length(tenant_id) BETWEEN 1 AND 64"),
        (devices, f"{effective_schema}.devices", "ck_devices_tenant_id_canonical", "tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'"),
        (devices, f"{effective_schema}.devices", "ck_devices_bound_owner", "(is_bound = FALSE AND bound_user_id IS NULL) OR (is_bound = TRUE AND bound_user_id IS NOT NULL)"),
        (sessions, f"{effective_schema}.session_requests", "ck_session_requests_tenant_id", "length(tenant_id) BETWEEN 1 AND 64"),
        (sessions, f"{effective_schema}.session_requests", "ck_session_requests_tenant_id_canonical", "tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'"),
        (sessions, f"{effective_schema}.session_requests", "ck_session_requests_status", "status IN ('requested', 'approved', 'rejected', 'expired')"),
        (sessions, f"{effective_schema}.session_requests", "ck_session_requests_policy_revision", "policy_revision IS NULL OR policy_revision > 0"),
        (sessions, f"{effective_schema}.session_requests", "ck_session_requests_approved_bundle", "status <> 'approved' OR (grant_expires_at IS NOT NULL AND policy_revision IS NOT NULL AND policy_expires_at IS NOT NULL AND intended_peer_id IS NOT NULL AND relay_allowed_regions IS NOT NULL AND relay_preferred_regions IS NOT NULL AND relay_accepted_transports IS NOT NULL)"),
    )
    for table_name, regclass, name, expression in checks:
        await _add_constraint(
            connection, table=table_name, regclass=regclass,
            name=name, expression=f"CHECK ({expression})",
        )

    await _add_constraint(
        connection,
        table=devices,
        regclass=f"{effective_schema}.devices",
        name="devices_bound_user_id_fkey",
        expression=f"FOREIGN KEY (bound_user_id) REFERENCES {users}(id) ON DELETE RESTRICT",
    )
    await _add_constraint(
        connection,
        table=sessions,
        regclass=f"{effective_schema}.session_requests",
        name="session_requests_intended_peer_id_fkey",
        expression=f"FOREIGN KEY (intended_peer_id) REFERENCES {devices}(id) ON DELETE CASCADE",
    )
    for statement in (
        f"CREATE INDEX IF NOT EXISTS ix_users_tenant_id ON {users} (tenant_id)",
        f"CREATE INDEX IF NOT EXISTS ix_devices_tenant_id ON {devices} (tenant_id)",
        f"CREATE INDEX IF NOT EXISTS ix_devices_bound_user_id ON {devices} (bound_user_id)",
        f"CREATE INDEX IF NOT EXISTS ix_session_requests_tenant_id ON {sessions} (tenant_id)",
    ):
        await connection.execute(text(statement))

    await connection.run_sync(lambda sync: _verify(sync, schema))
    for version in _VERSIONS:
        await connection.execute(
            text(
                f"INSERT INTO {versions} (version) VALUES (:version) "
                "ON CONFLICT (version) DO NOTHING"
            ),
            {"version": version},
        )
    await connection.run_sync(
        lambda sync: _verify_migration_ledger(
            sync, schema, require_exact_versions=True
        )
    )


def _type_matches(value: object, expected_type: type[object], length: int | None = None) -> bool:
    if not isinstance(value, expected_type):
        return False
    if length is not None and getattr(value, "length", None) != length:
        return False
    if expected_type is DateTime and not getattr(value, "timezone", False):
        return False
    return True


def _auth_specs() -> dict[str, dict[str, tuple[type[object], int | None, bool]]]:
    return {
        "users": {
            "id": (String, 36, False),
            "tenant_id": (String, 64, False),
        },
        "devices": {
            "id": (String, 36, False),
            "is_bound": (Boolean, None, False),
            "bound_user_id": (String, 36, True),
            "tenant_id": (String, 64, False),
        },
        "session_requests": {
            "id": (String, 36, False),
            "requester_user_id": (String, 36, False),
            "target_device_id": (String, 36, False),
            "signaling_room": (String, 128, False),
            "tenant_id": (String, 64, False),
            "status": (String, 24, False),
            "grant_expires_at": (DateTime, None, True),
            "policy_revision": (BigInteger, None, True),
            "policy_expires_at": (DateTime, None, True),
            "intended_peer_id": (String, 128, True),
            "relay_allowed_regions": (JSONB, None, True),
            "relay_preferred_regions": (JSONB, None, True),
            "relay_accepted_transports": (JSONB, None, True),
        },
    }


def _verify_column_types(connection: object, schema: str | None) -> None:
    inspector = inspect(connection)
    # Tenant columns may still be nullable during the additive/backfill phase.
    for table_name, expected in _auth_specs().items():
        columns = {
            column["name"]: column
            for column in inspector.get_columns(table_name, schema=schema)
        }
        for name, (expected_type, length, _) in expected.items():
            column = columns.get(name)
            if column is None or not _type_matches(column["type"], expected_type, length):
                raise RelayAccessMigrationError(
                    f"relay access schema type differs for {table_name}.{name}"
                )


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


def _verify_migration_ledger(
    connection: object,
    schema: str | None,
    *,
    require_exact_versions: bool,
) -> None:
    inspector = inspect(connection)
    table_name = "relay_access_schema_migrations"
    columns = {
        column["name"]: column
        for column in inspector.get_columns(table_name, schema=schema)
    }
    if set(columns) != {"version", "applied_at"}:
        raise RelayAccessMigrationError("relay access migration ledger columns differ")
    if (
        columns["version"]["nullable"] is not False
        or not isinstance(columns["version"]["type"], Integer)
        or isinstance(columns["version"]["type"], BigInteger)
        or columns["version"]["default"] is not None
        or columns["applied_at"]["nullable"] is not False
        or not _type_matches(columns["applied_at"]["type"], DateTime)
        or _normalize_server_default(columns["applied_at"]["default"]) != "now()"
    ):
        raise RelayAccessMigrationError("relay access migration ledger columns differ")
    primary_key = inspector.get_pk_constraint(table_name, schema=schema)
    if (
        primary_key.get("name") != "relay_access_schema_migrations_pkey"
        or tuple(primary_key.get("constrained_columns") or ()) != ("version",)
    ):
        raise RelayAccessMigrationError(
            "relay access migration ledger primary key differs"
        )
    effective_schema = schema or connection.scalar(text("SELECT current_schema()"))
    if not isinstance(effective_schema, str):
        raise RelayAccessMigrationError(
            "relay access migration ledger schema differs"
        )
    _assert_constraint_states(
        connection,
        schema=effective_schema,
        table_name=table_name,
        expected_types={"relay_access_schema_migrations_pkey": "p"},
        exact=True,
    )
    _assert_no_semantic_objects(inspector, table_name, schema)
    table = _table(schema, table_name)
    actual_versions = set(
        connection.execute(text(f"SELECT version FROM {table}")).scalars()
    )
    expected_versions = set(_VERSIONS)
    if (
        not actual_versions.issubset(expected_versions)
        or (require_exact_versions and actual_versions != expected_versions)
    ):
        raise RelayAccessMigrationError("relay access migration ledger versions differ")


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


def _assert_no_semantic_objects(
    inspector: object, table_name: str, schema: str | None
) -> None:
    if (
        inspector.get_check_constraints(table_name, schema=schema)
        or inspector.get_unique_constraints(table_name, schema=schema)
        or inspector.get_foreign_keys(table_name, schema=schema)
        or _standalone_indexes(inspector, table_name, schema)
    ):
        raise RelayAccessMigrationError(
            f"relay access schema differs for {table_name} semantic objects"
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
    exact: bool,
) -> None:
    actual = _constraint_states(
        connection, schema=schema, table_name=table_name
    )
    expected = {
        name: (constraint_type, True, False, False)
        for name, constraint_type in expected_types.items()
    }
    differs = actual != expected if exact else any(
        actual.get(name) != state for name, state in expected.items()
    )
    if differs:
        raise RelayAccessMigrationError(
            f"relay access schema differs for {table_name} constraint states"
        )


def _verify_device_enrollment_table(
    connection: object, schema: str | None, *, current_schema: str
) -> None:
    inspector = inspect(connection)
    table_name = "device_enrollments"
    expected_columns = {
        "id": (String, 36, False),
        "token_digest": (String, 64, False),
        "expires_at": (DateTime, None, False),
        "consumed_at": (DateTime, None, True),
        "request_digest": (String, 64, True),
        "registered_device_id": (String, 36, True),
        "issued_by_user_id": (String, 36, False),
        "issued_at": (DateTime, None, False),
    }
    columns = {
        column["name"]: column
        for column in inspector.get_columns(table_name, schema=schema)
    }
    if set(columns) != set(expected_columns):
        raise RelayAccessMigrationError(
            "relay access device enrollment columns differ"
        )
    for name, (expected_type, length, nullable) in expected_columns.items():
        column = columns[name]
        if (
            column["nullable"] is not nullable
            or not _type_matches(column["type"], expected_type, length)
            or column["default"] is not None
        ):
            raise RelayAccessMigrationError(
                f"relay access device enrollment differs for {name}"
            )
    primary_key = inspector.get_pk_constraint(table_name, schema=schema)
    if (
        primary_key.get("name") != "device_enrollments_pkey"
        or tuple(primary_key.get("constrained_columns") or ()) != ("id",)
    ):
        raise RelayAccessMigrationError(
            "relay access device enrollment primary key differs"
        )

    expected_checks = {
        "ck_device_enrollments_token_digest": "length(token_digest) = 64",
        "ck_device_enrollments_request_digest": (
            "request_digest IS NULL OR length(request_digest) = 64"
        ),
        "ck_device_enrollments_expiry": "expires_at > issued_at",
        "ck_device_enrollments_consumed_bundle": (
            "consumed_at IS NULL AND request_digest IS NULL AND "
            "registered_device_id IS NULL OR "
            "consumed_at IS NOT NULL AND request_digest IS NOT NULL AND "
            "registered_device_id IS NOT NULL"
        ),
    }
    actual_checks = {
        constraint["name"]: _normalize_check_expression(constraint["sqltext"])
        for constraint in inspector.get_check_constraints(
            table_name, schema=schema
        )
    }
    normalized_expected_checks = {
        name: _normalize_check_expression(expression)
        for name, expression in expected_checks.items()
    }
    if actual_checks != normalized_expected_checks:
        raise RelayAccessMigrationError(
            "relay access device enrollment checks differ"
        )

    actual_unique = {
        constraint["name"]: tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints(
            table_name, schema=schema
        )
    }
    if actual_unique != {
        "device_enrollments_token_digest_key": ("token_digest",)
    }:
        raise RelayAccessMigrationError(
            "relay access device enrollment unique constraints differ"
        )

    expected_foreign_keys = {
        (
            "device_enrollments_registered_device_id_fkey",
            ("registered_device_id",), current_schema, "devices", ("id",),
            "RESTRICT", "NO ACTION", False, None, "SIMPLE",
        ),
        (
            "device_enrollments_issued_by_user_id_fkey",
            ("issued_by_user_id",), current_schema, "users", ("id",),
            "RESTRICT", "NO ACTION", False, None, "SIMPLE",
        ),
    }
    actual_foreign_keys = {
        _foreign_key_signature(key, current_schema=current_schema)
        for key in inspector.get_foreign_keys(table_name, schema=schema)
    }
    if actual_foreign_keys != expected_foreign_keys:
        raise RelayAccessMigrationError(
            "relay access device enrollment foreign keys differ"
        )

    _assert_constraint_states(
        connection,
        schema=current_schema,
        table_name=table_name,
        expected_types={
            "device_enrollments_pkey": "p",
            "device_enrollments_token_digest_key": "u",
            **{name: "c" for name in expected_checks},
            **{str(signature[0]): "f" for signature in expected_foreign_keys},
        },
        exact=True,
    )

    indexes = _standalone_indexes(inspector, table_name, schema)
    if set(indexes) != {"ix_device_enrollments_expiry"} or not _index_matches(
        indexes["ix_device_enrollments_expiry"], ("expires_at",)
    ) or _index_access_method(
        connection,
        schema=current_schema,
        index_name="ix_device_enrollments_expiry",
    ) != "btree":
        raise RelayAccessMigrationError(
            "relay access device enrollment indexes differ"
        )


def _verify(connection: object, schema: str | None) -> None:
    inspector = inspect(connection)
    effective_schema = schema or connection.scalar(text("SELECT current_schema()"))
    if not isinstance(effective_schema, str):
        raise RelayAccessMigrationError("relay access schema is invalid")
    try:
        assert_relay_schema_conforms(connection, schema)
    except RelaySchemaMismatchError as error:
        raise RelayAccessMigrationError(
            "relay access control schema differs"
        ) from error
    _verify_device_enrollment_table(
        connection, schema, current_schema=effective_schema
    )
    for table_name, expected in _auth_specs().items():
        columns = {
            column["name"]: column
            for column in inspector.get_columns(table_name, schema=schema)
        }
        for name, (expected_type, length, nullable) in expected.items():
            column = columns.get(name)
            if (
                column is None
                or column["nullable"] is not nullable
                or not _type_matches(column["type"], expected_type, length)
            ):
                raise RelayAccessMigrationError(
                    f"relay access schema differs for {table_name}.{name}"
                )
        if _normalize_server_default(columns["tenant_id"]["default"]) != "'default'":
            raise RelayAccessMigrationError(
                f"relay access tenant default differs for {table_name}"
            )
        no_default_columns = {
            "session_requests": {
                "grant_expires_at",
                "policy_revision",
                "policy_expires_at",
                "intended_peer_id",
                "relay_allowed_regions",
                "relay_preferred_regions",
                "relay_accepted_transports",
            }
        }.get(table_name, set())
        if any(columns[name]["default"] is not None for name in no_default_columns):
            raise RelayAccessMigrationError(
                f"relay access server defaults differ for {table_name}"
            )
    session_columns = {
        column["name"]: column
        for column in inspector.get_columns("session_requests", schema=schema)
    }
    if _normalize_server_default(session_columns["status"]["default"]) != "'requested'":
        raise RelayAccessMigrationError("relay session status default differs")

    required_checks = {
        "users": {
            "ck_users_tenant_id": "length(tenant_id) >= 1 AND length(tenant_id) <= 64",
            "ck_users_tenant_id_canonical": "tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'",
        },
        "devices": {
            "ck_devices_tenant_id": "length(tenant_id) >= 1 AND length(tenant_id) <= 64",
            "ck_devices_tenant_id_canonical": "tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'",
            "ck_devices_bound_owner": "is_bound = FALSE AND bound_user_id IS NULL OR is_bound = TRUE AND bound_user_id IS NOT NULL",
        },
        "session_requests": {
            "ck_session_requests_tenant_id": "length(tenant_id) >= 1 AND length(tenant_id) <= 64",
            "ck_session_requests_tenant_id_canonical": "tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'",
            "ck_session_requests_status": (
                "status = ANY (ARRAY['requested', 'approved', 'rejected', 'expired'])"
            ),
            "ck_session_requests_policy_revision": "policy_revision IS NULL OR policy_revision > 0",
            "ck_session_requests_approved_bundle": "status <> 'approved' OR grant_expires_at IS NOT NULL AND policy_revision IS NOT NULL AND policy_expires_at IS NOT NULL AND intended_peer_id IS NOT NULL AND relay_allowed_regions IS NOT NULL AND relay_preferred_regions IS NOT NULL AND relay_accepted_transports IS NOT NULL",
        },
    }
    for table_name, expected in required_checks.items():
        checks = {
            item["name"]: _normalize_check_expression(item["sqltext"])
            for item in inspector.get_check_constraints(table_name, schema=schema)
        }
        if any(
            checks.get(name) != _normalize_check_expression(expression)
            for name, expression in expected.items()
        ):
            raise RelayAccessMigrationError(
                f"relay access checks differ for {table_name}"
            )

    _verify_foreign_key(
        inspector, schema, expected_schema=effective_schema,
        table="devices", name="devices_bound_user_id_fkey",
        constrained=("bound_user_id",), referred_table="users",
        referred=("id",), ondelete="RESTRICT",
    )
    for name, constrained, referred_table, referred, ondelete in (
        ("session_requests_requester_user_id_fkey", ("requester_user_id",), "users", ("id",), "CASCADE"),
        ("session_requests_target_device_id_fkey", ("target_device_id",), "devices", ("id",), "CASCADE"),
        ("session_requests_intended_peer_id_fkey", ("intended_peer_id",), "devices", ("id",), "CASCADE"),
    ):
        _verify_foreign_key(
            inspector, schema, expected_schema=effective_schema,
            table="session_requests", name=name,
            constrained=constrained, referred_table=referred_table,
            referred=referred, ondelete=ondelete,
        )

    required_constraint_types = {
        "users": {name: "c" for name in required_checks["users"]},
        "devices": {
            **{name: "c" for name in required_checks["devices"]},
            "devices_bound_user_id_fkey": "f",
        },
        "session_requests": {
            **{name: "c" for name in required_checks["session_requests"]},
            "session_requests_requester_user_id_fkey": "f",
            "session_requests_target_device_id_fkey": "f",
            "session_requests_intended_peer_id_fkey": "f",
        },
    }
    for table_name, expected_types in required_constraint_types.items():
        _assert_constraint_states(
            connection,
            schema=effective_schema,
            table_name=table_name,
            expected_types=expected_types,
            exact=False,
        )

    required_indexes = {
        "users": {"ix_users_tenant_id": ("tenant_id",)},
        "devices": {
            "ix_devices_tenant_id": ("tenant_id",),
            "ix_devices_bound_user_id": ("bound_user_id",),
        },
        "session_requests": {
            "ix_session_requests_tenant_id": ("tenant_id",),
            "ix_session_requests_requester_user_id": ("requester_user_id",),
            "ix_session_requests_target_device_id": ("target_device_id",),
        },
    }
    for table_name, expected in required_indexes.items():
        actual = {
            item["name"]: item
            for item in inspector.get_indexes(table_name, schema=schema)
        }
        if any(
            not _index_matches(actual.get(name), columns)
            or _index_access_method(
                connection, schema=effective_schema, index_name=name
            )
            != "btree"
            for name, columns in expected.items()
        ):
            raise RelayAccessMigrationError(
                f"relay access indexes differ for {table_name}"
            )

    relay_specs = {
        "relay_nodes": {
            "measured_rtt_ms": (BigInteger, None, True),
            "recent_failure_bps": (Integer, None, False),
            "physical_host_id": (String, 128, True),
        },
        "relay_node_registrations": {
            "physical_host_id": (String, 128, True),
            "topology_approved_at": (DateTime, None, True),
            "encrypted_turn_secret": (LargeBinary, None, True),
        },
    }
    for table_name, expected in relay_specs.items():
        columns = {
            column["name"]: column
            for column in inspector.get_columns(table_name, schema=schema)
        }
        for name, (expected_type, length, nullable) in expected.items():
            column = columns.get(name)
            if column is None or column["nullable"] is not nullable or not _type_matches(
                column["type"], expected_type, length
            ):
                raise RelayAccessMigrationError("relay topology/metric schema differs")
        expected_defaults = {
            "relay_nodes": {
                "measured_rtt_ms": None,
                "recent_failure_bps": "0",
                "physical_host_id": None,
            },
            "relay_node_registrations": {
                "physical_host_id": None,
                "topology_approved_at": None,
                "encrypted_turn_secret": None,
            },
        }[table_name]
        for name, expected_default in expected_defaults.items():
            actual_default = columns[name]["default"]
            if (
                actual_default is not None
                if expected_default is None
                else _normalize_server_default(actual_default) != expected_default
            ):
                raise RelayAccessMigrationError(
                    "relay topology/metric server defaults differ"
                )
    relay_checks = {
        item["name"]: _normalize_check_expression(item["sqltext"])
        for item in inspector.get_check_constraints("relay_nodes", schema=schema)
    }
    expected_relay_checks = {
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
    }
    if any(
        relay_checks.get(name) != _normalize_check_expression(expression)
        for name, expression in expected_relay_checks.items()
    ):
        raise RelayAccessMigrationError("relay topology/metric checks differ")
    registration_checks = {
        item["name"]: _normalize_check_expression(item["sqltext"])
        for item in inspector.get_check_constraints(
            "relay_node_registrations", schema=schema
        )
    }
    expected_registration_checks = {
        "ck_relay_node_registrations_topology": (
            "topology_approved_at IS NULL AND physical_host_id IS NULL OR "
            "topology_approved_at IS NOT NULL AND physical_host_id IS NOT NULL"
        ),
        "ck_relay_node_registrations_turn_secret": (
            "encrypted_turn_secret IS NULL OR length(encrypted_turn_secret) >= 30"
        ),
    }
    if any(
        registration_checks.get(name) != _normalize_check_expression(expression)
        for name, expression in expected_registration_checks.items()
    ):
        raise RelayAccessMigrationError("relay registration checks differ")
    relay_indexes = {
        item["name"]: item
        for item in inspector.get_indexes("relay_nodes", schema=schema)
    }
    if not _index_matches(
        relay_indexes.get("ix_relay_nodes_physical_host"),
        ("physical_host_id",),
    ) or _index_access_method(
        connection,
        schema=effective_schema,
        index_name="ix_relay_nodes_physical_host",
    ) != "btree":
        raise RelayAccessMigrationError("relay topology indexes differ")


def _verify_foreign_key(
    inspector: object,
    schema: str | None,
    *,
    expected_schema: str,
    table: str,
    name: str,
    constrained: tuple[str, ...],
    referred_table: str,
    referred: tuple[str, ...],
    ondelete: str,
) -> None:
    keys = {
        key.get("name"): key
        for key in inspector.get_foreign_keys(table, schema=schema)
    }
    key = keys.get(name)
    options = (key or {}).get("options") or {}
    referred_schema = (key or {}).get("referred_schema") or expected_schema
    if (
        key is None
        or tuple(key.get("constrained_columns") or ()) != constrained
        or key.get("referred_table") != referred_table
        or referred_schema != expected_schema
        or tuple(key.get("referred_columns") or ()) != referred
        or options.get("ondelete") != ondelete
        or str(options.get("onupdate") or "NO ACTION").upper() != "NO ACTION"
        or options.get("deferrable") not in {None, False}
        or options.get("initially") is not None
        or str(options.get("match") or "SIMPLE").upper() != "SIMPLE"
    ):
        raise RelayAccessMigrationError(
            f"relay access foreign key differs for {table}.{name}"
        )


async def _add_constraint(
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
            text(f"ALTER TABLE {table} ADD CONSTRAINT {name} {expression}")
        )


def _lock_key(schema: str) -> int:
    digest = hashlib.sha256(_LOCK_CONTEXT + schema.encode("ascii")).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


if __name__ == "__main__":
    asyncio.run(migrate())
