from __future__ import annotations

import asyncio
import hashlib
import hmac
import re

from sqlalchemy import BigInteger, Boolean, DateTime, Integer, LargeBinary, String, inspect, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine
from pydantic import SecretStr

from app.db.migrate_add_relay_control import (
    RelaySchemaMismatchError,
    assert_relay_schema_conforms,
)
from app.db.session import engine as default_engine
from app.services.device_enrollment import device_serial_digest


_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_CHECK_CAST = re.compile(
    r"::(?:character\s+varying|text|integer|bigint)(?:\[\])?",
    flags=re.IGNORECASE,
)
_LOCK_CONTEXT = b"MRD_RELAY_ACCESS_SCHEMA_MIGRATION_V1\x00"
_VERSIONS = (1, 2, 3, 4, 5)


class RelayAccessMigrationError(RuntimeError):
    pass


def _table(schema: str | None, name: str) -> str:
    if schema is None:
        return name
    if _IDENTIFIER.fullmatch(schema) is None:
        raise ValueError("invalid database schema identifier")
    return f'"{schema}".{name}'


def _qualified_index(schema: str | None, name: str) -> str:
    if schema is None:
        return name
    if _IDENTIFIER.fullmatch(schema) is None or _IDENTIFIER.fullmatch(name) is None:
        raise ValueError("invalid database identifier")
    return f'"{schema}".{name}'


async def migrate(
    bind: AsyncEngine | AsyncConnection = default_engine,
    *,
    schema: str | None = None,
    serial_pepper: bytes | str | SecretStr | None = None,
) -> None:
    if isinstance(bind, AsyncEngine):
        async with bind.begin() as connection:
            await _migrate_connection(
                connection, schema=schema, serial_pepper=serial_pepper
            )
        return
    await _migrate_connection(bind, schema=schema, serial_pepper=serial_pepper)


async def _migrate_connection(
    connection: AsyncConnection,
    *,
    schema: str | None,
    serial_pepper: bytes | str | SecretStr | None,
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
    reservations = _table(schema, "relay_reservations")
    versions = _table(schema, "relay_access_schema_migrations")
    ledger_exists = await connection.run_sync(
        lambda sync: inspect(sync).has_table(
            "relay_access_schema_migrations", schema=schema
        )
    )
    if not ledger_exists:
        await connection.execute(
            text(
                f"CREATE TABLE {versions} ("
                "version INTEGER PRIMARY KEY, "
                "applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
            )
        )
    await connection.run_sync(
        lambda sync: _verify_migration_ledger(
            sync, schema, require_exact_versions=False
        )
    )
    applied_versions = set(
        (
            await connection.execute(
                text(f"SELECT version FROM {versions}")
            )
        ).scalars()
    )
    if applied_versions == set(_VERSIONS):
        # Steady-state startup is read-only after the advisory lock. This is a
        # schema verification path, never a repeated table-wide backfill.
        await connection.run_sync(lambda sync: _verify(sync, schema))
        return
    supported_upgrade_states = (
        set(),
        {1, 2, 3},
        {1, 2, 3, 4},
    )
    if applied_versions not in supported_upgrade_states:
        # Versions 1-3 shipped as one atomic legacy migration. A partial legacy
        # set cannot be produced by that transaction and is therefore drift, not
        # a resumable state. This also makes every future/unknown version fail
        # before any application table is changed.
        raise RelayAccessMigrationError(
            "relay access migration ledger versions differ"
        )
    apply_legacy_access = not applied_versions
    apply_device_identity = 4 not in applied_versions
    apply_directory_lifecycle = 5 not in applied_versions
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

    if apply_legacy_access:
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

    legacy_statements = (
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
    )
    device_identity_statements = (
        f"ALTER TABLE {devices} ADD COLUMN IF NOT EXISTS "
        "motherboard_serial_digest VARCHAR(64)",
        f"ALTER TABLE {devices} ADD COLUMN IF NOT EXISTS auth_version INTEGER",
        f"ALTER TABLE {devices} ADD COLUMN IF NOT EXISTS "
        "auth_revoked_at TIMESTAMPTZ",
    )
    directory_lifecycle_statements = (
        f"ALTER TABLE {reservations} ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMPTZ",
        f"ALTER TABLE {reservations} ADD COLUMN IF NOT EXISTS "
        "directory_generation VARCHAR(64)",
    )
    for statement in (
        (legacy_statements if apply_legacy_access else ())
        + (device_identity_statements if apply_device_identity else ())
        + (directory_lifecycle_statements if apply_directory_lifecycle else ())
    ):
        await connection.execute(text(statement))

    # Reject wrong historical types before any backfill can coerce or partially
    # rewrite a malformed deployment.
    await connection.run_sync(lambda sync: _verify_column_types(sync, schema))
    legacy_session_status = await connection.run_sync(
        lambda sync: _session_status_constraint_is_legacy(sync, schema)
    )

    contradictory_owners = int(
        await connection.scalar(
            text(
                f"SELECT count(*) FROM {devices} d WHERE "
                "(d.is_bound = FALSE AND d.bound_user_id IS NOT NULL) OR "
                "(d.is_bound = TRUE AND d.bound_user_id IS NULL) OR "
                "(d.bound_user_id IS NOT NULL AND NOT EXISTS ("
                f"SELECT 1 FROM {users} u WHERE u.id = d.bound_user_id))"
            )
        )
        or 0
    )
    if contradictory_owners:
        raise RelayAccessMigrationError(
            "relay access ownership remediation required for "
            f"{contradictory_owners} device row(s); run the offline ownership "
            "remediation before startup"
        )
    if apply_legacy_access:
        await connection.execute(
            text(f"UPDATE {users} SET tenant_id = 'default' WHERE tenant_id IS NULL")
        )
        await connection.execute(
            text(
                f"UPDATE {devices} d SET tenant_id = u.tenant_id FROM {users} u "
                "WHERE d.bound_user_id = u.id AND d.tenant_id IS NULL"
            )
        )
        await connection.execute(
            text(f"UPDATE {devices} SET tenant_id = 'default' WHERE tenant_id IS NULL")
        )
        await connection.execute(
            text(
                f"UPDATE {sessions} s SET tenant_id = u.tenant_id FROM {users} u "
                "WHERE s.requester_user_id = u.id AND s.tenant_id IS NULL"
            )
        )
        await connection.execute(
            text(f"UPDATE {sessions} SET tenant_id = 'default' WHERE tenant_id IS NULL")
        )
        await connection.execute(
            text(f"UPDATE {sessions} SET status = 'requested' WHERE status IS NULL")
        )
        for table_name in (users, devices, sessions):
            await connection.execute(
                text(
                    f"ALTER TABLE {table_name} "
                    "ALTER COLUMN tenant_id SET DEFAULT 'default', "
                    "ALTER COLUMN tenant_id SET NOT NULL"
                )
            )
        await connection.execute(
            text(
                f"ALTER TABLE {sessions} "
                "ALTER COLUMN status SET DEFAULT 'requested', "
                "ALTER COLUMN status SET NOT NULL"
            )
        )
    if apply_device_identity:
        await _backfill_device_serial_digests(
            connection,
            devices=devices,
            serial_pepper=_configured_serial_pepper(serial_pepper),
        )
        await connection.execute(
            text(f"UPDATE {devices} SET auth_version = 1 WHERE auth_version IS NULL")
        )
        await connection.execute(
            text(
                f"ALTER TABLE {devices} ALTER COLUMN auth_version SET DEFAULT 1, "
                "ALTER COLUMN auth_version SET NOT NULL"
            )
        )
        await connection.execute(
            text(
                f"DROP INDEX IF EXISTS "
                f"{_qualified_index(schema, 'ix_devices_motherboard_serial')}"
            )
        )
    if apply_directory_lifecycle:
        await connection.execute(
            text(
                f"UPDATE {reservations} SET directory_generation = 'legacy' "
                "WHERE directory_generation IS NULL"
            )
        )
        await connection.execute(
            text(
                f"ALTER TABLE {reservations} "
                "ALTER COLUMN directory_generation SET DEFAULT 'legacy', "
                "ALTER COLUMN directory_generation SET NOT NULL"
            )
        )

    checks = (
        (users, f"{effective_schema}.users", "ck_users_tenant_id", "length(tenant_id) BETWEEN 1 AND 64"),
        (users, f"{effective_schema}.users", "ck_users_tenant_id_canonical", "tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'"),
        (devices, f"{effective_schema}.devices", "ck_devices_tenant_id", "length(tenant_id) BETWEEN 1 AND 64"),
        (devices, f"{effective_schema}.devices", "ck_devices_tenant_id_canonical", "tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'"),
        (devices, f"{effective_schema}.devices", "ck_devices_bound_owner", "(is_bound = FALSE AND bound_user_id IS NULL) OR (is_bound = TRUE AND bound_user_id IS NOT NULL)"),
        (devices, f"{effective_schema}.devices", "ck_devices_auth_version", "auth_version >= 1"),
        (devices, f"{effective_schema}.devices", "ck_devices_serial_digest", "motherboard_serial_digest IS NULL OR length(motherboard_serial_digest) = 64"),
        (devices, f"{effective_schema}.devices", "ck_devices_plaintext_serial_cleared", "motherboard_serial IS NULL"),
        (sessions, f"{effective_schema}.session_requests", "ck_session_requests_tenant_id", "length(tenant_id) BETWEEN 1 AND 64"),
        (sessions, f"{effective_schema}.session_requests", "ck_session_requests_tenant_id_canonical", "tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'"),
        (sessions, f"{effective_schema}.session_requests", "ck_session_requests_status", "status IN ('requested', 'approved', 'rejected', 'expired', 'closed', 'revoked')"),
        (sessions, f"{effective_schema}.session_requests", "ck_session_requests_policy_revision", "policy_revision IS NULL OR policy_revision > 0"),
        (sessions, f"{effective_schema}.session_requests", "ck_session_requests_approved_bundle", "status <> 'approved' OR (grant_expires_at IS NOT NULL AND policy_revision IS NOT NULL AND policy_expires_at IS NOT NULL AND intended_peer_id IS NOT NULL AND relay_allowed_regions IS NOT NULL AND relay_preferred_regions IS NOT NULL AND relay_accepted_transports IS NOT NULL)"),
    )
    for table_name, regclass, name, expression in checks:
        should_apply = (
            (name == "ck_session_requests_status" and (
                apply_legacy_access or apply_directory_lifecycle
            ))
            or (name in {
                "ck_devices_auth_version",
                "ck_devices_serial_digest",
                "ck_devices_plaintext_serial_cleared",
            } and apply_device_identity)
            or (name not in {
                "ck_session_requests_status",
                "ck_devices_auth_version",
                "ck_devices_serial_digest",
                "ck_devices_plaintext_serial_cleared",
            } and apply_legacy_access)
        )
        if not should_apply:
            continue
        if name == "ck_session_requests_status" and legacy_session_status:
            await connection.execute(
                text(f"ALTER TABLE {sessions} DROP CONSTRAINT IF EXISTS {name}")
            )
        await _add_constraint(
            connection, table=table_name, regclass=regclass,
            name=name, expression=f"CHECK ({expression})",
        )

    if apply_legacy_access:
        await _add_constraint(
            connection,
            table=devices,
            regclass=f"{effective_schema}.devices",
            name="devices_bound_user_id_fkey",
            expression=(
                f"FOREIGN KEY (bound_user_id) REFERENCES {users}(id) "
                "ON DELETE RESTRICT"
            ),
        )
        await _add_constraint(
            connection,
            table=sessions,
            regclass=f"{effective_schema}.session_requests",
            name="session_requests_intended_peer_id_fkey",
            expression=(
                f"FOREIGN KEY (intended_peer_id) REFERENCES {devices}(id) "
                "ON DELETE CASCADE"
            ),
        )
    legacy_indexes = (
        f"CREATE INDEX IF NOT EXISTS ix_users_tenant_id ON {users} (tenant_id)",
        f"CREATE INDEX IF NOT EXISTS ix_devices_tenant_id ON {devices} (tenant_id)",
        f"CREATE INDEX IF NOT EXISTS ix_devices_bound_user_id ON {devices} (bound_user_id)",
        f"CREATE INDEX IF NOT EXISTS ix_session_requests_tenant_id ON {sessions} (tenant_id)",
    )
    identity_indexes = (
        f"CREATE UNIQUE INDEX IF NOT EXISTS ix_devices_motherboard_serial_digest "
        f"ON {devices} (motherboard_serial_digest)",
    )
    for statement in (
        (legacy_indexes if apply_legacy_access else ())
        + (identity_indexes if apply_device_identity else ())
    ):
        await connection.execute(text(statement))

    await connection.run_sync(lambda sync: _verify(sync, schema))
    for version in sorted(set(_VERSIONS) - applied_versions):
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


def _configured_serial_pepper(
    value: bytes | str | SecretStr | None,
) -> bytes | None:
    if isinstance(value, SecretStr):
        value = value.get_secret_value()
    if isinstance(value, bytes):
        return bytes(value) if len(value) >= 32 else None
    if isinstance(value, str):
        try:
            decoded = bytes.fromhex(value)
        except ValueError:
            return None
        return decoded if len(decoded) >= 32 else None
    return None


def _session_status_constraint_is_legacy(
    connection: object, schema: str | None
) -> bool:
    inspector = inspect(connection)
    checks = {
        item["name"]: _normalize_check_expression(item["sqltext"])
        for item in inspector.get_check_constraints(
            "session_requests", schema=schema
        )
    }
    actual = checks.get("ck_session_requests_status")
    legacy = _normalize_check_expression(
        "status = ANY (ARRAY['requested', 'approved', 'rejected', 'expired'])"
    )
    current = _normalize_check_expression(
        "status = ANY (ARRAY['requested', 'approved', 'rejected', 'expired', "
        "'closed', 'revoked'])"
    )
    if actual == legacy:
        return True
    if actual == current:
        return False
    raise RelayAccessMigrationError(
        "relay access session status constraint differs"
    )


async def _backfill_device_serial_digests(
    connection: AsyncConnection,
    *,
    devices: str,
    serial_pepper: bytes | None,
) -> None:
    rows = list(
        (
            await connection.execute(
                text(
                    f"SELECT id, motherboard_serial, motherboard_serial_digest "
                    f"FROM {devices} ORDER BY id FOR UPDATE"
                )
            )
        ).all()
    )
    plaintext_rows = [row for row in rows if row.motherboard_serial is not None]
    if plaintext_rows and serial_pepper is None:
        raise RelayAccessMigrationError(
            "relay access serial remediation requires the configured device "
            "serial pepper"
        )
    seen: dict[str, str] = {}
    updates: list[tuple[str, str]] = []
    for row in rows:
        actual_digest = row.motherboard_serial_digest
        if actual_digest is not None:
            if not isinstance(actual_digest, str) or re.fullmatch(
                r"[0-9a-f]{64}", actual_digest
            ) is None:
                raise RelayAccessMigrationError(
                    "relay access device serial digest differs"
                )
            previous = seen.setdefault(actual_digest, str(row.id))
            if previous != str(row.id):
                raise RelayAccessMigrationError(
                    "relay access serial digest collision requires offline remediation"
                )
        if row.motherboard_serial is None:
            continue
        assert serial_pepper is not None
        digest = device_serial_digest(str(row.motherboard_serial), serial_pepper)
        if actual_digest is not None and not hmac.compare_digest(
            actual_digest, digest
        ):
            raise RelayAccessMigrationError(
                "relay access serial identity conflict requires offline remediation"
            )
        previous = seen.setdefault(digest, str(row.id))
        if previous != str(row.id):
            raise RelayAccessMigrationError(
                "relay access serial digest collision requires offline remediation"
            )
        updates.append((str(row.id), digest))
    for row_id, digest in updates:
        await connection.execute(
            text(
                f"UPDATE {devices} SET motherboard_serial_digest = :digest, "
                "motherboard_serial = NULL WHERE id = :row_id"
            ),
            {"digest": digest, "row_id": row_id},
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
            "motherboard_serial": (String, 128, True),
            "motherboard_serial_digest": (String, 64, True),
            "auth_version": (Integer, None, False),
            "auth_revoked_at": (DateTime, None, True),
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
    _verify_exact_indexes(
        connection,
        inspector,
        schema=schema,
        current_schema=effective_schema,
        table_name=table_name,
        expected={},
    )
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


def _index_matches(
    index: object, columns: tuple[str, ...], *, unique: bool = False
) -> bool:
    if not isinstance(index, dict):
        return False
    if tuple(index.get("column_names") or ()) != columns:
        return False
    if index.get("unique") is not unique:
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
        or dialect.get("postgresql_nulls_not_distinct") is True
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


def _verify_exact_indexes(
    connection: object,
    inspector: object,
    *,
    schema: str | None,
    current_schema: str,
    table_name: str,
    expected: dict[str, tuple[tuple[str, ...], bool]],
) -> None:
    actual = _standalone_indexes(inspector, table_name, schema)
    if set(expected) - set(actual):
        raise RelayAccessMigrationError(
            f"relay access indexes differ for {table_name}"
        )
    if any(
        not _index_matches(actual[name], columns, unique=unique)
        or _index_access_method(
            connection, schema=current_schema, index_name=name
        )
        != "btree"
        for name, (columns, unique) in expected.items()
    ):
        raise RelayAccessMigrationError(
            f"relay access indexes differ for {table_name}"
        )
    for name, index in actual.items():
        if name in expected:
            continue
        columns = index.get("column_names")
        if (
            not isinstance(columns, list)
            or not columns
            or any(not isinstance(column, str) for column in columns)
            or not _index_matches(index, tuple(columns), unique=False)
            or _index_access_method(
                connection, schema=current_schema, index_name=name
            )
            != "btree"
        ):
            raise RelayAccessMigrationError(
                f"relay access indexes differ for {table_name}"
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


def _unique_constraint_signature(
    constraint: dict[str, object],
) -> tuple[object, ...]:
    dialect = constraint.get("dialect_options") or {}
    return (
        constraint.get("name"),
        tuple(constraint.get("column_names") or ()),
        bool(dialect.get("postgresql_nulls_not_distinct", False)),
        tuple(constraint.get("include_columns") or ()),
        tuple(dialect.get("postgresql_include") or ()),
    )


def _primary_key_matches(
    primary_key: dict[str, object],
    *,
    name: str,
    columns: tuple[str, ...],
) -> bool:
    dialect = primary_key.get("dialect_options") or {}
    return (
        primary_key.get("name") == name
        and tuple(primary_key.get("constrained_columns") or ()) == columns
        and not dialect.get("postgresql_include")
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
    if not _primary_key_matches(
        primary_key,
        name="device_enrollments_pkey",
        columns=("id",),
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
        _unique_constraint_signature(constraint)
        for constraint in inspector.get_unique_constraints(
            table_name, schema=schema
        )
    }
    if actual_unique != {
        (
            "device_enrollments_token_digest_key",
            ("token_digest",),
            False,
            (),
            (),
        )
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

    _verify_exact_indexes(
        connection,
        inspector,
        schema=schema,
        current_schema=current_schema,
        table_name=table_name,
        expected={"ix_device_enrollments_expiry": (("expires_at",), False)},
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
    device_columns = {
        column["name"]: column
        for column in inspector.get_columns("devices", schema=schema)
    }
    if _normalize_server_default(device_columns["auth_version"]["default"]) != "1":
        raise RelayAccessMigrationError("relay device auth version default differs")
    if any(
        device_columns[name]["default"] is not None
        for name in (
            "motherboard_serial",
            "motherboard_serial_digest",
            "auth_revoked_at",
        )
    ):
        raise RelayAccessMigrationError("relay device identity defaults differ")

    required_checks = {
        "users": {
            "ck_users_tenant_id": "length(tenant_id) >= 1 AND length(tenant_id) <= 64",
            "ck_users_tenant_id_canonical": "tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'",
        },
        "devices": {
            "ck_devices_tenant_id": "length(tenant_id) >= 1 AND length(tenant_id) <= 64",
            "ck_devices_tenant_id_canonical": "tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'",
            "ck_devices_bound_owner": "is_bound = FALSE AND bound_user_id IS NULL OR is_bound = TRUE AND bound_user_id IS NOT NULL",
            "ck_devices_auth_version": "auth_version >= 1",
            "ck_devices_serial_digest": (
                "motherboard_serial_digest IS NULL OR "
                "length(motherboard_serial_digest) = 64"
            ),
            "ck_devices_plaintext_serial_cleared": "motherboard_serial IS NULL",
        },
        "session_requests": {
            "ck_session_requests_tenant_id": "length(tenant_id) >= 1 AND length(tenant_id) <= 64",
            "ck_session_requests_tenant_id_canonical": "tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'",
            "ck_session_requests_status": (
                "status = ANY (ARRAY['requested', 'approved', 'rejected', "
                "'expired', 'closed', 'revoked'])"
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
        normalized_expected = {
            name: _normalize_check_expression(expression)
            for name, expression in expected.items()
        }
        if checks != normalized_expected:
            raise RelayAccessMigrationError(
                f"relay access checks differ for {table_name}"
            )

    primary_keys = {
        "users": ("users_pkey", ("id",)),
        "devices": ("devices_pkey", ("id",)),
        "session_requests": ("session_requests_pkey", ("id",)),
    }
    for table_name, (name, columns) in primary_keys.items():
        if not _primary_key_matches(
            inspector.get_pk_constraint(table_name, schema=schema),
            name=name,
            columns=columns,
        ):
            raise RelayAccessMigrationError(
                f"relay access primary key differs for {table_name}"
            )

    for table_name in primary_keys:
        actual_unique = {
            _unique_constraint_signature(constraint)
            for constraint in inspector.get_unique_constraints(
                table_name, schema=schema
            )
        }
        if actual_unique:
            raise RelayAccessMigrationError(
                f"relay access unique constraints differ for {table_name}"
            )

    expected_foreign_keys = {
        "users": set(),
        "devices": {
            (
                "devices_bound_user_id_fkey",
                ("bound_user_id",),
                effective_schema,
                "users",
                ("id",),
                "RESTRICT",
                "NO ACTION",
                False,
                None,
                "SIMPLE",
            )
        },
        "session_requests": {
            (
                "session_requests_requester_user_id_fkey",
                ("requester_user_id",),
                effective_schema,
                "users",
                ("id",),
                "CASCADE",
                "NO ACTION",
                False,
                None,
                "SIMPLE",
            ),
            (
                "session_requests_target_device_id_fkey",
                ("target_device_id",),
                effective_schema,
                "devices",
                ("id",),
                "CASCADE",
                "NO ACTION",
                False,
                None,
                "SIMPLE",
            ),
            (
                "session_requests_intended_peer_id_fkey",
                ("intended_peer_id",),
                effective_schema,
                "devices",
                ("id",),
                "CASCADE",
                "NO ACTION",
                False,
                None,
                "SIMPLE",
            ),
        },
    }
    for table_name, expected in expected_foreign_keys.items():
        actual = {
            _foreign_key_signature(key, current_schema=effective_schema)
            for key in inspector.get_foreign_keys(table_name, schema=schema)
        }
        if actual != expected:
            raise RelayAccessMigrationError(
                f"relay access foreign keys differ for {table_name}"
            )

    required_constraint_types = {
        "users": {
            "users_pkey": "p",
            **{name: "c" for name in required_checks["users"]},
        },
        "devices": {
            "devices_pkey": "p",
            **{name: "c" for name in required_checks["devices"]},
            "devices_bound_user_id_fkey": "f",
        },
        "session_requests": {
            "session_requests_pkey": "p",
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
            exact=True,
        )

    required_indexes = {
        "users": {
            "ix_users_email": (("email",), True),
            "ix_users_tenant_id": (("tenant_id",), False),
            "ix_users_username": (("username",), True),
        },
        "devices": {
            "ix_devices_bound_user_id": (("bound_user_id",), False),
            "ix_devices_device_id": (("device_id",), True),
            "ix_devices_motherboard_serial_digest": (
                ("motherboard_serial_digest",), True
            ),
            "ix_devices_name": (("name",), False),
            "ix_devices_tenant_id": (("tenant_id",), False),
        },
        "session_requests": {
            "ix_session_requests_requester_user_id": (
                ("requester_user_id",), False
            ),
            "ix_session_requests_signaling_room": (("signaling_room",), False),
            "ix_session_requests_target_device_id": (
                ("target_device_id",), False
            ),
            "ix_session_requests_tenant_id": (("tenant_id",), False),
        },
    }
    for table_name, expected in required_indexes.items():
        _verify_exact_indexes(
            connection,
            inspector,
            schema=schema,
            current_schema=effective_schema,
            table_name=table_name,
            expected=expected,
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
