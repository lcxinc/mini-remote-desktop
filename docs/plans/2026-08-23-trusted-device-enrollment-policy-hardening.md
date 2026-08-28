# Trusted Device Enrollment and Current Policy Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development to implement this plan task-by-task.

**Goal:** Require an administrator-created, single-use trust root for first device registration, revoke stale relay grants immediately when server policy changes, and make relay-owned PostgreSQL schemas reject every unexpected semantic object.

**Architecture:** Add a dedicated `device_enrollments` ledger whose raw 256-bit token exists only in the issue response and request header; the database stores a domain-separated keyed digest, bounded lifetime, request digest, device result, and issuer/consumer audit metadata. Inject the configured session grant policy into relay access and compare it against the locked grant before any capacity reservation. Normalize PostgreSQL inspector output and compare complete PK, FK, CHECK, unique-constraint, and standalone-index sets for every migration-owned table.

**Tech Stack:** FastAPI, Pydantic v2, SQLAlchemy async ORM, PostgreSQL advisory/row locks, pytest/AnyIO, Rust relay directory contract tests.

---

### Task 1: Device enrollment trust root

**Files:**
- Create: `apps/Rdesk-Server/app/models/device_enrollment.py`
- Create: `apps/Rdesk-Server/app/services/device_enrollment.py`
- Modify: `apps/Rdesk-Server/app/api/v1/devices.py`
- Modify: `apps/Rdesk-Server/app/schemas/device.py`
- Modify: `apps/Rdesk-Server/app/core/config.py`
- Modify: `apps/Rdesk-Server/app/db/migrate_add_relay_access.py`
- Test: `apps/Rdesk-Server/tests/test_device_ownership.py`
- Test: `apps/Rdesk-Server/tests/test_device_ownership_postgres.py`

1. Write failing API tests for admin-only issuance, raw-token redaction, anonymous registration rejection, exact single bounded header, one-use conflict, same-payload recovery, and existing-device non-escalation.
2. Run the focused tests and confirm they fail because enrollment issuance/storage does not exist and anonymous first registration still succeeds.
3. Add the ledger model/service, token header scheme, admin endpoint, transactionally locked consume/recovery flow, and redacted audit events.
4. Run focused tests to green.
5. Add and run real PostgreSQL concurrent-consume tests proving one logical device/result.

### Task 2: Current policy and self-grant revalidation

**Files:**
- Modify: `apps/Rdesk-Server/app/services/relay_directory.py`
- Modify: `apps/Rdesk-Server/app/api/v1/relays.py`
- Test: `apps/Rdesk-Server/tests/test_relay_directory.py`
- Test: `apps/Rdesk-Server/tests/test_relay_directory_postgres.py`

1. Write failing tests for settings revision bump, changed policy fields/deadlines, and forged approved requester-equals-owner grants; assert zero reservations.
2. Inject `configured_session_grant_policy(settings)` into production relay access.
3. Compare caller revision, locked grant revision, current revision, policy lists, and remaining deadlines before selecting or reserving; explicitly reject requester/owner equality.
4. Run unit/API/real-PostgreSQL tests to green.

### Task 3: Exact migration object sets

**Files:**
- Modify: `apps/Rdesk-Server/app/db/migrate_add_relay_control.py`
- Modify: `apps/Rdesk-Server/app/db/migrate_add_relay_access.py`
- Test: `apps/Rdesk-Server/tests/test_relay_repository_postgres.py`
- Test: `apps/Rdesk-Server/tests/test_relay_directory_postgres.py`

1. Write real PostgreSQL negative tests for extra `CHECK (FALSE)`, extra unique constraint/index, extra FK, and partial/include index; confirm migrations currently accept them.
2. Normalize inspector output, exclude only legitimate `duplicates_constraint` backing indexes, and compare exact named semantic sets for migration-owned tables and ledgers.
3. Add strict schema validation for `device_enrollments`, including types/defaults/PK/FKs/CHECKs/unique/indexes.
4. Run negative, idempotent, rollback, and concurrent migration tests to green.

### Task 4: Final verification and handoff

1. Run focused device/session/Task5 suites with real PostgreSQL configured.
2. Run the complete backend suite with real PostgreSQL.
3. Run `cargo test -p mrd-relay-control` and confirm 27 tests.
4. Import the production FastAPI app, generate OpenAPI, compile Python, run `pip check`, and run `git diff --check`.
5. Review the exact staged paths and commit with `fix: require trusted device enrollment and current policy`.
