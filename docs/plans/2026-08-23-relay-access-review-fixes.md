# Relay Access Review Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close the five relay-access specification gaps with server-owned grants,
trusted topology, node-held TURN secrets, reservation-aware fallback, and strict
PostgreSQL migration verification.

**Architecture:** Add a focused session grant service and extend the existing relay
registry/repository boundaries. All authorization and two-phase reservation work stays
inside one database transaction. Migrations are additive, advisory-locked, idempotent,
and verify the exact security-relevant schema after applying changes.

**Tech Stack:** FastAPI, Pydantic v2, SQLAlchemy async ORM, PostgreSQL/asyncpg,
AES-GCM, HMAC-SHA1 coturn REST credentials, pytest, Rust contract tests.

---

### Task 1: Server-owned tenant session grants

**Files:**
- Create: `apps/Rdesk-Server/app/services/session_grants.py`
- Modify: `apps/Rdesk-Server/app/api/v1/sessions.py`
- Modify: `apps/Rdesk-Server/app/schemas/session.py`
- Modify: `apps/Rdesk-Server/app/models/user.py`
- Modify: `apps/Rdesk-Server/app/models/device.py`
- Modify: `apps/Rdesk-Server/app/models/session_request.py`
- Modify: `apps/Rdesk-Server/app/core/config.py`
- Test: `apps/Rdesk-Server/tests/test_session_grants.py`

1. Write API tests showing anonymous and caller-supplied requester data cannot create a
   grant, while a JWT requester can request only a bound same-tenant target.
2. Run the focused tests and record the expected authentication/spoof failures.
3. Add tenant columns/models and implement request creation using the authenticated user.
4. Write approval tests for wrong owner, self-approval, cross-tenant, conflict, and a
   server-generated complete policy/deadline bundle.
5. Run RED, implement row-locked owner approval in `SessionGrantService`, then run GREEN.
6. Add an API-flow test that both participants can call relay access after approval.

### Task 2: Trusted topology and node-generated TURN secret

**Files:**
- Modify: `apps/Rdesk-Server/app/schemas/relay.py`
- Modify: `apps/Rdesk-Server/app/api/v1/relays.py`
- Modify: `apps/Rdesk-Server/app/models/relay_node.py`
- Modify: `apps/Rdesk-Server/app/models/relay_node_registration.py`
- Modify: `apps/Rdesk-Server/app/services/relay_registry.py`
- Modify: `apps/Rdesk-Server/app/services/relay_repository.py`
- Modify: `apps/Rdesk-Server/app/services/turn_credentials.py`
- Test: `apps/Rdesk-Server/tests/test_relay_node_api.py`
- Test: `apps/Rdesk-Server/tests/test_relay_lifecycle_hardening.py`

1. Write failing enrollment tests for missing/noncanonical secrets, same-token different
   secret conflict, pickup redaction, and an admin approval that must assign topology.
2. Add registration encrypted-secret/topology fields and nullable node physical host ID.
3. Bind the secret hash into the enrollment digest and encrypt at request time; remove all
   pickup decryption/secret response code.
4. Require explicit admin topology in approval and copy only confirmed topology and
   ciphertext into the node on pickup.
5. Add `decrypt_mutable`, use it only in credential issuance, clear the buffer in
   `finally`, and run the focused lifecycle/credential tests GREEN.

### Task 3: Reservation-aware two-phase selection

**Files:**
- Modify: `apps/Rdesk-Server/app/services/relay_directory.py`
- Modify: `apps/Rdesk-Server/app/services/relay_repository.py`
- Test: `apps/Rdesk-Server/tests/test_relay_directory.py`
- Test: `apps/Rdesk-Server/tests/test_relay_directory_postgres.py`

1. Write failing tests for pending-full high-score primary falling back within the same
   domain, repository rejection falling through to the next same-domain primary, and a
   backup that differs by confirmed domain and physical host despite endpoint aliases.
2. Count other-session pending reservations after node locks and create effective views.
3. Add a bounded per-call repository result limit without weakening the configured
   per-session maximum.
4. Reserve primary with limit one; derive and reserve the backup from the actual primary,
   all inside the existing outer transaction; preserve canonical signed output order.
5. Run unit and real PostgreSQL concurrent issuance tests GREEN.

### Task 4: Strict additive migrations

**Files:**
- Modify: `apps/Rdesk-Server/app/db/migrate_add_relay_control.py`
- Modify: `apps/Rdesk-Server/app/db/migrate_add_relay_access.py`
- Modify: `apps/Rdesk-Server/app/main.py`
- Create: `apps/Rdesk-Server/tests/test_relay_access_migration_postgres.py`
- Modify: `apps/Rdesk-Server/tests/test_relay_repository_postgres.py`

1. Write PostgreSQL RED tests for idempotent upgrade/backfill and rejection of wrong
   type, length, nullability, default, check, foreign key, and index definitions.
2. Advance relay-control schema for registration ciphertext and trusted topology while
   retaining Task 4 compatibility.
3. Advance relay-access schema, backfill `default` tenant safely, add exact constraints,
   and implement comprehensive inspector verification.
4. Exercise concurrent migration calls and confirm startup ordering is idempotent.

### Task 5: Cross-cutting verification and review

**Files:** all files above and existing relay tests.

1. Run extended focused Python tests and fix only demonstrated regressions using RED/GREEN.
2. Run all backend tests with `MRD_TEST_DATABASE_URL` configured and confirm no skips.
3. Run `cargo test -p mrd-relay-control --test directory_contract`.
4. Run compileall, OpenAPI assertions, secret/redaction searches, and `git diff --check`.
5. Request independent code review and resolve every Critical/Important finding.
6. Commit the implementation with a clear `fix:` message and record SHA/clean status.
