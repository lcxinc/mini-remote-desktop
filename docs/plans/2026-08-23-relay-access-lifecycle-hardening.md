# Relay Access Lifecycle and Operations Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close device privacy and ownership gaps, remove relay lock/capacity races, rotate secrets safely, complete the grant lifecycle, and make migrations operationally idempotent.

**Architecture:** Add versioned device identity and reservation lifecycle fields through the existing PostgreSQL migrations. Centralize device JWT, response cache, session lock-order, exact-deadline, and keyring behavior in small helpers used by the current FastAPI/services rather than introducing new deployment components.

**Tech Stack:** FastAPI, Pydantic v2, SQLAlchemy async ORM, PostgreSQL advisory/row locks, JOSE HS256 JWT, AES-GCM, pytest/anyio, Rust relay contracts.

---

### Task 1: Device privacy, ownership, and credential lifecycle

**Files:** `app/api/v1/devices.py`, `app/core/security.py`, `app/core/config.py`, `app/models/device.py`, `app/schemas/device.py`, `app/services/device_enrollment.py`, `tests/test_device_ownership.py`

1. Add failing tests for tenant-scoped list/get/status, dual-proof rename, device token audience/version/revoke/rotate, POST inventory, absence of raw serial in URLs/database/logs, and same-serial concurrent enrollment.
2. Run focused tests and record the expected authorization/privacy/concurrency failures.
3. Implement query scoping, proof checks, versioned device JWT endpoints, serial HMAC/advisory locking, and stable savepoint conflicts.
4. Run focused unit and real-PG tests until green.

### Task 2: Session lock order, reservations, and exact deadlines

**Files:** `app/services/session_grants.py`, `app/services/relay_directory.py`, `app/services/relay_repository.py`, `app/models/relay_reservation.py`, relay/session tests.

1. Add failing PG deadlock/progress tests, per-node reservation tests, replacement/superseded-capacity tests, rollback tests, and fractional-second deadline boundary tests.
2. Run them to demonstrate global node locking, current-slot exhaustion, and deadline divergence.
3. Introduce advisory-first Device→Users→Session locking, snapshot selection, per-candidate node/registration locking, directory generations/supersession, and exact `expires_at` admission.
4. Run focused and PG concurrency tests until green.

### Task 3: Sensitive responses and key rotation

**Files:** auth/device/relay APIs, `app/core/response_security.py`, `app/core/config.py`, `app/services/relay_repository.py`, `app/services/relay_directory.py`, `app/services/turn_credentials.py`, secret tests.

1. Add failing cache-header, read-key rotation/re-encryption, unknown-key, and low-entropy TURN-secret tests.
2. Implement the shared no-store dependency, bounded JSON read-key parser, transactional re-encryption, and exact secret-quality checks.
3. Run focused tests until green.

### Task 4: Grant lifecycle and audits

**Files:** `app/api/v1/sessions.py`, `app/schemas/session.py`, `app/services/session_grants.py`, `app/models/session_request.py`, session/access tests.

1. Add failing audit and reject/close/revoke authorization/irreversibility tests.
2. Implement durable request/approve audits and terminal transitions with row locks, immediate deadlines, reservation supersession, and redacted summaries.
3. Verify closed/revoked grants cannot issue access and old reservations still count capacity.

### Task 5: Versioned operational migrations

**Files:** `app/db/migrate_add_relay_access.py`, `app/db/migrate_add_relay_control.py`, `app/main.py`, `.env.example`, migration tests.

1. Add failing real-PG tests for once-only startup, serial backfill/no-pepper/collision, contradictory ownership, new exact columns/constraints, and allowed operational indexes.
2. Gate DDL/backfill by missing ledger versions, add device/reservation/session fields, and make current startup verification-only.
3. Preserve exact constraint/unique/partial semantics while allowing safe extra nonunique btree indexes.
4. Run legal repeat/concurrent/rollback/future-version migrations until green.

### Task 6: Full verification and commit

1. Run expanded device/session/relay and all real-PG tests, then the full backend.
2. Run Rust 27, production OpenAPI/import, compileall, requirements/pip, and diff checks.
3. Stage only intended paths and commit `fix: harden relay access lifecycle and operations`.
