# Close Device Enumeration and Auth Schema Drift Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make device inventory checks admin-only before database access and make relay access migrations fail closed on every semantic object attached to the four auth tables they manage or trust.

**Architecture:** Reuse the existing `require_admin` dependency on `/devices/check/{motherboard_serial}` so FastAPI authenticates and authorizes before constructing the route database query. Extend the existing PostgreSQL catalog normalizers into an exact per-table schema contract covering PK, CHECK, UNIQUE, FK, and standalone indexes for `users`, `devices`, `session_requests`, and `device_enrollments`; column/default validation remains in the same migration transaction.

**Tech Stack:** FastAPI dependencies and OpenAPI, SQLAlchemy 2 async sessions/inspection, PostgreSQL `pg_constraint`/`pg_index`, pytest/anyio.

---

### Task 1: Close device inventory enumeration

**Files:**
- Modify: `apps/Rdesk-Server/tests/test_device_ownership.py`
- Modify: `apps/Rdesk-Server/app/api/v1/devices.py`

1. Add tests proving anonymous, ordinary-user, and device-only requests never execute the database dependency/query for known or unknown serials, while admin requests retain the inventory response.
2. Run the new tests and confirm RED because the route is currently anonymous.
3. Inject `require_admin` before `get_db`, mark the route as admin inventory/deprecated, and keep response fields unchanged for admins.
4. Run the focused tests and confirm GREEN; verify OpenAPI exposes bearer authentication.

### Task 2: Enforce the complete auth schema contract

**Files:**
- Modify: `apps/Rdesk-Server/tests/test_relay_directory_postgres.py`
- Modify: `apps/Rdesk-Server/app/db/migrate_add_relay_access.py`

1. Add real-PostgreSQL negative tests that add an extra unvalidated CHECK, UNIQUE constraint, self-FK, and partial index to each auth table category, and assert migration failure plus transaction rollback.
2. Run the new tests and confirm RED because current validation accepts extra objects on `users`, `devices`, and `session_requests`.
3. Define the exact legal PK/CHECK/UNIQUE/FK/index sets produced by the real ORM DDL and relay access migration. Compare full normalized sets, including validation/deferrability, referenced schema/actions, index uniqueness/method/predicate/include, while excluding only indexes explicitly reported as constraint backing indexes.
4. Run the focused real-PG suite and confirm GREEN, including legal repeat and concurrent migrations.

### Task 3: Verify and commit

**Files:**
- Verify all files above and this plan.

1. Run device security, Task5 focused, full real-PG/backend tests, Rust relay tests, production import/OpenAPI, compileall, requirements/pip, and diff checks.
2. Stage only intended paths and inspect the staged diff.
3. Commit with `fix: close device enumeration and auth schema drift` and confirm a clean worktree.
