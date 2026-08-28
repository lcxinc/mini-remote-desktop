# Relay Agent Gate Completion Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete the portable relay-agent orchestration, exact Python/Rust wire contract, certificate lifecycle, and restart-safe node-generated secret rotation required by the Task 7 gate.

**Architecture:** Keep platform service managers outside Task 7. Share exact fixtures between Python and Rust, bind all mutable agent state to a certificate identity epoch, and run backend/identity work independently from local coturn supervision. Persist rotation intent before side effects and use authenticated upload/commit endpoints so secrets never travel in heartbeat responses.

**Tech Stack:** Rust/Tokio/reqwest/rustls/ring/rcgen/x509-parser, Python/FastAPI/Pydantic/SQLAlchemy/cryptography, SQLite/PostgreSQL repository tests.

---

### Task 1: Exact heartbeat wire and strict backend validation

**Files:**
- Create: `tests/fixtures/relay_heartbeat_wire_v1.json`
- Modify: `apps/mrd-relay-agent/src/backend.rs`
- Modify: `apps/mrd-relay-agent/src/identity.rs`
- Modify: `apps/mrd-relay-agent/tests/runtime.rs`
- Modify: `apps/Rdesk-Server/app/schemas/relay.py`
- Modify: `apps/Rdesk-Server/app/api/v1/relays.py`
- Modify: `apps/Rdesk-Server/app/services/relay_registry.py`
- Modify: `apps/Rdesk-Server/tests/test_relay_node_api.py`

**Steps:**

1. Add Rust and Python tests loading the same fixture. Assert canonical request bytes, exact JSON, state vocabulary, identity epoch, sequence, boot ID, nonce, health, capacity, traffic, loss, pressure, endpoints, and desired-state response.
2. Run the focused Rust/Python tests and record failures for `available`, missing request fields, and absent strict directive wire.
3. Implement bounded Rust/Pydantic types with unknown-field denial and response identity/epoch/sequence verification. Generate boot ID once per process and nonce once per request; persist only sequence and epoch.
4. Extend heartbeat persistence and service validation. Add `Cache-Control: no-store` and exact response fields.
5. Rerun focused tests until green.

### Task 2: Database identity epoch and node-generated rotation control plane

**Files:**
- Modify: `apps/Rdesk-Server/app/models/relay_node.py`
- Modify: `apps/Rdesk-Server/app/db/migrate_add_relay_control.py`
- Modify: `apps/Rdesk-Server/app/services/relay_registry.py`
- Modify: `apps/Rdesk-Server/app/api/v1/relays.py`
- Modify: `apps/Rdesk-Server/app/schemas/relay.py`
- Modify: `apps/Rdesk-Server/tests/test_relay_node_api.py`
- Modify: `apps/Rdesk-Server/tests/test_relay_repository.py`
- Modify: `apps/Rdesk-Server/tests/test_relay_repository_postgres.py`

**Steps:**

1. Add failing tests for renewal epoch increment/reset, old-epoch rejection, admin desired-version/drain creation, idempotent authenticated upload, conflicting digest rejection, commit-before-drain/probe rejection, atomic encrypted active-secret switch, and audit/no-store behavior.
2. Run focused API/repository tests and record missing schema/model/service failures.
3. Add bounded model columns and migration contracts for identity epoch, boot/nonce metadata, desired/applied/pending versions, pending encrypted secret/digest/idempotency ID, and safe switch deadlines.
4. Implement admin rotate plus signed mTLS upload/commit routes. Keep plaintext in `SecretStr`/short-lived buffers; encrypt before flush. Commit active secret/version only after the agent's completion proof and audit it.
5. Run SQLite tests and real PostgreSQL tests when configured.

### Task 3: Strict certificate lifecycle and hot backend swap

**Files:**
- Modify: `apps/mrd-relay-agent/src/identity.rs`
- Modify: `apps/mrd-relay-agent/src/backend.rs`
- Modify: `apps/mrd-relay-agent/tests/runtime.rs`

**Steps:**

1. Add failing current-time certificates and negative tests for expired/not-yet-valid leaf or CA, untrusted CA, wrong CN/SAN cardinality, CA=true leaf, missing digital-signature/client-auth, CA without key-cert-sign, expiry mismatch, invalid reloaded active/pending bundle, client-factory failure, write failure, and restart.
2. Run the focused certificate tests and record current acceptance failures.
3. Add injected wall clock, trusted-root validation, one validation path for active/pending/new pairs, and redacted PEM/CSR Debug implementations.
4. Build the candidate mTLS client before atomic promotion; hot-swap only after persistence. Preserve old pair/client on every failure.
5. Rerun focused identity/backend tests.

### Task 4: Persistent transactional desired state and real-evidence boundary

**Files:**
- Modify: `apps/mrd-relay-agent/src/process.rs`
- Modify: `apps/mrd-relay-agent/src/runtime.rs`
- Modify: `apps/mrd-relay-agent/src/backend.rs`
- Modify: `apps/mrd-relay-agent/tests/runtime.rs`

**Steps:**

1. Add failing tests for a restrictive atomic production state store, intent-before-side-effects, restart at every rotation phase, zero allocations/deadline gates, same-version different-secret rejection, upload/apply/live-probe/commit/resume ordering, and old-epoch directive rejection.
2. Add compile-fail/private-constructor coverage proving ordinary callers cannot construct live allocation evidence; fakes return explicit `NonEvidence`.
3. Implement the persisted rotation state machine and production store. Expose live evidence only through a private production probe constructor.
4. Implement the authenticated node-generated upload/commit calls and CSPRNG canonical secret generation.
5. Rerun focused tests and redaction scans.

### Task 5: Independent supervisor and portable orchestrator

**Files:**
- Modify: `apps/mrd-relay-agent/src/runtime.rs`
- Modify: `apps/mrd-relay-agent/src/process.rs`
- Modify: `apps/mrd-relay-agent/src/metrics.rs`
- Modify: `apps/mrd-relay-agent/src/lib.rs`
- Modify: `apps/mrd-relay-agent/src/main.rs`
- Modify: `apps/mrd-relay-agent/tests/runtime.rs`

**Steps:**

1. Add failing paused-backend/barrier test proving the supervisor continues, plus restart delays exactly 1/2/4 seconds, healthy-probe reset, unavailable reporting, and no healthy lease renewal while failed.
2. Add failing main exit-code/config parsing tests and bounded real coturn metrics fixture tests, including chunk/content-length/UTF-8/line/field/numeric limits.
3. Implement `run_agent` with independent Tokio tasks and explicit lock snapshots; backend/client swaps do not hold locks across awaits.
4. Implement portable configuration loading and make missing Task 8 adapter return a stable reason code and nonzero exit.
5. Run multiple timing repetitions to detect flakes.

### Task 6: Full verification and handoff

**Files:**
- Review all files changed in Tasks 1-5.

**Steps:**

1. Run `cargo test -p mrd-relay-agent` and repeat timing tests ten times.
2. Run targeted and full `apps/Rdesk-Server` relay suites, including real PostgreSQL suites when configured.
3. Run `cargo test -p mrd-relay-control`, `cargo test -p mrd-proto`, both clippy commands, fmt check, and `git diff --check`.
4. Inspect all Debug/Display/error/log sources for key, secret, receipt, PEM, CSR, or credential URL leakage.
5. Commit all gate fixes as `fix: complete relay agent orchestration and wire contract` and report RED/GREEN evidence plus environment-limited checks.
