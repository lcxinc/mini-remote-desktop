# Relay Agent Crash And Concurrency Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development for every behavior change.

**Goal:** Close the second Task 7 audit by making relay identity, heartbeat,
rotation and coturn health safe under concurrent requests, transient failures
and cross-file crashes.

**Architecture:** Use a single locked-row transaction boundary for all signed
server mutations and a generation-aware shared-health boundary in the portable
Rust agent. Treat persisted identity as authoritative, persisted probe evidence
as untrusted, and plaintext secrets as short-lived zeroizing buffers.

**Tech Stack:** Rust/Tokio/reqwest/rustls/zeroize, Python/FastAPI/Pydantic,
SQLAlchemy/PostgreSQL 18, shared canonical JSON fixtures.

---

### Task 1: Strict TLS, identifiers, headers and endpoint wire

**Files:**
- Modify: `apps/mrd-relay-agent/src/backend.rs`
- Modify: `apps/mrd-relay-agent/src/identity.rs`
- Modify: `apps/mrd-relay-agent/src/config.rs`
- Modify: `apps/mrd-relay-agent/tests/runtime.rs`
- Modify: `apps/Rdesk-Server/app/schemas/relay.py`
- Modify: `apps/Rdesk-Server/tests/test_relay_node_api.py`
- Modify: `tests/fixtures/relay_heartbeat_wire_v1.json`
- Modify: `tests/fixtures/relay_secret_rotation_wire_v1.json`

1. Write tests that fail for an extra TLS root, missing heartbeat no-store
   headers, short node IDs, invalid generated IDs, noncanonical boot IDs and
   credential-bearing TURN endpoints.
2. Run focused Rust and Python tests and record the expected failures.
3. Disable built-in roots, add protocol-specific validators, rejection-sampled
   IDs, strict boot decoding, endpoint parsing and redacted Debug.
4. Rerun focused tests to green.

### Task 2: Serialize every signed PostgreSQL mutation

**Files:**
- Modify: `apps/Rdesk-Server/app/services/relay_registry.py`
- Modify: `apps/Rdesk-Server/app/api/v1/relays.py`
- Modify: `apps/Rdesk-Server/tests/test_relay_node_api.py`
- Modify: `apps/Rdesk-Server/tests/test_relay_repository_postgres.py`

1. Add real two-session barrier tests for conflicting upload, duplicate commit,
   renewal versus old epoch, and heartbeat versus upload sequence ordering.
2. Verify RED against the identity-map stale-row behavior.
3. Add one advisory-lock plus fresh locked-row helper and revalidate all signed
   inputs inside it; make audit insertion idempotent.
4. Repeat the concurrency tests and the complete PostgreSQL repository suite.

### Task 3: Desired drain and contiguous migration lifecycle

**Files:**
- Modify: `apps/Rdesk-Server/app/db/migrate_add_relay_control.py`
- Modify: `apps/Rdesk-Server/app/services/relay_registry.py`
- Modify: `apps/Rdesk-Server/tests/test_relay_node_api.py`
- Modify: `apps/Rdesk-Server/tests/test_relay_repository_postgres.py`

1. Add failing rotation/non-evidence/resume lifecycle tests and a true v6
   schema-to-v8 upgrade/rollback/steady-state test.
2. Preserve desired drain independently of sampled state; reject resume during
   pending rotation.
3. Upgrade missing final v8 fields and constraints from genuine v6 while
   retaining the exact three-mutation v7 path.
4. Rerun lifecycle and migration tests.

### Task 4: Crash-safe portable runtime

**Files:**
- Modify: `apps/mrd-relay-agent/src/runtime.rs`
- Modify: `apps/mrd-relay-agent/src/identity.rs`
- Modify: `apps/mrd-relay-agent/src/backend.rs`
- Modify: `apps/mrd-relay-agent/tests/runtime.rs`

1. Add failing first-run v1 bootstrap, cross-file epoch crash, fresh-after-wait
   health, transient-failure, renewal-timeout and response-loss tests.
2. Add identity/runtime reconciliation and trusted bootstrap persistence before
   the first heartbeat.
3. Split maintenance from heartbeat, classify retryable failures, and sample
   generation-aware health only after the cadence wait.
4. Persist an explicit commit-unknown phase. In the same generation, perform a
   fresh validation probe but retry the exact persisted commit body. Across
   generations, use a signed read-only rotation-status API: finalize only an
   exact committed receipt, or discard stale proof and re-probe when the server
   reports pending; fail closed on unknown or mismatch.
5. Repeat clock, crash and pending-backend tests ten times.

### Task 5: Secret ownership and WebRTC teardown

**Files:**
- Modify: `apps/mrd-relay-agent/src/backend.rs`
- Modify: `apps/mrd-relay-agent/src/identity.rs`
- Modify: `crates/mrd-transport-webrtc/src/config.rs`
- Modify: `crates/mrd-transport-webrtc/src/peer.rs`
- Modify: `crates/mrd-transport-webrtc/src/probe.rs`
- Modify: corresponding Rust tests

1. Add failing type/lifecycle and redaction tests using observable owner hooks,
   not `needs_drop` proxies.
2. Return zeroizing upload bodies, reuse them for signing/sending, and clear
   mutable base64 buffers immediately.
3. Wrap third-party ICE server and SDP/candidate ownership so teardown clears
   controllable copies; avoid ordinary lowercase/query clones.
4. Run relay-agent and WebRTC tests plus Clippy.

### Task 6: Full verification and commit

1. Run relay-agent, WebRTC, relay-control and proto suites.
2. Run the complete Python suite with PostgreSQL 18 and zero skips; repeat the
   two-session barriers and v6/v7/v8 migration tests.
3. Run both strict Clippy commands, fmt and `git diff --check`.
4. Review all 20 audit items against tests and code.
5. Commit as `fix: harden relay agent crash and concurrency paths` and confirm
   the worktree is clean.
