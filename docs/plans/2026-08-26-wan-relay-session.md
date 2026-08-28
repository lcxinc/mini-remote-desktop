# Initial WAN Relay Session Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make a fresh attended remote session travel end to end through `mrd-service` over an authorized, capacity-reserved, multi-region TURN route, then automatically start media and retain the existing relay failover behavior.

**Architecture:** Keep Rdesk as a thin IPC shell. Add version-3 initial-session messages with description-owned ICE candidate commitments, device-authenticated backend authorization with one immutable shared relay-access generation, and a role-aware `mrd-service::wan_session` coordinator. The realtime server remains a blind authenticated router; generation zero must prove a relay/relay selected pair on the exact signed directory node before media, input, or failover installation is enabled.

**Tech Stack:** Rust (`tokio`, `serde`, `ed25519`, `webrtc-rs`, Axum/WebSocket), Python 3/FastAPI/SQLAlchemy/PostgreSQL, React/TypeScript/Vitest, coturn Docker, Cargo/pytest/pnpm.

---

## Implementation rules

- Follow `docs/plans/2026-08-26-wan-relay-session-design.md` as the authoritative design.
- Use `superpowers:test-driven-development` for every behavior change: observe the focused RED test, add only the smallest implementation, then run the focused and neighboring GREEN suites.
- Before claiming completion, use `superpowers:verification-before-completion` and record the actual command output.
- Do not stage or rewrite unrelated dirty files. In particular, leave the existing changes under `mrd-file-transfer`, `mrd-quality-gate`, and `mrd-session` untouched.
- On this low-space Windows host, prefix Rust commands with:

  ```powershell
  $env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'
  ```

- Backend tests use a worktree-local `--basetemp .pytest_tmp/wan-session`; PostgreSQL-only rows additionally require `MRD_TEST_DATABASE_URL` and must skip explicitly when it is absent.
- Never place a device token, TURN credential, SDP, candidate line, signed grant body, or endpoint userinfo in IPC, persistence, snapshots, logs, errors, assertions, or test failure messages.
- Each commit below must stage only the paths named by that task. Run `git diff --check --cached` before committing.

### Task 1: Add the IPC route-preference contract

**Files:**

- Modify: `crates/mrd-ipc/src/lib.rs`
- Modify: `crates/mrd-ipc/tests/contracts.rs`
- Modify: `apps/Rdesk/src/app/adapters/tauri/types.ts`
- Modify: `apps/Rdesk/src/app/adapters/tauri/contract.test.ts`
- Modify: `apps/Rdesk/src/app/services/ipcSessionService.ts`
- Modify: `apps/Rdesk/src/app/services/ipcSessionService.test.ts`

**Step 1: Write the failing contract tests**

Add Rust fixtures proving that an omitted field deserializes as `Auto`, and that the wire values are exactly `auto`, `lan`, and `wan_relay`. Add TypeScript contract tests that send `route_preference: 'wan_relay'` and verify it reaches `RequestRemoteSession` unchanged.

```rust
assert_eq!(decoded.route_preference, RemoteRoutePreference::Auto);
assert_eq!(serde_json::to_value(RemoteRoutePreference::WanRelay)?, "wan_relay");
```

**Step 2: Run RED**

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-ipc --test contracts remote_route_preference
pnpm --dir apps/Rdesk test -- --run app/adapters/tauri/contract.test.ts app/services/ipcSessionService.test.ts
```

Expected: Rust cannot resolve `RemoteRoutePreference`; TypeScript rejects the new property.

**Step 3: Implement the minimal contract**

Add a snake-case enum with `Default` returning `Auto`, then add `#[serde(default)] pub route_preference` to `RemoteSessionRequest`. Mirror it with a closed TypeScript union. Keep all existing callers source-compatible by having the service helper insert `auto` when no preference is supplied.

**Step 4: Run GREEN**

Run the RED commands again, then:

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-ipc
pnpm --dir apps/Rdesk type-check
```

**Step 5: Commit**

```powershell
git add crates/mrd-ipc/src/lib.rs crates/mrd-ipc/tests/contracts.rs apps/Rdesk/src/app/adapters/tauri/types.ts apps/Rdesk/src/app/adapters/tauri/contract.test.ts apps/Rdesk/src/app/services/ipcSessionService.ts apps/Rdesk/src/app/services/ipcSessionService.test.ts
git diff --check --cached
git commit -m "feat: add remote route preference contract"
```

### Task 2: Define authenticated initial-session protocol v3

**Files:**

- Create: `crates/mrd-signal-proto/src/initial_v3.rs`
- Modify: `crates/mrd-signal-proto/src/lib.rs`
- Modify: `crates/mrd-signal-proto/src/authenticated.rs`
- Create: `crates/mrd-signal-proto/tests/initial_v3.rs`
- Modify: `crates/mrd-signal-proto/tests/authenticated_messages.rs`

**Step 1: Write failing protocol and golden-vector tests**

Cover:

- bounded and normalized attended intent scopes/profile;
- an intent commitment included verbatim by the grant;
- a grant commitment included by offer, answer, and candidate;
- non-empty, sorted, duplicate-free, bounded candidate fingerprint manifests;
- domain-separated candidate fingerprints including description role, MID, index, username fragment, and candidate payload;
- signature, intended-peer, lifetime, replay, wrong role, manifest mutation, and grant mismatch failures;
- envelope version 3 required for v3 initial messages;
- envelope version 2 initial intent/grant/offer/answer/candidate rejected;
- existing version 2 registration, close/reconnect, and relay-migration vectors still accepted.

```rust
let offer = WebRtcOfferV3::sign(&controller, payload)?;
assert!(offer.verify_candidate_manifest(&candidates).is_ok());
assert_eq!(SignalEnvelope::new(offer.into()).version, 3);
```

**Step 2: Run RED**

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-signal-proto --test initial_v3
```

Expected: the `initial_v3` module and v3 message variants do not exist.

**Step 3: Implement the v3 types and version pairing**

Create closed structs for `SessionIntentV3`, `SessionGrantV3`, `WebRtcOfferV3`, `WebRtcAnswerV3`, and `WebRtcCandidateV3`. Reuse `AuthClaims` and the established signed-message primitives, but give every commitment a distinct context string. Do not put TURN credentials in any type.

Change envelope validation from one global constant to an allowed `(version, message kind)` pairing:

- version 3: v3 intent, grant, WebRTC description, and WebRTC candidate;
- version 2: existing server/auth/presence/deny/close/reconnect and relay-migration messages;
- version 2 legacy initial messages: deserialize only far enough to return `UnsupportedVersion`, never route them;
- every cross-version pairing: reject.

Make `SignalEnvelope::new` derive the required version from the message. Retain legacy v2 Rust types only for explicit rejection and compatibility tests; mark constructors unavailable to new initial-session callers.

**Step 4: Run GREEN**

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-signal-proto --test initial_v3
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-signal-proto
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo clippy -p mrd-signal-proto --all-targets -- -D warnings
```

**Step 5: Commit**

```powershell
git add crates/mrd-signal-proto/src/initial_v3.rs crates/mrd-signal-proto/src/lib.rs crates/mrd-signal-proto/src/authenticated.rs crates/mrd-signal-proto/tests/initial_v3.rs crates/mrd-signal-proto/tests/authenticated_messages.rs
git diff --check --cached
git commit -m "feat: define authenticated wan session v3"
```

### Task 3: Route v3 messages through the realtime server

**Files:**

- Modify: `apps/realtime-server/src/lib.rs`
- Modify: `apps/realtime-server/src/routes.rs`
- Modify: `apps/realtime-server/tests/authenticated_routing.rs`

**Step 1: Write failing routing tests**

Use two registered device sockets. Prove all five v3 message kinds route only to the signed intended peer, while a v2 initial message, cross-version envelope, wrong room/peer, oversized manifest, or invalid signature is rejected and never delivered. Assert only stable error codes, never raw message bodies.

**Step 2: Run RED**

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p realtime-server --test authenticated_routing v3_initial
```

Expected: v3 variants are not matched/routed.

**Step 3: Implement blind routing**

Extend the exhaustive message match and route policy to v3. Validate envelope/message version pairing before signature and room checks. Route the opaque authenticated payload unchanged; do not interpret SDP/candidates and do not add TURN access to server state.

**Step 4: Run GREEN**

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p realtime-server --test authenticated_routing
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p realtime-server
```

**Step 5: Commit**

```powershell
git add apps/realtime-server/src/lib.rs apps/realtime-server/src/routes.rs apps/realtime-server/tests/authenticated_routing.rs
git diff --check --cached
git commit -m "feat: route authenticated wan session signals"
```

### Task 4: Persist device-bound requests and a shared relay-access generation

**Files:**

- Modify: `apps/Rdesk-Server/app/models/session_request.py`
- Create: `apps/Rdesk-Server/app/models/relay_access_generation.py`
- Modify: `apps/Rdesk-Server/app/models/__init__.py`
- Modify: `apps/Rdesk-Server/app/db/migrate_add_relay_access.py`
- Modify: `apps/Rdesk-Server/tests/test_relay_directory_postgres.py`
- Create: `apps/Rdesk-Server/tests/test_wan_session_migration.py`

**Step 1: Write failing migration/model tests**

Require `session_requests` to persist requester device, normalized request payload/digest, access mode, route policy, requested/approved scopes and profile, policy expiry, and active relay generation. Require a unique generation row keyed by `(session_id, generation)` with directory ID, canonical signed public directory, signature/key ID, URL digest, primary node, reservation IDs, and expiry.

Tests must prove the generation row has no username, password, token, or credential column and that active generation uniqueness survives concurrent transactions.

**Step 2: Run RED**

```powershell
python -m pytest apps/Rdesk-Server/tests/test_wan_session_migration.py --basetemp .pytest_tmp/wan-session -q
```

Expected: model/table/columns are missing. PostgreSQL assertions skip with an explicit reason when `MRD_TEST_DATABASE_URL` is unavailable.

**Step 3: Implement an additive migration and models**

Add constrained, indexed columns and a `RelayAccessGeneration` model. The row stores only the signed public directory and reservation references; participant TURN credentials remain derived/ephemeral. Use an additive, idempotent migration and backfill only safe nullable/default values. Add foreign keys and checks for attended + relay-only approved WAN rows.

**Step 4: Run GREEN**

```powershell
python -m pytest apps/Rdesk-Server/tests/test_wan_session_migration.py apps/Rdesk-Server/tests/test_relay_directory_postgres.py --basetemp .pytest_tmp/wan-session -q
python -m pytest apps/Rdesk-Server/tests/test_app_startup_contract.py --basetemp .pytest_tmp/wan-session -q
```

**Step 5: Commit**

```powershell
git add apps/Rdesk-Server/app/models/session_request.py apps/Rdesk-Server/app/models/relay_access_generation.py apps/Rdesk-Server/app/models/__init__.py apps/Rdesk-Server/app/db/migrate_add_relay_access.py apps/Rdesk-Server/tests/test_relay_directory_postgres.py apps/Rdesk-Server/tests/test_wan_session_migration.py
git diff --check --cached
git commit -m "feat: persist wan session relay generations"
```

### Task 5: Add device-authenticated session request and lifecycle endpoints

**Files:**

- Modify: `apps/Rdesk-Server/app/schemas/session.py`
- Create: `apps/Rdesk-Server/app/services/device_sessions.py`
- Create: `apps/Rdesk-Server/app/api/v1/device_sessions.py`
- Modify: `apps/Rdesk-Server/app/api/v1/router.py`
- Create: `apps/Rdesk-Server/tests/test_device_session_api.py`

**Step 1: Write failing API tests**

Cover create, inspect, reject, close, and revoke using device bearer authentication. Require:

- authoritative caller-supplied session ID;
- requester device belongs to the derived user and differs from target;
- only the exact target device can reject;
- only either exact participant can inspect/close;
- exact retry returns the same row;
- conflicting session-ID reuse returns a privacy-preserving conflict;
- unattended or non-relay WAN requests fail closed;
- user tokens and device tokens are not interchangeable.

```python
response = await controller.post(
    "/api/v1/device-sessions",
    json={"session_id": session_id, "target_device_id": target_id, ...},
)
assert response.json()["request_commitment"] == expected_commitment
```

**Step 2: Run RED**

```powershell
python -m pytest apps/Rdesk-Server/tests/test_device_session_api.py --basetemp .pytest_tmp/wan-session -q
```

Expected: endpoint returns 404.

**Step 3: Implement the device-auth service and router**

Derive user/device identity only from the existing device-auth dependency. Canonicalize the request before computing its commitment. Lock the session row for transitions, return closed schemas, emit sanitized audit actions, and make terminal transitions idempotent. Approval is deliberately added in Task 6 because it must share one database transaction with capacity reservation and directory creation.

**Step 4: Run GREEN**

```powershell
python -m pytest apps/Rdesk-Server/tests/test_device_session_api.py apps/Rdesk-Server/tests/test_device_ownership.py apps/Rdesk-Server/tests/test_session_grants.py --basetemp .pytest_tmp/wan-session -q
```

**Step 5: Commit**

```powershell
git add apps/Rdesk-Server/app/schemas/session.py apps/Rdesk-Server/app/services/device_sessions.py apps/Rdesk-Server/app/api/v1/device_sessions.py apps/Rdesk-Server/app/api/v1/router.py apps/Rdesk-Server/tests/test_device_session_api.py
git diff --check --cached
git commit -m "feat: add device authenticated session lifecycle"
```

### Task 6: Make approval, capacity, and shared access generation atomic

**Files:**

- Modify: `apps/Rdesk-Server/app/services/device_sessions.py`
- Modify: `apps/Rdesk-Server/app/services/session_grants.py`
- Modify: `apps/Rdesk-Server/app/services/relay_directory.py`
- Modify: `apps/Rdesk-Server/app/api/v1/device_sessions.py`
- Modify: `apps/Rdesk-Server/app/api/v1/relays.py`
- Modify: `apps/Rdesk-Server/tests/test_device_session_api.py`
- Create: `apps/Rdesk-Server/tests/test_wan_relay_access.py`
- Modify: `apps/Rdesk-Server/tests/test_relay_directory_postgres.py`

**Step 1: Write failing atomicity and concurrency tests**

Prove:

- only the exact target device can approve;
- approval locks the request, binds approved scopes/profile/policy, selects primary plus cross-failure-domain backups, reserves capacity, and creates generation zero in one transaction;
- concurrent duplicate approvals yield one active generation and one reservation set;
- any selection/reservation/signing failure rolls back approval and releases partial capacity;
- controller and target fetching generation zero receive the same directory ID, ordering, endpoint URL digest, reservation IDs, signature, and expiry;
- their ephemeral credentials may differ and are authorized only for the participant making the request;
- a requested generation mismatch, expired policy, revocation, or unrelated device fails closed;
- refresh serializes a new generation and never mutates an old signed directory.

**Step 2: Run RED**

```powershell
python -m pytest apps/Rdesk-Server/tests/test_wan_relay_access.py --basetemp .pytest_tmp/wan-session -q
```

Expected: approval route and stable shared-generation behavior are absent; current repeated access fetches produce different directory IDs.

**Step 3: Implement the transaction boundary**

Move public-directory creation behind a session-row lock. Persist the canonical signed directory before commit, derive participant credentials after authorization, and reconstruct each response by combining the immutable public generation with only that device's credentials. Keep the existing relay capacity/release repository as the single capacity authority. On every exception, execute deterministic `ReleaseAll` for allocations not owned by a committed generation.

Both participants must request access with intended peer equal to the target device: controller passes the target; target passes itself.

**Step 4: Run GREEN**

```powershell
python -m pytest apps/Rdesk-Server/tests/test_wan_relay_access.py apps/Rdesk-Server/tests/test_device_session_api.py apps/Rdesk-Server/tests/test_relay_directory.py apps/Rdesk-Server/tests/test_session_grants.py --basetemp .pytest_tmp/wan-session -q
python -m pytest apps/Rdesk-Server/tests/test_relay_directory_postgres.py apps/Rdesk-Server/tests/test_relay_repository_postgres.py --basetemp .pytest_tmp/wan-session -q
```

**Step 5: Commit**

```powershell
git add apps/Rdesk-Server/app/services/device_sessions.py apps/Rdesk-Server/app/services/session_grants.py apps/Rdesk-Server/app/services/relay_directory.py apps/Rdesk-Server/app/api/v1/device_sessions.py apps/Rdesk-Server/app/api/v1/relays.py apps/Rdesk-Server/tests/test_device_session_api.py apps/Rdesk-Server/tests/test_wan_relay_access.py apps/Rdesk-Server/tests/test_relay_directory_postgres.py
git diff --check --cached
git commit -m "feat: issue atomic shared relay access generations"
```

### Task 7: Add the service-owned device-auth backend client

**Files:**

- Create: `apps/mrd-service/src/wan_session/mod.rs`
- Create: `apps/mrd-service/src/wan_session/config.rs`
- Create: `apps/mrd-service/src/wan_session/backend.rs`
- Modify: `apps/mrd-service/src/lib.rs`
- Modify: `apps/mrd-service/src/app_state.rs`
- Create: `apps/mrd-service/tests/wan_session_backend.rs`

**Step 1: Write failing client tests**

Drive a fake HTTP backend and verify typed create/inspect/approve/reject/close/revoke/access operations, bounded body sizes, strict deadlines, retry only for safe/idempotent calls, stable error mapping, and cancellation. Inspect captured headers to prove only the configured device token is sent. Prove `Debug`, errors, tracing, and serialized test snapshots contain neither token nor returned credentials.

**Step 2: Run RED**

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-service --test wan_session_backend
```

Expected: `wan_session::backend` does not exist.

**Step 3: Implement an abstract port and HTTP adapter**

Define a `WanSessionBackend` trait for coordinator tests and one production HTTP adapter using the existing service relay/backend configuration conventions. Store secrets in redacted/zeroizing wrappers, deserialize closed response DTOs, verify returned session/generation IDs, and expose no raw HTTP body in errors.

**Step 4: Run GREEN**

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-service --test wan_session_backend
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-service --test relay_directory
```

**Step 5: Commit**

```powershell
git add apps/mrd-service/src/wan_session/mod.rs apps/mrd-service/src/wan_session/config.rs apps/mrd-service/src/wan_session/backend.rs apps/mrd-service/src/lib.rs apps/mrd-service/src/app_state.rs apps/mrd-service/tests/wan_session_backend.rs
git diff --check --cached
git commit -m "feat: add wan session backend client"
```

### Task 8: Generalize the authenticated signaling bus for v3 sessions

**Files:**

- Modify: `crates/mrd-application/src/lib.rs`
- Modify: `apps/mrd-service/src/signaling/runtime.rs`
- Modify: `apps/mrd-service/src/signaling/event_mapper.rs`
- Modify: `apps/mrd-service/src/signaling/mod.rs`
- Modify: `apps/mrd-service/tests/signaling_runtime.rs`

**Step 1: Write failing bus/mapping tests**

Add bounded outbound commands and inbound application events for all v3 initial messages. Test exact session/peer routing, backpressure, reconnect, duplicate delivery, invalid-v2 rejection, and queue cleanup on close. Existing relay-migration tests must remain unchanged and green.

**Step 2: Run RED**

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-service --test signaling_runtime v3_initial
```

Expected: the runtime has only `OutboundRelayMigrationSignal`, and initial events are validation-only.

**Step 3: Implement a bounded generic bus**

Introduce `OutboundAuthenticatedSessionSignal`/command types that can carry the v3 signed envelopes without exposing their bodies in `Debug`. Map verified v3 messages into `AuthenticatedSessionSignal` with metadata and the typed signed payload. Preserve the existing migration command API through an adapter so generation-1 behavior does not change in this task.

**Step 4: Run GREEN**

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-service --test signaling_runtime
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-application
```

**Step 5: Commit**

```powershell
git add crates/mrd-application/src/lib.rs apps/mrd-service/src/signaling/runtime.rs apps/mrd-service/src/signaling/event_mapper.rs apps/mrd-service/src/signaling/mod.rs apps/mrd-service/tests/signaling_runtime.rs
git diff --check --cached
git commit -m "feat: carry wan session signaling through service"
```

### Task 9: Build the role-aware WAN session state machine

**Files:**

- Create: `apps/mrd-service/src/wan_session/model.rs`
- Create: `apps/mrd-service/src/wan_session/coordinator.rs`
- Modify: `apps/mrd-service/src/wan_session/mod.rs`
- Modify: `apps/mrd-service/src/app_state.rs`
- Create: `apps/mrd-service/tests/wan_session_state.rs`

**Step 1: Write failing state-machine tests**

Use fake backend, signaling, clock, relay access, transport, media, input, and cleanup ports. Cover both roles across:

```text
Created -> BackendBound -> AwaitingConsent -> Granted -> AccessBound
        -> Negotiating -> RelayVerified -> Streaming -> Closed | Failed
```

Require exact-duplicate idempotency, conflicting duplicate failure, no skipped phase, immutable identities/keys/policy/generation, one absolute negotiation deadline, bounded buffering/retries, attended-only approval, and joined cleanup after failure at every construction phase.

**Step 2: Run RED**

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-service --test wan_session_state
```

Expected: coordinator/state types do not exist.

**Step 3: Implement pure transition logic first, then orchestration**

Keep the transition model deterministic and independent of HTTP/WebRTC. Add a coordinator registry keyed by `SessionId`, with bounded concurrent sessions and one owned cancellation/task group per session. The controller creates backend state then sends intent. The target verifies intent against an independently fetched backend request and publishes an IPC consent event without opening WebRTC or reserving capacity. Approval installs the exact backend policy and shared generation.

On terminalization: freeze input, stop media, close transport, remove relay failover state, clear signaling buffers, close/revoke backend state when possible, and join every task.

**Step 4: Run GREEN**

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-service --test wan_session_state
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-service --test session_authorization
```

If `session_authorization` is unit-only rather than an integration target, replace the second command with `cargo test -p mrd-service session_authorization` and record that adjustment in the task log.

**Step 5: Commit**

```powershell
git add apps/mrd-service/src/wan_session/model.rs apps/mrd-service/src/wan_session/coordinator.rs apps/mrd-service/src/wan_session/mod.rs apps/mrd-service/src/app_state.rs apps/mrd-service/tests/wan_session_state.rs
git diff --check --cached
git commit -m "feat: coordinate attended wan session authorization"
```

### Task 10: Execute generation-zero WebRTC negotiation and route proof

**Files:**

- Create: `apps/mrd-service/src/wan_session/webrtc.rs`
- Modify: `apps/mrd-service/src/wan_session/coordinator.rs`
- Modify: `apps/mrd-service/src/wan_session/mod.rs`
- Modify: `apps/mrd-service/src/transports/webrtc.rs`
- Modify: `apps/mrd-service/src/relay/runtime.rs`
- Create: `apps/mrd-service/tests/wan_session_negotiation.rs`

**Step 1: Write failing negotiation tests**

With a fake `WebRtcHost`, verify:

- no peer opens before approval and verified access;
- relay-only URL configuration uses only the signed primary node;
- offerer gathers a complete bounded candidate set before signing/sending the offer manifest, then sends exactly those candidates;
- answerer follows the same manifest-before-candidates rule;
- out-of-order remote candidates are buffered, bounded, fingerprint-checked, and applied only after the matching signed description and local grant;
- missing, extra, mutated, duplicated, or wrong-role candidates fail terminally;
- `wait_connected` must finish before route proof;
- selected pair is relay/relay and its normalized URL digest/node ID matches the immutable generation;
- `install_connected_relay_session` is called exactly once only after proof;
- timeout/cancel closes the physical peer and publishes no media authority.

**Step 2: Run RED**

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-service --test wan_session_negotiation
```

Expected: generation-zero executor is absent.

**Step 3: Implement by adapting the proven migration manifest pattern**

Use `relay/executor.rs` only as an implementation pattern, not as generation-zero state. Add the smallest transport-host API needed to signal candidate gathering completion and obtain sanitized selected-pair evidence. Keep raw SDP/candidates inside the signed protocol/host boundary. After exact proof, call `install_connected_relay_session` with generation zero so the existing failover coordinator owns generation 1+.

**Step 4: Run GREEN**

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-service --test wan_session_negotiation
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-service --test relay_failover --test signaling_runtime
```

**Step 5: Commit**

```powershell
git add apps/mrd-service/src/wan_session/webrtc.rs apps/mrd-service/src/wan_session/coordinator.rs apps/mrd-service/src/wan_session/mod.rs apps/mrd-service/src/transports/webrtc.rs apps/mrd-service/src/relay/runtime.rs apps/mrd-service/tests/wan_session_negotiation.rs
git diff --check --cached
git commit -m "feat: negotiate verified generation zero relay sessions"
```

### Task 11: Dispatch IPC routes and automatically start authorized media

**Files:**

- Modify: `apps/mrd-service/src/handlers/session.rs`
- Modify: `apps/mrd-service/src/handlers/transport.rs`
- Modify: `apps/mrd-service/src/ipc_server/dispatch.rs`
- Modify: `apps/mrd-service/src/app_state.rs`
- Create: `apps/mrd-service/src/wan_session/media.rs`
- Modify: `apps/mrd-service/src/wan_session/mod.rs`
- Create: `apps/mrd-service/tests/wan_session_dispatch.rs`
- Modify: `apps/mrd-service/tests/agent_media_routing.rs`
- Modify: `apps/Rdesk/src/app/components/RemoteSessionModal.tsx`
- Create: `apps/Rdesk/src/app/components/RemoteSessionModal.test.tsx`
- Modify: `apps/Rdesk/src/app/services/ipcSessionService.test.ts`

**Step 1: Write failing dispatch/media/UI tests**

Prove:

- `Lan` invokes only secure LAN bootstrap and never falls back;
- `WanRelay` invokes only the WAN coordinator;
- `Auto` chooses LAN only from an already-fresh, signed, public-key-pinned target discovery record, otherwise immediately chooses WAN without a discovery wait;
- unattended WAN fails before backend/signaling/WebRTC calls;
- consent approve/reject events call the coordinator for the exact session;
- target capture/send and controller receive/render start automatically only after `RelayVerified` and only for approved scopes/profile;
- input remains frozen until the existing control evidence barrier passes;
- media startup failure closes the session and removes failover state;
- the modal exposes Auto/LAN/WAN Relay with Auto default and sends only the enum, no secrets.

**Step 2: Run RED**

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-service --test wan_session_dispatch
pnpm --dir apps/Rdesk test -- --run app/components/RemoteSessionModal.test.tsx app/services/ipcSessionService.test.ts
```

Expected: handler always enters LAN and the UI has no route selector.

**Step 3: Implement route selection and activation barriers**

Extract a pure route-selection function. Query only the existing authenticated discovery cache for `Auto`; do not initiate discovery. Dispatch WAN work to the coordinator and project its snapshots/events through existing IPC types. Add a media activation port whose target/controller actions are role-specific and whose authority token can be created only from `RelayVerified` plus the installed grant.

**Step 4: Run GREEN**

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-service --test wan_session_dispatch --test agent_media_routing --test agent_input_routing
pnpm --dir apps/Rdesk test -- --run app/components/RemoteSessionModal.test.tsx app/services/ipcSessionService.test.ts app/adapters/tauri/contract.test.ts
pnpm --dir apps/Rdesk type-check
```

**Step 5: Commit**

```powershell
git add apps/mrd-service/src/handlers/session.rs apps/mrd-service/src/handlers/transport.rs apps/mrd-service/src/ipc_server/dispatch.rs apps/mrd-service/src/app_state.rs apps/mrd-service/src/wan_session/media.rs apps/mrd-service/src/wan_session/mod.rs apps/mrd-service/tests/wan_session_dispatch.rs apps/mrd-service/tests/agent_media_routing.rs apps/Rdesk/src/app/components/RemoteSessionModal.tsx apps/Rdesk/src/app/components/RemoteSessionModal.test.tsx apps/Rdesk/src/app/services/ipcSessionService.test.ts
git diff --check --cached
git commit -m "feat: start remote sessions through verified wan relays"
```

### Task 12: Exercise the complete service-to-service flow with real coturn

**Files:**

- Create: `apps/mrd-service/tests/wan_session_e2e.rs`
- Modify: `apps/mrd-service/Cargo.toml`
- Modify: `tests/integration/multi_region_relay.rs`
- Modify: `tests/benchmarks/scripts/multi_region_relay_common.ps1`
- Modify: `tests/benchmarks/scripts/test_multi_region_relay.ps1`
- Modify: `tests/benchmarks/scripts/run_multi_region_relay.ps1`
- Modify: `crates/mrd-quality-gate/tests/artifact_validation.rs`
- Modify: `docs/release/multi-region-turn-relay-acceptance.md`

**Step 1: Add ignored live integration rows and evidence schema tests**

Build a harness with two service runtimes, the realtime server, FastAPI, and pinned coturn. Add rows for UDP, TCP, and TLS generation zero; target rejection; capacity exhaustion; backend loss before approval; signaling disconnect; expired generation; service restart; primary failure followed by cross-failure-domain migration; and deterministic `ReleaseAll`.

Each passing row must prove authorization, one shared generation, reservation ownership, relay/relay selected pair, actual media/control/realtime-control traffic, migration, and cleanup. Static fixtures or listening ports are not success.

**Step 2: Run RED on the non-live harness contract**

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-service --test wan_session_e2e evidence_contract
```

Expected: harness/evidence row types do not exist.

**Step 3: Implement the harness and gate wiring**

Reuse the exact pinned coturn image already documented in the acceptance file. Keep live rows `#[ignore]` unless the runner supplies their explicit environment contract. Add invocation-bound evidence IDs and preserve `INFRA_FAIL` for missing two-region/different-failure-domain/Linux-to-Windows topology. Never convert an ignored or unavailable row to `PASS`.

**Step 4: Run GREEN locally, then the available live rows**

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-service --test wan_session_e2e evidence_contract
powershell -ExecutionPolicy Bypass -File tests/benchmarks/scripts/run_multi_region_relay.ps1 -Scenario initial_wan_local
```

Expected local result: UDP/TCP/TLS rows pass when Docker/coturn are available; unavailable external multi-region or Windows rows remain explicit `INFRA_FAIL`. Verify every temporary container created by the invocation is removed by exact name; do not remove unrelated containers or the cached image.

**Step 5: Commit**

```powershell
git add apps/mrd-service/tests/wan_session_e2e.rs apps/mrd-service/Cargo.toml tests/integration/multi_region_relay.rs tests/benchmarks/scripts/multi_region_relay_common.ps1 tests/benchmarks/scripts/test_multi_region_relay.ps1 tests/benchmarks/scripts/run_multi_region_relay.ps1 crates/mrd-quality-gate/tests/artifact_validation.rs docs/release/multi-region-turn-relay-acceptance.md
git diff --check --cached
git commit -m "test: gate initial wan relay sessions"
```

### Task 13: Run regression, security, and completion verification

**Files:**

- Modify if evidence changes: `docs/release/multi-region-turn-relay-acceptance.md`
- Modify if commands change: `docs/plans/2026-08-26-wan-relay-session.md`

**Step 1: Run focused Rust verification**

```powershell
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-signal-proto
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p realtime-server
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo test -p mrd-service
$env:CARGO_INCREMENTAL='0'; $env:RUSTFLAGS='-C debuginfo=0'; $env:CARGO_BUILD_JOBS='1'; cargo clippy -p mrd-signal-proto -p realtime-server -p mrd-service --lib --bins -- -D warnings
```

If all-target clippy remains blocked only by the documented pre-existing `vendor/nvenc` warnings, record the exact output and do not describe it as an implementation pass.

**Step 2: Run backend and frontend verification**

```powershell
Push-Location apps/Rdesk-Server
try {
  New-Item -ItemType Directory -Force .pytest_tmp | Out-Null
  python -m pytest tests --basetemp .pytest_tmp/wan-session -q
} finally {
  Pop-Location
}
pnpm --dir apps/Rdesk test -- --run
pnpm --dir apps/Rdesk type-check
pnpm --dir apps/Rdesk build
```

**Step 3: Run secret-negative and repository checks**

```powershell
rg -n "turn.*password|Authorization: Bearer|candidate:|a=ice-pwd|a=ice-ufrag" apps/mrd-service docs/release apps/Rdesk-Server/tests apps/mrd-service/tests
git diff --check
git status --short
```

Inspect every match. Test fixture generators may construct secrets in memory, but snapshots, logs, errors, committed evidence, and assertions must not contain real secret values or raw SDP/candidates.

**Step 4: Update acceptance evidence honestly**

Record command, timestamp, commit, topology, row result, evidence artifact, and cleanup. Product status becomes `PASS` only after real Linux-to-Linux and Linux-to-Windows rows across at least two regions/different failure domains pass. Otherwise retain `INFRA_FAIL` while separately recording all local/unit/integration passes.

**Step 5: Request review and commit only necessary evidence changes**

Use `superpowers:requesting-code-review`, address findings through `superpowers:receiving-code-review`, rerun affected suites, then:

```powershell
git add docs/release/multi-region-turn-relay-acceptance.md docs/plans/2026-08-26-wan-relay-session.md
git diff --check --cached
git commit -m "docs: record initial wan relay verification"
```

Skip this commit if neither file changed. Finish with `superpowers:finishing-a-development-branch`; do not merge, push, or delete the worktree without the user's explicit choice.
