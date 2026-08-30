# Core Production Remediation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Turn the audited relay, WAN, desktop, IPC, packaging, and release paths into one fail-closed, production-verifiable remote desktop system.

**Architecture:** Keep `SessionAuthorizationRegistry` as the permission authority, `WanSessionCoordinator` as the workflow owner, and installed transport/media tasks as the only source of connected/streaming truth. Roll out relay renewal reader-before-writer, wire WAN side effects through rollback receipts, and make every UI/API entrypoint consume the same authenticated session workflow.

**Tech Stack:** Rust/Tokio, FastAPI/SQLAlchemy/PostgreSQL, React/TypeScript/Tauri, WebRTC, PowerShell, GitHub Actions.

---

### Task 1: Make relay certificate renewal policy explicit and bounded

**Files:**
- Modify: `apps/mrd-relay-agent/src/backend.rs`
- Modify: `apps/mrd-relay-agent/src/identity.rs`
- Modify: `apps/mrd-relay-agent/src/runtime.rs`
- Modify: `apps/mrd-relay-agent/src/main.rs`
- Modify: `apps/mrd-relay-agent/tests/runtime.rs`
- Modify: `apps/Rdesk-Server/app/core/config.py`
- Modify: `apps/Rdesk-Server/app/api/v1/relays.py`
- Modify: `apps/Rdesk-Server/.env.example`
- Test: `apps/Rdesk-Server/tests/test_security_configuration.py`
- Test: `apps/Rdesk-Server/tests/test_relay_lifecycle_hardening.py`

**Step 1: Write the failing agent regression test**

Add a production-worker test with a one-hour certificate and a server-provided
renew-at value 10 minutes before expiry. Advance three heartbeat cycles and
assert no renewal occurs; advance to renew-at and assert exactly one renewal.
Also assert the renewed certificate receives a later renew-at and cannot renew
again in the same cycle.

```rust
assert_eq!(backend.renewal_count(), 0);
clock.set_unix_seconds(renew_at);
worker.cycle().await.unwrap();
assert_eq!(backend.renewal_count(), 1);
worker.cycle().await.unwrap();
assert_eq!(backend.renewal_count(), 1);
```

**Step 2: Run RED**

Run: `cargo test --locked -p mrd-relay-agent backend_worker_does_not_repeatedly_renew_short_lived_certificates -- --exact`

Expected: FAIL because certificate state has no persisted renew-at and runtime
still uses the 24-hour constant.

**Step 3: Implement the agent reader**

- Add `renew_at_unix_seconds` to `NodeCertificate` and `StoredCertificate`.
- Read bounded `x-relay-renew-at` response headers for pickup and renewal.
- When the header is absent, derive one conservative time from the validated
  X.509 not-before/not-after interval.
- Atomically persist it with the certificate.
- Replace `expires_at - renewal_window` with the stored value.
- Remove the hard-coded 24-hour value from `main.rs`.
- Reject schedules outside the certificate interval or already due on a newly
  issued certificate.

**Step 4: Run agent GREEN and regression suite**

Run: `cargo test --locked -p mrd-relay-agent`

Expected: all agent tests pass.

**Step 5: Write failing backend configuration and wire tests**

Add tests proving startup rejects `renew_before >= validity / 2`, and pickup
plus renewal return the exact bounded renew-at header.

**Step 6: Run backend RED**

Run: `python -m pytest tests/test_security_configuration.py tests/test_relay_lifecycle_hardening.py -q`

Expected: new assertions fail because the configuration is currently accepted
and no header is emitted.

**Step 7: Implement the backend writer**

- Default certificate validity to a bounded value and renewal lead to at most
  one third of validity.
- Validate the relationship in `Settings.validate_security_boundary`.
- Emit `x-relay-renew-at` on enrollment pickup and renewal.
- Preserve health state and the bounded current lease for a routine,
  authenticated renewal while resetting only identity replay state.

**Step 8: Run GREEN and commit**

Run: `python -m pytest tests/test_security_configuration.py tests/test_relay_lifecycle_hardening.py tests/test_relay_node_api.py -q`

Commit: `fix: stabilize relay certificate renewal lifecycle`

### Task 2: Close Backend tenant and process-control authorization gaps

**Files:**
- Modify: `apps/Rdesk-Server/app/api/v1/network_groups.py`
- Modify: `apps/Rdesk-Server/app/api/v1/realtime.py`
- Modify: `apps/Rdesk-Server/app/services/realtime_manager.py`
- Create: `apps/Rdesk-Server/tests/test_network_groups_api.py`
- Modify: `apps/Rdesk-Server/tests/test_realtime_api.py`
- Modify: `apps/Rdesk-Server/tests/test_realtime_manager.py`

**Step 1: Write cross-tenant RED tests**

Create two tenants/users/devices. Authenticate user A and assert add, patch,
remove, and list cannot expose user B's device even when its public device ID
is known. Assert user A's own bound device still works.

**Step 2: Run RED**

Run: `python -m pytest tests/test_network_groups_api.py -q`

Expected: cross-tenant add succeeds or leaks the foreign device.

**Step 3: Implement one ownership predicate**

Add a shared local query helper that requires, for non-privileged access:

```python
Device.tenant_id == current_user.tenant_id
Device.is_bound.is_(True)
Device.bound_user_id == current_user.id
```

Use it for add, remove, patch, and group-device reads. An administrator bypass
must be explicit and audited rather than implied by a missing filter.

**Step 4: Run network-group GREEN**

Run: `python -m pytest tests/test_network_groups_api.py tests/test_device_ownership.py -q`

**Step 5: Write realtime authorization and concurrency RED tests**

- Anonymous status/start/stop/restart return 401.
- Authenticated non-admin may read status but receives 403 for mutations.
- Admin mutations succeed.
- Two concurrent starts create at most one child process.

**Step 6: Implement realtime authorization and lock**

Use `Depends(get_current_user)` for status and an admin dependency for
mutations. Protect manager start/stop/restart with one lock and make repeated
operations idempotent.

**Step 7: Run GREEN and commit**

Run: `python -m pytest tests/test_realtime_api.py tests/test_realtime_manager.py -q`

Commit: `fix: enforce tenant and realtime control authorization`

### Task 3: Remove fixed credentials and false bootstrap behavior

**Files:**
- Delete or rewrite: `apps/Rdesk-Server/check_db.py`
- Modify: `apps/Rdesk/src/app/components/AuthModal.tsx`
- Create: `apps/Rdesk/src/app/components/AuthModal.security.test.tsx`
- Modify: `apps/Rdesk-Server/tests/test_security_configuration.py`

**Step 1: Write RED tests**

- Assert source/build output contains no `admin123` bootstrap path.
- Assert the login UI has no default-credential autofill control.
- Assert explicit environment bootstrap remains supported and requires the
  existing minimum password length.

**Step 2: Run RED**

Run: `python -m pytest tests/test_security_configuration.py -q`

Run: `pnpm test -- AuthModal`

Expected: fixed-credential assertions fail.

**Step 3: Remove fixed credentials**

Delete the legacy script or turn it into a read-only health inspection command
that calls no user-creation function. Remove the credential hint and autofill
button. Keep only explicit environment bootstrap.

**Step 4: Run GREEN and commit**

Commit: `fix: remove fixed administrator credentials`

### Task 4: Repair deterministic CI and local contract failures

**Files:**
- Modify: `.github/workflows/rust.yml`
- Modify: `.github/workflows/relay-control.yml`
- Modify: `apps/mrd-relay-agent/tests/cli_contract.rs`
- Modify: `apps/mrd-service/src/lan_discovery/security_negative_evidence_tests.rs`
- Modify: `deploy/turn/test_deploy_contract.ps1`
- Modify: `crates/mrd-ffmpeg/src/lib.rs`
- Add or modify: `.gitattributes`

**Step 1: Reproduce each failure**

Run the exact failing Linux CLI tests, UDP test repeatedly, TURN contract on a
CRLF checkout, and workspace clippy. Record the original failure in the commit
message or test name.

**Step 2: Write/adjust RED contracts**

- Relay CLI fixtures use a root-owned production-valid location on Linux
  without weakening secure-store checks.
- UDP evidence test reuses the original socket or asks the OS for a new port;
  it never drop/rebinds the same ephemeral port.
- TURN regex accepts canonical LF after normalizing `\r\n` at file-read time.
- Backend workflow executes `python -m pytest`, not unittest discovery.
- PowerShell captures native exit codes without `2>&1 | Tee-Object` changing
  failure semantics.

**Step 3: Implement minimal fixes**

Remove the useless `PathBuf::from`, add workspace-wide fmt/clippy commands,
and extend Relay workflow path filters to deployment, service relay, and test
paths.

**Step 4: Verify and commit**

Run: `cargo fmt --all -- --check`

Run: `cargo clippy --workspace --all-targets --locked -- -D warnings`

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File deploy/turn/test_deploy_contract.ps1`

Commit: `fix: make core release checks deterministic`

### Task 5: Create controller-side WAN authorization before signaling

**Files:**
- Modify: `apps/mrd-service/src/handlers/session.rs`
- Modify: `apps/mrd-service/src/wan_session/service.rs`
- Modify: `apps/mrd-service/src/signaling/event_mapper.rs`
- Modify: `apps/mrd-service/tests/wan_session_dispatch.rs`
- Modify: `apps/mrd-service/tests/session_authorization.rs`

**Step 1: Write RED integration tests**

Exercise the production `RequestRemoteSession(WanRelay)` handler and assert an
outgoing authorization exists before the coordinator sends the intent. Feed a
verified matching grant and assert the authorization becomes `Granted`.
Tampered peer, scope, profile, commitment, or deadline must never grant.

**Step 2: Run RED**

Run: `cargo test --locked -p mrd-service --test wan_session_dispatch controller_wan_request_creates_and_grants_exact_authorization -- --exact`

Expected: authorization snapshot is absent.

**Step 3: Implement under the security gate**

Construct `VerifiedIncomingAuthorizationRequest`/outgoing equivalent from the
exact WAN request and call `begin_outgoing` before `start_controller`. On any
coordinator-start failure, record failure and remove the authorization. The
verified grant path binds peer key and records approval before negotiation.

**Step 4: Run GREEN and commit**

Run: `cargo test --locked -p mrd-service --test wan_session_dispatch --test session_authorization --test signaling_runtime`

Commit: `fix: bind WAN controller workflow to authorization`

### Task 6: Unify WAN query, stop, failure, revoke, and cleanup

**Files:**
- Modify: `apps/mrd-service/src/handlers/session.rs`
- Modify: `apps/mrd-service/src/ipc_server/dispatch.rs`
- Modify: `apps/mrd-service/src/wan_session/coordinator.rs`
- Modify: `apps/mrd-service/src/wan_session/service.rs`
- Modify: `apps/mrd-service/tests/wan_session_dispatch.rs`
- Modify: `apps/mrd-service/tests/wan_session_state.rs`

**Step 1: Write lifecycle RED tests**

Start controller and target sessions through production handlers, then query,
list, stop, fail, revoke, and repeat each terminal request. Assert coordinator,
authorization, media, WebRTC, failover, reservation, and projected snapshot
converge to one terminal result.

**Step 2: Run RED**

Run: `cargo test --locked -p mrd-service --test wan_session_dispatch`

Expected: controller query is missing and terminal handlers leave WAN state.

**Step 3: Implement one WAN-aware resolver and cleanup receipt**

Resolve session kind before dispatch. Serialize terminalization under the
security gate, fence new operations, invoke coordinator cleanup once, and only
then publish the terminal projection. Correct WAN audit action/transport names.

**Step 4: Run GREEN and commit**

Commit: `fix: complete WAN session lifecycle handling`

### Task 7: Reserve bitrate as well as allocations

**Files:**
- Modify: `apps/Rdesk-Server/app/services/device_sessions.py`
- Modify: `apps/Rdesk-Server/app/services/relay_directory.py`
- Modify: `apps/Rdesk-Server/app/models/relay_reservation.py`
- Create: `apps/Rdesk-Server/app/db/migrate_add_relay_reserved_egress.py`
- Modify: `apps/Rdesk-Server/tests/test_relay_directory.py`
- Modify: `apps/Rdesk-Server/tests/test_relay_directory_postgres.py`
- Modify: `apps/Rdesk-Server/tests/test_wan_relay_access.py`

**Step 1: Write RED capacity tests**

In PostgreSQL, concurrently request profiles whose individual bitrates fit but
whose sum exceeds node capacity. Assert only the bounded subset succeeds.
Assert close/expiry releases reserved bitrate, and migration overlap reserves
both routes only until its TTL.

**Step 2: Run RED**

Run: `python -m pytest tests/test_relay_directory.py tests/test_relay_directory_postgres.py tests/test_wan_relay_access.py -q`

**Step 3: Implement transactional bitrate reservations**

Derive required bps from the approved profile with bounded overhead. Store it
per allocation, sum active reservations under the existing advisory/row locks,
and require both allocation and bitrate headroom during selection.

**Step 4: Run GREEN and commit**

Commit: `feat: reserve relay bandwidth per WAN session`

### Task 8: Replace WAN metadata activation with real media tasks

**Files:**
- Modify: `apps/mrd-service/src/wan_session/media.rs`
- Modify: `apps/mrd-service/src/wan_session/service.rs`
- Modify: `apps/mrd-service/src/transports/webrtc.rs`
- Modify: `apps/mrd-service/src/app_state/media_pipeline_registry.rs`
- Modify: `apps/mrd-service/tests/wan_session_negotiation.rs`
- Create: `apps/mrd-service/tests/wan_session_media.rs`

**Step 1: Write media RED tests against production adapters**

Use a real bounded in-memory mux. For target role, prove capture/encode emits a
video envelope. For controller role, inject an encoded access unit and prove
decode/render readiness. Assert `Streaming` is absent before evidence and
present after it. Cancellation must stop all owned tasks.

**Step 2: Run RED**

Run: `cargo test --locked -p mrd-service --test wan_session_media`

Expected: no envelopes or tasks exist because activation only writes metadata.

**Step 3: Implement role-specific runtime adapters**

Reuse the existing capture, encode, receiver, decoder, renderer, and
`TransportMuxPort` components. Register task ownership and readiness evidence
in one media pipeline entry. Return a rollback receipt to the coordinator.

**Step 4: Run GREEN and commit**

Run: `cargo test --locked -p mrd-service --test wan_session_media --test wan_session_negotiation --test transport_mux`

Commit: `feat: run WAN media over authenticated WebRTC mux`

### Task 9: Route authenticated WAN control input over the mux

**Files:**
- Modify: `apps/mrd-service/src/wan_session/media.rs`
- Modify: `apps/mrd-service/src/handlers/session.rs`
- Modify: `apps/mrd-service/src/transports/webrtc.rs`
- Modify: `apps/mrd-service/tests/authorized_control_input.rs`
- Create: `apps/mrd-service/tests/wan_session_control_input.rs`

**Step 1: Write input RED tests**

Send pointer and keyboard input from the controller after a granted WAN
session. Assert the target receives and injects it once. Wrong peer, revoked
grant, missing scope, stale counter, duplicate, post-close input, and LAN-path
misrouting must all be rejected.

**Step 2: Run RED**

Run: `cargo test --locked -p mrd-service --test wan_session_control_input`

**Step 3: Implement the WAN input adapter**

Serialize bounded control envelopes on the mux control lane. Validate exact
authorization and replay state immediately before target injection. Keep LAN
input routing unchanged for LAN sessions.

**Step 4: Run GREEN and commit**

Commit: `feat: carry authorized WAN input over WebRTC`

### Task 10: Remove desktop false-success entrypoints

**Files:**
- Modify: `apps/Rdesk/src/app/services/remoteDisplayLauncher.ts`
- Modify: `apps/Rdesk/src/app/services/remoteDisplayLauncher.test.ts`
- Modify: `apps/Rdesk/src/app/components/DeviceDetailPage.tsx`
- Modify: `apps/Rdesk/src/app/components/DevicesPage.tsx`
- Modify: `apps/Rdesk/src/app/components/RemoteSessionPage.tsx`
- Modify: corresponding component/page tests
- Modify: `apps/mrd-service/src/handlers/session.rs`

**Step 1: Write frontend RED tests**

Assert every non-local device invokes `RequestRemoteSession` with `Auto` or an
explicit route. A request acknowledgement must not set connected. Only a
streaming snapshot renders connected media. Production callers cannot invoke
legacy `StartSession`.

**Step 2: Run RED**

Run: `pnpm test -- remoteDisplayLauncher DeviceDetailPage RemoteSessionPage`

**Step 3: Implement common session launch and event-driven UI**

Separate explicit local test launch from remote launch. Remove the legacy
branch and random latency/quality simulation. Subscribe to typed session
events and show exact failure reasons.

**Step 4: Add service-side fail-closed guard**

Reject remote `StartSession` in production mode so an old UI cannot recreate
the false path.

**Step 5: Run GREEN and commit**

Commit: `fix: use authenticated remote session entrypoints`

### Task 11: Make the browser bridge real and credential-safe

**Files:**
- Modify: `apps/Rdesk/src/app/adapters/serviceBridge/client.ts`
- Modify: `apps/Rdesk/src/app/adapters/serviceBridge/client.test.ts`
- Modify: `apps/Rdesk/src/app/services/webRemoteSessionService.ts`
- Modify: `apps/Rdesk/src/app/components/RemoteSessionPage.tsx`
- Modify: `apps/mrd-service/src/web_bridge.rs`
- Modify: `apps/mrd-service/tests/web_bridge.rs`

**Step 1: Write RED contracts**

- Client and service both default to `9533`.
- WebSocket URLs never contain bearer tokens.
- Browser remote launch sends real IPC through the bridge.
- Missing preview capability fails before session creation.
- No production code constructs two local peer connections.

**Step 2: Run RED**

Run: `pnpm test -- serviceBridge commands.webBridge RemoteSessionPage`

Run: `cargo test --locked -p mrd-service --test web_bridge`

**Step 3: Implement endpoint and upgrade authentication**

Use a bounded subprotocol/one-time upgrade credential, exact origin checking,
TLS for non-loopback, and capability discovery. Feed preview from the real
authenticated controller media path.

**Step 4: Run GREEN and commit**

Commit: `fix: connect browser sessions through the real service bridge`

### Task 12: Authenticate local IPC and bound request lifetimes

**Files:**
- Modify: `crates/mrd-ipc/src/transport.rs`
- Modify: `crates/mrd-ipc/src/client.rs`
- Modify: `crates/mrd-ipc/tests/integration.rs`
- Modify: `apps/mrd-service/src/ipc_server/connection.rs`
- Modify: `apps/mrd-service/tests/ipc_transport_integration.rs`
- Modify: `apps/Rdesk/src-tauri/src/ipc_client.rs`

**Step 1: Write IPC RED tests**

Assert foreign Unix UID/wrong Windows principal is rejected before decoding an
IPC request. Assert socket/pipe permissions are exact. Assert a server that
accepts but never responds produces a bounded timeout and cancellation.

**Step 2: Run RED**

Run: `cargo test --locked -p mrd-ipc --tests`

Run: `cargo test --locked -p mrd-service --test ipc_transport_integration`

**Step 3: Implement peer policy and deadlines**

Set Unix directory/socket modes, validate `SO_PEERCRED`, provide an explicit
Windows pipe security descriptor, and wrap request/response in a configured
deadline. Reject before dispatch.

**Step 4: Run GREEN and commit**

Commit: `fix: authenticate and bound local IPC`

### Task 13: Add supported Linux and macOS machine-state adapters

**Files:**
- Modify: `apps/mrd-service/src/security/mod.rs`
- Replace: `apps/mrd-service/src/security/unsupported.rs`
- Create: `apps/mrd-service/src/security/linux.rs`
- Create: `apps/mrd-service/src/security/macos.rs`
- Modify: `apps/mrd-service/src/main.rs`
- Create: `apps/mrd-service/tests/unix_machine_state.rs`
- Add: platform service manifests under `deploy/`

**Step 1: Write platform RED tests**

On Linux, reject non-root-owned ancestors, group/world-writable state, symlink
replacement, and rollback. Prove atomic owner-only roundtrip. On macOS, test
the Keychain port contract with an injected adapter. Assert non-Windows
`run_service` no longer returns unconditional unsupported.

**Step 2: Implement Linux then macOS adapters**

Use exact resolved roots, `0700` directories, `0600` atomic files, ownership
checks, no-follow opens, and a monotonic state envelope on Linux. Use a scoped
Keychain item and launchd contract on macOS.

**Step 3: Run platform GREEN and commit**

Commit: `feat: support protected service state on Unix hosts`

### Task 14: Make remote file transfer real and cancellation authoritative

**Files:**
- Modify: `apps/mrd-service/src/handlers/files.rs`
- Modify: `apps/mrd-service/src/app_state/file_transfer_registry.rs`
- Modify: `crates/mrd-file-transfer/src/lib.rs`
- Modify: `apps/Rdesk/src/app/components/DeviceDetailPage.tsx`
- Modify: `apps/Rdesk/src/app/components/FileTransferPage.tsx`
- Create or modify: remote file transfer integration tests

**Step 1: Write RED tests**

Assert remote operations require an authorized session and traverse the mux
file lane. Assert cancellation aborts an in-progress large transfer and its
state remains `Cancelled`. Assert local directory enumeration cannot be used
as a remote-device listing.

**Step 2: Implement separate local and remote providers**

Give each transfer an owned cancellation token/join handle. Stream bounded,
checksummed chunks over the authorized mux and make terminal state monotonic.
Wire the UI buttons to real commands and snapshots.

**Step 3: Run GREEN and commit**

Commit: `feat: transfer remote files over authorized sessions`

### Task 15: Package and install all required runtime binaries

**Files:**
- Modify: `apps/Rdesk/scripts/prepare-mrd-service.mjs`
- Modify: `apps/Rdesk/scripts/prepare-mrd-service.test.mjs`
- Modify: `apps/Rdesk/src-tauri/tauri.conf.json`
- Modify: `apps/Rdesk/scripts/install-mrd-service.ps1`
- Modify: `apps/Rdesk/scripts/uninstall-mrd-service.ps1`
- Modify: `.github/workflows/rust.yml`
- Create: Windows package smoke script/test

**Step 1: Write packaging RED tests**

Assert staging contains `mrd-service.exe` and `mrd-session-agent.exe`, Tauri
resources reference both, and the installer refuses mismatched hashes or
insecure ACLs. Run install/start/IPC/stop/uninstall against a disposable path.

**Step 2: Implement deterministic staging and bundle configuration**

Build both packages with locked dependencies, copy exact artifacts into the
bundle staging area, and make installer paths derive from that manifest.

**Step 3: Run GREEN and commit**

Run: `node apps/Rdesk/scripts/prepare-mrd-service.test.mjs`

Run: Windows package smoke script.

Commit: `fix: package the complete desktop service runtime`

### Task 16: Enforce full release evidence and protected main

**Files:**
- Modify: `.github/workflows/rust.yml`
- Modify: `.github/workflows/relay-control.yml`
- Modify: `.github/workflows/mainline-e2e.yml`
- Modify: `.github/workflows/multi-region-relay-device-lab.yml`
- Modify: test scripts and release documentation as required

**Step 1: Add workflow contract RED tests**

Assert required jobs run complete pytest, PostgreSQL migrations and WAN cases,
workspace tests including integrations, fmt, clippy, package smoke, TURN
contracts, and real two-region evidence. Assert a missing device-lab runner
cannot become a green release result.

**Step 2: Implement workflow gates**

Use locked dependencies, explicit native exit-code handling, bounded artifacts,
and exact job dependencies. Separate PR-safe deterministic checks from the
required staging/live release gate without allowing synthetic evidence to
stand in for live acceptance.

**Step 3: Run the full local verification matrix**

Run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
pnpm test
pnpm type-check
pnpm build
python -m pytest -q
powershell -File deploy/turn/test_deploy_contract.ps1
```

Run PostgreSQL, package, Linux relay, and two-region WAN suites in their
declared environments. Require first frame, input, forced relay loss,
migration, cleanup, and capacity evidence.

**Step 4: Review every audit finding**

Map each original P0/P1/P2 finding to its regression test, production call
path, and verification artifact. Any missing or skipped evidence keeps the
branch incomplete.

**Step 5: Commit, push, and protect main**

Commit: `ci: require complete production acceptance evidence`

After all required checks are present and green, push the branch and configure
`main` branch protection to require them. Re-query branch protection and CI to
prove enforcement.
