# Multi-Region TURN Relay Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Deliver a production TURN relay control plane with mTLS-managed Linux/Windows nodes, capacity-aware multi-region selection, short-lived node-scoped credentials, and active-session failover.

**Architecture:** Keep coturn as the encrypted packet relay, add a cross-platform Rust relay agent on every node, make Rdesk-Server the PostgreSQL-backed directory and credential authority, and let mrd-service verify signed directories and migrate WebRTC sessions. Reusable relay state, selection, signature, and failure semantics live in a new mrd-relay-control crate; signaling only routes authenticated migration messages.

**Tech Stack:** Rust 2021, Tokio, reqwest/rustls, serde, Ed25519, FastAPI, SQLAlchemy asyncio, PostgreSQL, coturn, WebRTC/ICE, PowerShell, Bash, GitHub Actions.

---

## Execution constraints

- Apply @superpowers:test-driven-development to every production behavior.
- The current worktree contains substantial unrelated uncommitted changes. Before every commit, run git diff --cached --name-only and stage only the files named by that task.
- Never reset, discard, reformat, or bulk-stage existing user changes.
- Do not use junk/ as an implementation source.
- Keep TURN credentials, private keys, enrollment tokens, full session grants, and credential-bearing URLs out of logs, snapshots, fixtures, and test failures.
- Missing device-lab prerequisites produce INFRA_FAIL; they never count as product evidence.

### Task 1: Relay domain model and deterministic selection

**Files:**
- Modify: Cargo.toml
- Create: crates/mrd-relay-control/Cargo.toml
- Create: crates/mrd-relay-control/src/lib.rs
- Create: crates/mrd-relay-control/src/model.rs
- Create: crates/mrd-relay-control/src/health.rs
- Create: crates/mrd-relay-control/src/selection.rs
- Create: crates/mrd-relay-control/tests/selection.rs

**Step 1: Write failing tests**

Cover one behavior per test:

- stale, draining, unavailable, revoked, incompatible, and hard-full nodes are ineligible;
- soft-full and degraded nodes remain eligible with penalties;
- region, RTT, utilization, bandwidth headroom, and recent failures produce stable integer scores;
- backup nodes use a different failure domain;
- equal scores use RelayNodeId as the final tie-breaker;
- three healthy heartbeats are required after recovery;
- lease expiry at 15 seconds is exact and time is injected.

The wished-for API is:

~~~rust
let decision = select_relays(&policy, &nodes, now_ms)?;
assert_eq!(decision.primary.node_id.as_str(), "relay-hkg-1");
assert_ne!(
    decision.primary.failure_domain,
    decision.backups[0].failure_domain
);
~~~

**Step 2: Verify RED**

Run: cargo test -p mrd-relay-control --test selection

Expected: FAIL because the crate is absent.

**Step 3: Implement minimal production code**

Define bounded identifier constructors, closed RelayNodeState and RelayTransport enums, RelayNodeSnapshot, RelaySelectionPolicy, RelaySelectionDecision, RelayRejection, and stable reason codes. Use saturating integer arithmetic, never floating-point scoring. Pass now_ms into all time-dependent methods.

The central snapshot is:

~~~rust
pub struct RelayNodeSnapshot {
    pub node_id: RelayNodeId,
    pub region: RegionId,
    pub failure_domain: FailureDomainId,
    pub state: RelayNodeState,
    pub lease_expires_at_ms: u64,
    pub endpoints: Vec<RelayEndpoint>,
    pub active_allocations: u32,
    pub max_allocations: u32,
    pub current_egress_bps: u64,
    pub max_egress_bps: u64,
    pub recent_failure_bps: u16,
    pub measured_rtt_ms: Option<u32>,
}
~~~

**Step 4: Verify GREEN**

Run:

~~~text
cargo test -p mrd-relay-control
cargo test -p mrd-application
~~~

Expected: PASS.

**Step 5: Commit**

~~~text
git add Cargo.toml crates/mrd-relay-control
git diff --cached --name-only
git commit -m "feat: add relay selection domain"
~~~

### Task 2: Signed relay-directory wire contract

**Files:**
- Modify: crates/mrd-relay-control/Cargo.toml
- Modify: crates/mrd-relay-control/src/lib.rs
- Create: crates/mrd-relay-control/src/directory.rs
- Create: crates/mrd-relay-control/tests/directory_contract.rs
- Create: tests/relay/fixtures/directory-v1.json
- Create: tests/relay/fixtures/directory-v1-tampered.json

**Step 1: Write failing contract tests**

Prove exact canonical bytes are stable; Ed25519 accepts the golden vector; changed node order, endpoint, session binding, policy revision, expiry, or signature fails; duplicate nodes/endpoints, unknown versions, expired directories, invalid reservations, and untrusted signing keys fail closed.

The public shape is:

~~~rust
pub struct SignedRelayDirectory {
    pub payload: RelayDirectoryPayload,
    pub signing_key_id: String,
    pub signature_b64: String,
}

impl SignedRelayDirectory {
    pub fn verify(
        &self,
        trusted_keys: &BTreeMap<String, Vec<u8>>,
        expected_session_id: &str,
        now_ms: u64,
    ) -> Result<VerifiedRelayDirectory, RelayDirectoryError>;
}
~~~

**Step 2: Verify RED**

Run: cargo test -p mrd-relay-control --test directory_contract

Expected: FAIL because the directory contract is absent.

**Step 3: Implement canonical encoding and verification**

Use context MRD_RELAY_DIRECTORY_V1 and a fixed length-prefixed binary encoding: fixed field order, big-endian integers, UTF-8 strings prefixed by u32, and sorted candidate/endpoint lists. JSON is transport encoding only. Cap each directory at eight nodes and four endpoints per node.

**Step 4: Verify GREEN**

Run:

~~~text
cargo test -p mrd-relay-control
cargo test -p mrd-identity
~~~

Expected: PASS.

**Step 5: Commit**

~~~text
git add crates/mrd-relay-control tests/relay/fixtures
git commit -m "feat: sign relay directory contracts"
~~~

### Task 3: PostgreSQL relay persistence and transactional capacity

**Files:**
- Modify: apps/Rdesk-Server/requirements.txt
- Create: apps/Rdesk-Server/requirements-dev.txt
- Modify: apps/Rdesk-Server/app/models/__init__.py
- Create: apps/Rdesk-Server/app/models/relay_node.py
- Create: apps/Rdesk-Server/app/models/relay_enrollment.py
- Create: apps/Rdesk-Server/app/models/relay_reservation.py
- Create: apps/Rdesk-Server/app/db/migrate_add_relay_control.py
- Create: apps/Rdesk-Server/app/services/relay_repository.py
- Create: apps/Rdesk-Server/tests/test_relay_repository.py
- Create: apps/Rdesk-Server/tests/test_relay_repository_postgres.py

**Step 1: Write failing repository tests**

Use a fake clock. Test one-use hashed enrollment tokens, monotonic heartbeat sequence, certificate binding, 15-second leases, irreversible revocation, encrypted node secrets, reservation expiry, and concurrent SELECT FOR UPDATE admission that never exceeds max_allocations.

The repository API is:

~~~python
async def reserve_capacity(
    self,
    *,
    session_id: str,
    user_id: str,
    ordered_node_ids: list[str],
    now: datetime,
    ttl_seconds: int = 30,
) -> list[RelayReservation]:
    ...
~~~

**Step 2: Verify RED**

Run:

~~~text
python -m pytest apps/Rdesk-Server/tests/test_relay_repository.py -q
python -m pytest apps/Rdesk-Server/tests/test_relay_repository_postgres.py -q
~~~

Expected: FAIL because the models and repository are absent. The PostgreSQL test uses MRD_TEST_DATABASE_URL; Task 11 CI always configures it.

**Step 3: Implement minimal persistence**

Add database constraints for non-negative metrics, positive capacities, unique certificate fingerprints, and unique active session/node reservations. Store endpoints as validated JSON only at the persistence boundary. Make the migration idempotent and transactional; do not treat Base.metadata.create_all as the production migration.

**Step 4: Verify GREEN**

Run both focused tests and python -m pytest apps/Rdesk-Server/tests -q.

Expected: PASS.

**Step 5: Commit**

Stage only the Task 3 paths and commit with:

~~~text
git commit -m "feat: persist relay capacity and leases"
~~~

### Task 4: mTLS enrollment, heartbeat, and administration APIs

**Files:**
- Modify: apps/Rdesk-Server/app/core/config.py
- Modify: apps/Rdesk-Server/app/core/security.py
- Modify: apps/Rdesk-Server/app/api/v1/router.py
- Create: apps/Rdesk-Server/app/schemas/relay.py
- Create: apps/Rdesk-Server/app/services/relay_node_auth.py
- Create: apps/Rdesk-Server/app/services/relay_registry.py
- Create: apps/Rdesk-Server/app/api/v1/relays.py
- Create: apps/Rdesk-Server/tests/test_relay_node_api.py
- Create: apps/Rdesk-Server/tests/test_relay_admin_api.py

**Step 1: Write failing API tests**

Cover one-use CSR enrollment, explicit approval, node-bound certificates, mTLS fingerprint plus Ed25519 request signature, untrusted forwarded-certificate headers, replay, stale clocks, wrong node ID, revoked certificate, oversized metrics, administrator role, drain/resume/revoke, and audit events.

**Step 2: Verify RED**

Run:

~~~text
python -m pytest apps/Rdesk-Server/tests/test_relay_node_api.py apps/Rdesk-Server/tests/test_relay_admin_api.py -q
~~~

Expected: FAIL because /api/v1/relays is absent.

**Step 3: Implement the authentication boundary**

Create separate get_verified_relay_node and require_admin dependencies. The relay dependency must trust certificate metadata only from RDESK_TRUSTED_MTLS_PROXY, match the SHA-256 certificate fingerprint, verify the signed body, enforce request time/sequence, and reject public access to the backend listener. Enrollment still requires TLS and CSR proof of possession.

Return stable reason codes such as relay_certificate_invalid, relay_heartbeat_replayed, relay_node_revoked, and relay_metrics_invalid.

**Step 4: Verify GREEN**

Run focused and full backend tests. Capture logs and assert no token, key, or secret appears.

**Step 5: Commit**

Stage only the Task 4 paths and commit:

~~~text
git commit -m "feat: manage authenticated relay nodes"
~~~

### Task 5: Capacity-bound signed directories and node-scoped credentials

**Files:**
- Modify: apps/Rdesk-Server/app/services/turn_credentials.py
- Modify: apps/Rdesk-Server/app/api/v1/turn.py
- Create: apps/Rdesk-Server/app/services/relay_directory.py
- Create: apps/Rdesk-Server/app/services/relay_signing.py
- Modify: apps/Rdesk-Server/app/api/v1/relays.py
- Create: apps/Rdesk-Server/tests/test_relay_directory.py
- Modify: apps/Rdesk-Server/tests/test_turn_credentials.py
- Create: apps/Rdesk-Server/tests/test_relay_directory_vectors.py

**Step 1: Write failing issuance tests**

Prove hard filtering; distinct failure-domain backup; stable capacity exhaustion; minimum-of-all-deadlines TTL; username expiry:user_id:session_id:node_id; per-node secret isolation; exact shared golden vector; authorization/grant/policy enforcement; and secret redaction.

**Step 2: Verify RED**

Run:

~~~text
python -m pytest apps/Rdesk-Server/tests/test_relay_directory.py apps/Rdesk-Server/tests/test_turn_credentials.py apps/Rdesk-Server/tests/test_relay_directory_vectors.py -q
~~~

Expected: FAIL because selection and per-node issuance are absent.

**Step 3: Implement issuance**

Replace the caller-controlled deadline-only request with a server-verified session authorization. Keep legacy behavior only behind a development flag that defaults off.

Return:

~~~python
class RelayAccessResponse(BaseModel):
    directory: SignedRelayDirectoryOut
    credentials: list[NodeTurnCredentialOut]

class NodeTurnCredentialOut(BaseModel):
    node_id: str
    urls: list[str]
    username: str
    credential: str
    expires_at_unix_seconds: int
~~~

Verify authenticated participation, active grant deadline, and policy revision before reserving capacity. Sign only secret-free directory data. Decrypt node secrets only while calculating HMAC.

**Step 4: Verify GREEN**

Run:

~~~text
python -m pytest apps/Rdesk-Server/tests -q
cargo test -p mrd-relay-control --test directory_contract
~~~

Expected: PASS against the same fixture.

**Step 5: Commit**

Stage only Task 5 paths and commit:

~~~text
git commit -m "feat: issue capacity-bound relay access"
~~~

### Task 6: TURN probes and WebRTC restart primitives

**Files:**
- Modify: crates/mrd-transport-webrtc/src/lib.rs
- Modify: crates/mrd-transport-webrtc/src/config.rs
- Modify: crates/mrd-transport-webrtc/src/peer.rs
- Create: crates/mrd-transport-webrtc/src/probe.rs
- Modify: crates/mrd-transport-webrtc/tests/forced_relay.rs
- Create: crates/mrd-transport-webrtc/tests/ice_restart.rs

**Step 1: Write failing tests**

Test that a probe requires a real relay/relay selected pair; host/srflx cannot pass; new ICE servers increment generation and emit candidates; stale answer/candidate generations fail; media and control resume; losing generations close; and credentials stay redacted.

**Step 2: Verify RED**

Run:

~~~text
cargo test -p mrd-transport-webrtc --test ice_restart
cargo test -p mrd-transport-webrtc --test forced_relay
~~~

Expected: FAIL because probe and restart APIs are absent.

**Step 3: Implement minimal APIs**

Expose:

~~~rust
pub async fn probe_turn_relay(
    config: TurnRelayProbeConfig,
) -> Result<TurnRelayProbeEvidence, TransportError>;

pub async fn create_restart_offer(
    &self,
    generation: u64,
    ice_servers: Vec<IceServerConfig>,
) -> Result<SessionDescription, TransportError>;
~~~

If webrtc-rs cannot safely replace ICE configuration in place, build a pending replacement peer. Never label a normal offer as an ICE restart. Keep old and pending peers separate until evidence validation.

**Step 4: Verify GREEN**

Run cargo test -p mrd-transport-webrtc.

Expected: PASS. Live forced relay remains explicit non-evidence without MRD_TEST_TURN_*; Task 11 supplies a required live lane.

**Step 5: Commit**

~~~text
git add crates/mrd-transport-webrtc
git commit -m "feat: probe and restart turn relay routes"
~~~

### Task 7: Cross-platform relay-agent core

**Files:**
- Modify: Cargo.toml
- Create: apps/mrd-relay-agent/Cargo.toml
- Create: apps/mrd-relay-agent/src/lib.rs
- Create: apps/mrd-relay-agent/src/config.rs
- Create: apps/mrd-relay-agent/src/identity.rs
- Create: apps/mrd-relay-agent/src/backend.rs
- Create: apps/mrd-relay-agent/src/metrics.rs
- Create: apps/mrd-relay-agent/src/process.rs
- Create: apps/mrd-relay-agent/src/runtime.rs
- Create: apps/mrd-relay-agent/src/main.rs
- Create: apps/mrd-relay-agent/tests/runtime.rs

**Step 1: Write failing tests with fake ports**

Cover identity/CSR generation, mTLS enrollment and renewal, five-second monotonic heartbeats, bounded metric parsing, local allocation probe, exactly three restart attempts, backend outage, idempotent drain/secret update, and redaction.

Define ports first:

~~~rust
#[async_trait]
pub trait CoturnRuntimePort: Send + Sync {
    async fn snapshot(&self) -> Result<CoturnSnapshot>;
    async fn restart(&self) -> Result<()>;
    async fn apply_secret(&self, version: u64, secret: SecretBytes) -> Result<()>;
}

#[async_trait]
pub trait RelayBackendPort: Send + Sync {
    async fn enroll(&self, request: EnrollmentRequest) -> Result<NodeCertificate>;
    async fn heartbeat(&self, heartbeat: SignedHeartbeat) -> Result<NodeDirective>;
}
~~~

**Step 2: Verify RED**

Run: cargo test -p mrd-relay-agent --test runtime

Expected: FAIL because the application is absent.

**Step 3: Implement portable runtime**

Use reqwest/rustls mTLS, injected clock/sleeper, zeroized secret buffers, bounded exponential backoff, and stable reason-code logs. Leave native SCM/systemd details for Task 8.

**Step 4: Verify GREEN**

Run:

~~~text
cargo test -p mrd-relay-agent
cargo clippy -p mrd-relay-agent --all-targets -- -D warnings
~~~

Expected: PASS.

**Step 5: Commit**

~~~text
git add Cargo.toml apps/mrd-relay-agent
git commit -m "feat: add relay node agent core"
~~~

### Task 8: Linux/Windows service adapters and hardened deployment

**Files:**
- Modify: apps/mrd-relay-agent/Cargo.toml
- Create: apps/mrd-relay-agent/src/platform/mod.rs
- Create: apps/mrd-relay-agent/src/platform/linux.rs
- Create: apps/mrd-relay-agent/src/platform/windows.rs
- Create: apps/mrd-relay-agent/tests/platform_contract.rs
- Modify: deploy/turn/turnserver.conf.example
- Modify: deploy/turn/README.md
- Create: deploy/turn/regions.example.yaml
- Create: deploy/turn/linux/mrd-relay-agent.service
- Create: deploy/turn/linux/install-relay-node.sh
- Create: deploy/turn/linux/uninstall-relay-node.sh
- Create: deploy/turn/windows/install-relay-node.ps1
- Create: deploy/turn/windows/uninstall-relay-node.ps1
- Create: deploy/turn/windows/verify-relay-node.ps1
- Create: deploy/turn/test_deploy_contract.ps1

**Step 1: Write failing platform contracts**

Assert systemd hardening and dedicated user; Windows delayed-start restricted service and DPAPI path; literal safe filesystem operations; coturn auth/TLS/quota/rate/port/metrics hardening; configurable TLS 443 conflict detection; native/Docker/WSL2 parity; and allocation/relayed-packet preflight.

**Step 2: Verify RED**

Run:

~~~text
cargo test -p mrd-relay-agent --test platform_contract
powershell -ExecutionPolicy Bypass -File deploy/turn/test_deploy_contract.ps1
~~~

Expected: FAIL because adapters/scripts are absent.

**Step 3: Implement adapters and deployment**

Linux uses systemd and root-owned 0600 secrets. Windows uses windows-service, machine-scope DPAPI, LiteralPath, and SCM recovery policy. Supervise only an exact configured coturn service/container/WSL command.

**Step 4: Verify GREEN**

Run contracts on Windows and Rust Linux checks in CI. Run shellcheck when available. Contract tests must not install or remove real services.

**Step 5: Commit**

Stage Task 8 paths and commit:

~~~text
git commit -m "feat: deploy cross platform relay nodes"
~~~

### Task 9: Version and authorize relay-migration signaling

**Files:**
- Modify: crates/mrd-signal-proto/src/authenticated.rs
- Modify: crates/mrd-signal-proto/tests/authenticated_messages.rs
- Modify: crates/mrd-application/src/lib.rs
- Modify: apps/realtime-server/src/routes.rs
- Modify: apps/realtime-server/src/lib.rs
- Modify: apps/realtime-server/tests/authenticated_routing.rs
- Modify: apps/mrd-service/src/signaling/runtime.rs
- Modify: apps/mrd-service/src/signaling/event_mapper.rs
- Modify: apps/mrd-service/tests/signaling_runtime.rs

**Step 1: Write failing protocol tests**

Add signed migration offer/answer/candidate payloads with session ID, migration_generation, candidate fingerprints, directory ID, and node ID. Test monotonic generation, participant authorization, grant fingerprints, generation zero, stale/skipped generation, random peers, mismatch, replay, and post-close behavior.

**Step 2: Verify RED**

Run:

~~~text
cargo test -p mrd-signal-proto --test authenticated_messages
cargo test -p realtime-server --test authenticated_routing
cargo test -p mrd-service --test signaling_runtime
~~~

Expected: FAIL because migration messages are absent.

**Step 3: Implement protocol and generation guards**

Keep signaling ReconnectRequest distinct from ICE migration. Store latest accepted generation in SessionRoute. Apply participant, grant, fingerprint, replay, rate, payload, and TTL checks. realtime-server routes messages but never interprets credentials or claims route success.

**Step 4: Verify GREEN**

Run all three packages' full suites.

Expected: PASS.

**Step 5: Commit**

Stage only Task 9 paths and commit:

~~~text
git commit -m "feat: authorize relay migration signaling"
~~~

### Task 10: mrd-service relay selection and active failover

**Files:**
- Modify: apps/mrd-service/Cargo.toml
- Modify: apps/mrd-service/src/lib.rs
- Modify: apps/mrd-service/src/main.rs
- Create: apps/mrd-service/src/relay/mod.rs
- Create: apps/mrd-service/src/relay/config.rs
- Create: apps/mrd-service/src/relay/client.rs
- Create: apps/mrd-service/src/relay/cache.rs
- Create: apps/mrd-service/src/relay/migration.rs
- Modify: apps/mrd-service/src/transports/webrtc.rs
- Modify: apps/mrd-service/src/control_input.rs
- Modify: apps/mrd-service/src/app_state/core.rs
- Create: apps/mrd-service/tests/relay_directory.rs
- Create: apps/mrd-service/tests/relay_failover.rs

**Step 1: Write failing service tests**

Use fake backend/signaling/clock and real in-memory TransportMux. Prove verify-before-use; bounded cache; sanitized route evidence; disconnected grace and immediate failed recovery; ReleaseAll before freeze; different-domain backup; atomic replacement; late-loser suppression; terminal grant/policy/revocation/signature/identity failures; backend outage semantics; and all-lane session continuity.

**Step 2: Verify RED**

Run:

~~~text
cargo test -p mrd-service --test relay_directory
cargo test -p mrd-service --test relay_failover
~~~

Expected: FAIL because the relay runtime is absent.

**Step 3: Implement client/cache/migration**

Require HTTPS, pinned directory keys, bounded timeouts, and credential-free URLs. Use the existing authenticated backend device token and keep credentials memory-only.

Add pending-generation host APIs:

~~~rust
pub async fn begin_replacement(
    &self,
    session_id: &SessionId,
    generation: u64,
    config: PeerConnectionConfig,
) -> Result<PendingWebRtcReplacement, ServiceWebRtcTransportError>;

pub async fn commit_replacement(
    &self,
    pending: PendingWebRtcReplacement,
    expected: VerifiedRelayEvidence,
) -> Result<Arc<dyn TransportMuxPort>, ServiceWebRtcTransportError>;
~~~

Commit only after selected-pair evidence matches the planned node. Keep the old mux until commit. Close both paths on terminal security errors.

**Step 4: Verify GREEN**

Run focused tests and cargo test -p mrd-service.

Expected: PASS.

**Step 5: Commit**

Stage only Task 10 paths and commit:

~~~text
git commit -m "feat: migrate sessions across turn relays"
~~~

### Task 11: Integration, capacity, security, and CI gates

**Files:**
- Modify: tests/integration/Cargo.toml
- Create: tests/integration/multi_region_relay.rs
- Create: tests/benchmarks/scripts/multi_region_relay_common.ps1
- Create: tests/benchmarks/scripts/test_multi_region_relay.ps1
- Create: tests/benchmarks/scripts/run_multi_region_relay.ps1
- Create: tests/quality-gates/policies/windows-multi-region-relay.v1.json
- Create: tests/quality-gates/fixtures/multi-region-relay-valid.json
- Modify: crates/mrd-quality-gate/src/artifact.rs
- Modify: crates/mrd-quality-gate/src/evaluator.rs
- Modify: crates/mrd-quality-gate/tests/artifact_validation.rs
- Modify: crates/mrd-quality-gate/tests/policy_evaluation.rs
- Modify: crates/mrd-quality-gate/tests/workflow_contract.rs
- Create: .github/workflows/relay-control.yml
- Create: .github/workflows/multi-region-relay-device-lab.yml

**Step 1: Write failing integration and gate tests**

Use three fake nodes across two regions. Prove selection, reservation races, drain, lease expiry, failover generation, security dominance, and cleanup. PowerShell fakes prove lab call order and verdict aggregation.

Extend artifacts with directory, primary/backup failure domains, reservation, selected pair, allocation, injected failure, detection, generation, restored media, and cleanup. Reject metadata-only relay claims.

Workflow contracts require PostgreSQL backend tests, Linux/Windows agent builds, deterministic PowerShell contracts, a separate self-hosted two-region job, always-upload, enforced verdict, and no continue-on-error or missing-infrastructure success.

**Step 2: Verify RED**

Run:

~~~text
cargo test --manifest-path tests/integration/Cargo.toml --test multi_region_relay
powershell -ExecutionPolicy Bypass -File tests/benchmarks/scripts/test_multi_region_relay.ps1
cargo test -p mrd-quality-gate
~~~

Expected: FAIL because orchestration/gates are absent.

**Step 3: Implement orchestration and gates**

The live runner uses a configured lab-control executable for process kill, network outage, UDP block, TLS fallback, drain, and reset. Reset runs in finally. Missing hosts, certs, ports, control, or secrets yield INFRA_FAIL. Do not put secrets in process arguments or artifacts.

**Step 4: Verify GREEN**

Run all Step 2 commands and evaluate the committed fixture.

Expected: PASS for deterministic tests.

**Step 5: Commit**

Stage only Task 11 paths and commit:

~~~text
git commit -m "test: gate multi region relay recovery"
~~~

### Task 12: Verification and real-host acceptance

**Files:**
- Modify: deploy/turn/README.md
- Create: docs/release/multi-region-turn-relay-acceptance.md
- Modify: docs/plans/2026-08-22-multi-region-turn-relay.md only if commands differ

**Step 1: Run focused suites**

~~~text
cargo test -p mrd-relay-control
cargo test -p mrd-relay-agent
cargo test -p mrd-signal-proto
cargo test -p realtime-server
cargo test -p mrd-transport-webrtc
cargo test -p mrd-service
python -m pytest apps/Rdesk-Server/tests -q
powershell -ExecutionPolicy Bypass -File deploy/turn/test_deploy_contract.ps1
powershell -ExecutionPolicy Bypass -File tests/benchmarks/scripts/test_multi_region_relay.ps1
cargo test --manifest-path tests/integration/Cargo.toml --test multi_region_relay
cargo test -p mrd-quality-gate
~~~

Expected: PASS without warnings or secret-bearing output.

**Step 2: Run formatting and lint checks**

~~~text
cargo fmt --all -- --check
cargo clippy -p mrd-relay-control -p mrd-relay-agent -p mrd-signal-proto -p realtime-server -p mrd-transport-webrtc -p mrd-service --all-targets -- -D warnings
git diff --check
~~~

Expected: PASS. If unrelated existing changes break a workspace-wide check, record the exact pre-existing file and still run every focused check.

**Step 3: Run the configured lab**

Run:

~~~text
powershell -ExecutionPolicy Bypass -File tests/benchmarks/scripts/run_multi_region_relay.ps1 -Scenario all -OutputRoot artifacts/e2e/multi-region-relay
~~~

Required real rows:

- Linux primary to Linux backup;
- Linux primary to the declared Windows coturn mode;
- failure before allocation;
- coturn kill during video/audio/control;
- regional outage;
- planned drain;
- soft and hard capacity;
- UDP blocked with TCP/TLS;
- node certificate revocation;
- backend outage with existing allocation and expired-cache new-session failure.

Expected: product pass only when removal is at most 10 seconds, active recovery is at most 20 seconds, runtime evidence names the backup, permissions remain unchanged, ReleaseAll is recorded, media resumes, and all resources clean up. Otherwise emit PRODUCT_FAIL or INFRA_FAIL.

**Step 4: Record acceptance**

Document versions, host modes, topology, commands, artifact paths, verdicts, limitations, and the exact Windows hosting mode. Do not copy credentials or private endpoints.

**Step 5: Commit**

~~~text
git add deploy/turn/README.md docs/release/multi-region-turn-relay-acceptance.md docs/plans/2026-08-22-multi-region-turn-relay.md
git commit -m "docs: record multi region relay acceptance"
~~~

## Completion definition

The proxy-server work is not complete merely because coturn starts, credentials are issued, or offline tests pass. Completion requires all deterministic suites plus real selected-relay, capacity, failure, migration, media recovery, security, audit, and cleanup evidence for the declared Linux and Windows host paths.
