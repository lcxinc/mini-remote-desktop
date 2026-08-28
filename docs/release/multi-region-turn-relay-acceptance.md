# Multi-region TURN relay acceptance record

- Date: 2026-08-28
- Branch: `codex/initial-wan-relay-session`
- Initial-WAN implementation base: `682bf3a4` (Task 12 gate changes were
  verified from the working tree before their commit)
Overall live verdict: **INFRA_FAIL**

This record distinguishes deterministic implementation evidence from real
multi-host acceptance. The relay control plane, cross-platform agent,
capacity admission, signed directory, client migration, quality gate, and lab
orchestration are implemented and tested. No configured two-region Linux /
Windows TURN lab was available on this host, so no public-network or real-host
product pass is claimed.

## Verification environment

- Controller OS/toolchain: Windows x86_64 MSVC, Rust/Cargo 1.89.0,
  Windows PowerShell 5.1.26100.9032, Python 3.12.10.
- Repository revision verified: `1c44870a69b9` before this record update.
- Docker Desktop client/server 29.2.1 was available. A temporary, single-host
  coturn container was exercised for local transport evidence only; it was not
  configured as an MRD relay agent, broker, or multi-region lab node.
- No native local `turnserver` / `coturn` executable was discovered.
- `MRD_TEST_DATABASE_URL` was not configured, so PostgreSQL-only FastAPI rows
  remained environment-gated locally. `.github/workflows/relay-control.yml`
  provisions PostgreSQL and makes those rows mandatory in CI.

## Deterministic and local results

| Area | Result | Evidence |
| --- | --- | --- |
| Relay selection / directory | PASS | `mrd-relay-control`: 27 tests including the compile-fail doc contract |
| Cross-platform node agent | PASS | `mrd-relay-agent`: 209 tests across runtime, broker, platform, metrics, CLI, and secure stores |
| Authenticated migration protocol | PASS | `mrd-signal-proto`: 10 tests; `realtime-server`: 6 tests |
| WebRTC relay migration | PASS (multi-host rows not counted) | 86 unit, 18 integration, and 0 doc tests passed; 4 live/perf rows ignored in the ordinary package run. Local coturn UDP and TCP live rows were then invoked explicitly and passed. |
| Session service | PASS | `mrd-service`: 778 tests passed, 4 environment/hardware rows ignored |
| Backend | PASS for configured local rows | FastAPI: 348 passed, 78 PostgreSQL-gated rows skipped without `MRD_TEST_DATABASE_URL` |
| Deployment contract | PASS | `deploy/turn/test_deploy_contract.ps1` |
| Multi-region integration | PASS | 3 tests: explicit generation-zero peer binding, three-node/two-region capacity lifecycle, and real failover coordinator/security cleanup |
| Quality and workflow gates | PASS | `mrd-quality-gate`: 48 tests; PowerShell orchestration contracts PASS |
| Formatting | PASS | `cargo fmt --all -- --check`; `git diff --check` |
| Strict focused Clippy | PASS | relay-control, relay-agent, signal, realtime, WebRTC, and quality-gate with `--no-deps -D warnings` |

The WebRTC transport's upstream `webrtc-ice` 0.12 dependency does not gather
TURN/TCP or TURN/TLS candidates. Commit `1c44870a` supplies a bounded,
peer-owned stream bridge that preserves TURN allocation isolation, STUN and
ChannelData framing, TCP, strict platform-certificate TLS, and cleanup across
initial and restarted physical peers. Eight focused bridge tests passed,
including trusted TLS framing and proof that TLS endpoints never downgrade to
plaintext. `cargo clippy -p mrd-transport-webrtc --lib -- -D warnings` passed.
The all-target variant remains blocked by pre-existing strict warnings in
`vendor/nvenc`; no third-party source was changed.

The first full FastAPI invocation hit a Windows ACL denial in pytest's default
user temp root before affected tests were executed. Re-running the same suite
with a new workspace-local `--basetemp` completed with the result above. This
was an executor filesystem issue, not a product assertion failure.

`mrd-service --lib --no-deps -D warnings` remains blocked by 12 pre-existing,
non-relay Clippy findings in agent runtime, capabilities, generic session/LAN
handlers, wake-on-LAN, and web bridge code. The relay modules introduced by
this work produced no strict Clippy finding. The complete `mrd-service` test
package nevertheless passed.

### Initial attended WAN session gate

The Task 12 non-live evidence contract passed 3/3 tests. It defines eleven
ignored live rows: forced UDP/TCP/TLS generation zero, target rejection,
capacity exhaustion, backend loss before approval, signaling disconnect,
expired generation, service restart, primary failure with cross-failure-domain
migration, and deterministic `ReleaseAll`.

The contract is fail-closed. It rejects unknown or secret-bearing fields,
cross-invocation replay, metadata-only traffic claims, mismatched peer
session/directory/relay-URL bindings, nonzero initial generations, incorrect
negative outcomes, missing live component identities, and non-exact container
cleanup. Runtime IDs, probe IDs, evidence IDs, and temporary container names
must all be bound to the invocation. Every row is Ed25519-attested by the
configured lab authority; the runner supplies only its protected raw 32-byte
public-key file and key ID. The signature covers the domain
`MRD_INITIAL_WAN_EVIDENCE_V1\0` plus whitespace-free JSON with recursively
lexicographically sorted object keys and the `attestation` field removed.
The runner additionally inspects the invocation's Docker labels/names after
reset, marks any leak as a failure, and removes only containers carrying that
fresh invocation identity. The local PowerShell orchestration
contract passed, the quality artifact contract passed 14/14 tests, and the
multi-region deterministic integration target passed 3/3 tests.

These deterministic results do not count as live product evidence. The live
rows require an explicit `MRD_INITIAL_WAN_LAB_CONTROL` executable and trusted
`MRD_INITIAL_WAN_ATTESTATION_PUBLIC_KEY` / `_KEY_ID` which bind the authority
that owns
two service runtimes, realtime-server, FastAPI/PostgreSQL, and the exact pinned
coturn containers. The runner observed exit code 3 / `INFRA_FAIL` because that
control executable was not configured; it started no live row. Docker and the
pinned coturn image alone are intentionally insufficient for `PASS`.

One WebRTC cleanup-capacity test failed once on an immediate scheduler-entry
assertion. The exact test then passed five consecutive isolated runs and the
entire WebRTC package passed on the immediate full rerun. No product change was
made for the single non-reproducible scheduling event.

## Single-host local coturn evidence

This is transport smoke evidence, not multi-region or Windows node-mode
acceptance. Docker ran the exact image manifest
`coturn/coturn:4.17.2@sha256:aa68aab64a3b929d57fc2924c98ea447bf996cf8dade2508e7b71eaf23f1f14e`
with local-only ephemeral credentials, UDP/TCP port 34789, and relay ports
40000-40031. Loopback peers were allowed solely because both test WebRTC peers
ran on this controller.

| Local row | Result | Evidence |
| --- | --- | --- |
| Forced TURN/UDP | PASS | Selected pair was relay/relay and real media/control probes completed |
| Direct to TURN/UDP restart | PASS | Restart validation, route commit, and post-switch media/control completed |
| Forced TURN/TCP | PASS | Selected pair was relay/relay through the stream bridge and real media/control probes completed |
| Direct to TURN/TCP restart | PASS | Restart validation, route commit, and post-switch media/control completed |
| TURN/TLS framing and trust | PASS (deterministic) | Trusted IP certificate completed an encrypted bridge round trip; a plaintext endpoint was rejected with no downgrade |
| Public-certificate coturn TLS | NOT RUN | Requires the external lab certificate and public endpoint |

## Client mainline integration boundary

`mrd-service` now has a production initial-WAN caller: it dispatches the v3
intent/grant/offer/answer/candidate flow, binds the target signing key from the
verified grant, installs generation-zero relay sessions, activates the
role-specific media authority, and joins cleanup on shutdown. Rdesk also
propagates the explicit Auto/LAN/WAN Relay preference.

This record still does **not** accept a fresh end-user WAN session as a live
product pass. The required two-service/FastAPI/realtime/coturn execution has
not produced an invocation-bound artifact on this host, and the non-Windows
production runtime remains unqualified. The ignored live tests and their
static contract are gates for that evidence, not substitutes for it.

## Required live topology and host modes

The acceptance lab must provide at least three nodes across two regions and
different failure domains, plus controller and target hosts. Private hostnames,
addresses, credentials, certificates, and secrets must stay in lab variables
or secret stores and must not be copied into this record.

- Linux path: ordinary Linux host, native coturn 4.17.2 or newer, systemd
  agent/broker contract, public UDP/TCP/TLS and complete relay range.
- Windows path: **Docker mode** with the exact pinned
  `coturn/coturn:4.17.2` image digest and immutable runtime contract is the
  primary declared mode.
- Windows WSL2 is acceptable only for an existing LocalSystem-owned
  `MRDRelay` distribution with mirrored networking, systemd, accounting, and
  live UDP/range proof. Fresh WSL2 install is unsupported.
- Windows Native is not accepted until its signed drain wrapper is
  independently qualified.

No exact Windows mode was exercised in this run. Therefore the recorded mode
is `UNVERIFIED`, not Docker, WSL2, or Native product acceptance.

## Live runner result

Command:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File tests/benchmarks/scripts/run_multi_region_relay.ps1 `
  -Scenario all `
  -OutputRoot artifacts/e2e/multi-region-relay
```

- Observed exit code: `3`
- Observed verdict: `INFRA_FAIL`
- Summary: `artifacts/e2e/multi-region-relay/multi-region-relay-summary.json`

The summary reported only the missing configuration key names: lab-control
executable, controller/agent/primary/backup/Windows hosts, both certificate
paths, UDP/TLS ports, and lab authorization secret. It contained no endpoint
values or secret material. No scenario was started and no reset was required
because preflight detected the missing infrastructure before mutation.

The initial-WAN local row was also invoked explicitly:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File tests/benchmarks/scripts/run_multi_region_relay.ps1 `
  -Scenario initial_wan_local
```

- Observed exit code: `3`
- Observed verdict: `INFRA_FAIL`
- Sanitized reason: missing initial-WAN lab control and trusted attestation
  public-key configuration
- Cleanup: no row or container was started; the temporary summary used for
  verification was removed after inspection.

## Rows required for product acceptance

All rows below must produce invocation-bound artifacts and an enforced `PASS`:

- Linux primary to Linux backup;
- Linux primary to the declared Windows Docker mode (or an explicitly declared
  already-qualified WSL2 mode);
- failure before replacement allocation;
- coturn process kill during video, audio, and control traffic;
- full regional outage;
- planned drain;
- soft and hard capacity admission;
- UDP blocked with TCP/TLS fallback;
- relay certificate revocation;
- backend outage with an existing allocation; and
- backend outage with expired directory cache and fail-closed new-session
  admission.

Product acceptance requires failed-node removal within 10 seconds, media and
control recovery within 20 seconds, a runtime-selected backup relay in a
different failure domain, unchanged authorization, recorded `ReleaseAll`,
restored video/audio/control evidence, and complete reservation/allocation/
input/lab cleanup. Missing infrastructure is always `INFRA_FAIL`; a port-open,
process-running, static fixture, or ignored live test can never substitute for
these rows.

## Rerun checklist

1. Configure the variables and secret consumed by
   `.github/workflows/multi-region-relay-device-lab.yml` on a self-hosted
   `multi-region-relay` Windows controller.
2. Confirm both certificate files and the lab-control executable are protected
   local files; do not pass secrets on the command line.
3. Run the command above and archive the entire output directory with
   `if: always()`.
4. Require the runner exit code and summary verdict to be `PASS`, and require
   every row evaluation to pass the committed
   `windows-multi-region-relay.v1.json` policy.
5. Update this record with sanitized host modes, coturn versions, topology
   labels, artifact paths, timings, and final verdict. Do not add private
   endpoints or credentials.
