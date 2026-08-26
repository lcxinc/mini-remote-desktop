# Multi-region TURN relay acceptance record

- Date: 2026-08-26
- Branch: `codex/multi-region-turn-relay`
- Implementation commits: `e3c39a23`, `af91b9e9`, `534577f9`, `1c44870a`
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
| Multi-region integration | PASS | 2 tests: three-node/two-region capacity lifecycle plus real failover coordinator/security cleanup |
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

The proxy/control-plane acceptance scope currently begins with an already
authenticated, connected relay session. `mrd-service` can consume and emit
authenticated migration messages and execute failover, but
`install_connected_relay_session` has no production caller and the service
does not yet orchestrate the initial WAN grant/offer/answer/candidate flow.
The legacy Rdesk signaling path is not a substitute for that thin-shell
architecture. Therefore a fresh end-user WAN session through the new local
service is **not accepted** by this record; it needs a separate initial-session
integration plan and security design for candidate commitments.

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
