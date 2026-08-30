# Core Production Remediation Design

## Status

Approved on 2026-08-30.

This design remediates the production blockers found by the comprehensive
core-function audit of `main@3f265b6a520da5b2fd527ea489707db22a6dd570`.
It preserves the working attended secure-LAN path while closing the gaps that
currently let the relay control plane, WAN session workflow, desktop shell,
and release gates report success without an operational end-to-end session.

## Goals

- Make the default Linux/Windows relay-node deployment stable across
  enrollment, heartbeats, certificate renewal, capacity reservation, and
  migration.
- Make WAN authorization, generation-zero WebRTC, media, input, query, stop,
  failure, and cleanup one production-wired workflow.
- Remove remote-session paths that create snapshots or local peer connections
  without reaching the selected device.
- Close the confirmed tenant, process-control, credential, local-IPC, and Web
  Bridge security gaps.
- Package the runtime binaries that the desktop installer actually requires.
- Replace synthetic or silently skipped release evidence with required,
  environment-bound evidence.

Historical code under `junk/` is not an architecture source and is not part of
the remediation.

## Authoritative State and Fail-Closed Boundaries

### Relay identity lifecycle

The backend owns certificate-renewal policy. Enrollment pickup and renewal
responses carry an explicit `renew_at` value derived from the issued
certificate and configured renewal policy. The agent persists `renew_at` in
the same atomic identity bundle as the certificate and private key. It never
uses a hard-coded 24-hour window.

The backend rejects startup configuration unless:

- certificate validity and renewal lead time are within bounded ranges;
- `issued_at < renew_at < expires_at` after clock-skew allowance;
- the renewal lead time leaves a useful non-renewal interval;
- previous-certificate grace cannot outlive the old certificate.

An upgraded agent validates the wire value against the X.509 validity window.
Compatibility is staged: the agent first accepts an optional policy value and
uses a bounded certificate-lifetime fallback; the backend then starts emitting
the value. Routine authenticated renewal preserves the node's health evidence
and bounded lease rather than treating key rotation as a health failure. A
failed or abandoned agent still disappears when that lease expires.

### Session authorization and workflow

`SessionAuthorizationRegistry` is the sole permission authority for LAN and
WAN sessions. `WanSessionCoordinator` owns workflow phase, deadlines, receipts,
and cleanup ordering. `AppState.sessions` is a query projection and may not
grant permissions or prove that a transport exists.

Every WAN mutation runs under the existing authorization security gate. The
session identity, peer key, role, scope set, media profile, route policy,
backend commitment, and deadline must match at each boundary. Exact duplicate
messages are idempotent; conflicting reuse of a session ID fails closed.

### Transport and media truth

A session is not `Connected` until an authenticated transport mux has been
installed. It is not `Streaming` until the role-specific media task is running
and has produced fresh readiness evidence. Setting snapshot booleans is never
a substitute for starting capture, encode, send, receive, decode, or render.

All external side effects return rollback receipts. Cancellation, timeout,
revocation, failure, and close unwind media tasks, transport, failover,
reservations, authorization, and coordinator state in reverse order. Cleanup
is idempotent and bounded.

## WAN and Relay End-to-End Data Flow

### Controller

1. `RequestRemoteSession` creates an exact outgoing authorization under the
   security gate before starting the coordinator.
2. The coordinator creates the backend request and publishes a signed v3
   intent.
3. A signed grant is verified against the exact intent commitment, target
   identity, approved scope subset, media profile, policy, relay directory,
   and deadline.
4. Only the verified grant may transition the controller authorization to
   `Granted`.
5. Relay access reserves both allocation count and profile-derived egress
   bitrate in one PostgreSQL transaction.
6. Generation-zero negotiation accepts only relay candidates from the exact
   signed primary route. A final authorization/deadline check occurs before
   installing the mux.
7. The controller starts the receive, decode, and render path from that mux.
   First valid media evidence advances the session to `Streaming`.

### Target

1. A verified intent creates an incoming authorization and attended-consent
   request for the exact controller identity and requested scope set.
2. Approval creates the signed grant and transitions the target authorization
   to `Granted` in the same security boundary.
3. Generation-zero route proof installs the authenticated mux.
4. The target starts capture, encode, and video-lane send tasks from the
   approved profile and source.
5. Control-lane input is injected only after validating the session, peer,
   grant, scope, counter, replay window, and current authorization.

### Capacity and failover

Reservations record allocation units and reserved egress bits per second.
Selection applies allowed regions, preferred regions, failure domains, node
lease, certificate state, transport support, allocation headroom, and bitrate
headroom. Closing or expiring a session releases both resources.

Migration temporarily holds the old and new reservations with a bounded
overlap TTL. A health or lease failure produces a signed generation+1 route.
Both peers verify its exact directory and route evidence, atomically switch
the mux, and then release the old reservation. Once WAN is selected, the
workflow never silently downgrades to legacy `StartSession` or unauthenticated
LAN behavior.

### Query and terminal operations

Query, list, stop, fail, revoke, and close resolve both the WAN coordinator and
authorization aggregate. A terminal operation fences new media and input,
cancels owned tasks, rolls back installation and reservation receipts, and
publishes one stable terminal snapshot. Repeated terminal requests return that
result without restarting cleanup.

## Desktop, Browser, IPC, and Packaging

### Remote-session entrypoints

All production remote-device entrypoints use
`RequestRemoteSession(route=Auto)` unless the user selected an explicit secure
route. Legacy `StartSession` remains test/local-only and cannot be reached from
production UI. The UI derives progress solely from authenticated session
events or snapshots; the request acknowledgement does not set a connected
state.

The browser invokes the same service workflow through the Web Bridge. Its
preview consumes real media from the authenticated controller session. If the
preview feature or local bridge is unavailable, capability discovery rejects
the operation before session creation. The existing two-local-peer simulation
is removed.

### Web Bridge security

The service and browser share one default endpoint, `127.0.0.1:9533`.
WebSocket credentials no longer appear in the URL. Authentication uses a
bounded subprotocol or one-time upgrade credential, with exact origin checks.
Any non-loopback bind additionally requires TLS and an explicit origin
allowlist.

### Local IPC

Windows named pipes use an explicit DACL for the intended interactive user and
service identities. Unix sockets are created in an owner-only directory, use
mode `0600`, and validate `SO_PEERCRED`. Requests have bounded deadlines and
cancellation; a half-open service cannot leave the desktop awaiting forever.

Linux machine state uses an owner-verified root directory (`0700`) and atomic
secret files (`0600`) suitable for systemd. macOS uses Keychain and launchd.
These platform adapters remain separate from the cross-platform relay agent.

### Files and ancillary capabilities

Local copy and remote transfer are separate commands. Remote transfer requires
an authorized session and the mux file lane. Cancellation owns an abort handle
and cannot later be overwritten by `Completed`. Audio, clipboard, unattended
access, and power operations are advertised only when their production data
plane and authorization path are available.

### Packaging

Windows release staging builds and includes both `mrd-service.exe` and
`mrd-session-agent.exe`. The Tauri bundle or installer owns their exact paths,
service registration, ACLs, start/stop behavior, and uninstall cleanup. CI
installs the produced artifact in a disposable environment and proves UI to
service IPC before accepting it.

## API and Backend Security

- Network-group device mutations filter by the current tenant and bound user;
  any administrator exception is explicit and audited.
- Realtime status requires authentication. Start, stop, and restart require an
  administrator and serialize manager mutations.
- Fixed administrator credentials and UI autofill are removed. Bootstrap is
  possible only through the existing explicit environment configuration.
- Relay readiness reflects required CA, signing, enrollment, database, and
  regional-policy configuration rather than returning healthy when the relay
  control plane is unusable.

## Compatibility and Rollout

Security failures never fall back to legacy behavior. Additive wire changes
are deployed reader-first, then writer, and remain bounded and versioned.
Existing attended secure-LAN sessions retain their current protocol while
their UI entrypoint moves to the common route request. Existing active relay
sessions keep their current generation until close or a verified migration.

Rollout order:

1. Security and relay identity compatibility readers.
2. Backend renewal policy writer and authorization fixes.
3. WAN authorization and lifecycle production wiring.
4. Media, input, reservation, and failover data plane.
5. Desktop/browser entrypoints, local IPC, and packaging.
6. Required release gates and branch protection.

## Verification and Release Gates

Every behavior change follows RED-GREEN-REFACTOR. Required verification is:

- Rust workspace unit and integration tests with locked dependencies;
- frontend tests, type checking, and production build;
- the complete Python pytest suite, including PostgreSQL migrations,
  ownership, relay, and WAN cases;
- workspace formatting and clippy with warnings denied;
- TURN deployment contracts on LF and CRLF checkouts;
- Windows bundle install/start/IPC/stop/uninstall smoke;
- Linux relay service and secure-store smoke;
- real two-region TURN allocation, first WAN frame, authenticated input,
  forced node loss, migration, recovery, and cleanup evidence.

Synthetic fixtures remain useful unit evidence but cannot satisfy a live
release gate. Missing device-lab infrastructure blocks a production release
instead of being reported as a passing skip. `main` is protected only after
the corrected checks exist and are green.

## Completion Criteria

The remediation is complete only when each audit finding has a regression
test, the production entrypoint exercises the repaired path, all required
local suites pass, live environment evidence covers the intended Linux and
Windows relay deployment, and protected `main` rejects a change that lacks
those checks.
