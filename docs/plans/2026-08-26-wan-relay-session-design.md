# Initial WAN Relay Session Design

## Status

Approved on 2026-08-26.

This design closes the remaining thin-shell integration gap after the
multi-region TURN relay control plane and active-session migration work. It
makes `mrd-service` the only owner of a fresh WAN session from authorization
through generation-zero relay verification and automatic media startup.

## Decisions

- Initial session signaling moves to protocol v3. Protocol v2 initial-session
  messages are rejected; the existing v2 relay-migration messages remain
  compatible while migration is moved independently.
- A session grant binds identities, session, approved permissions, backend
  policy, signed relay directory, selected node, and relay-only route policy.
  It does not pre-commit ICE candidates.
- Each signed Offer or Answer commits its own complete candidate-fingerprint
  manifest. Candidate messages must match the corresponding manifest.
- Every WAN session begins relay-only on the selected TURN node. Direct-first
  WAN negotiation is outside this design.
- Only attended authorization is supported. Unattended WAN access continues to
  fail closed.
- `RemoteSessionRequest` gains an `auto | lan | wan_relay` route preference and
  defaults to `auto`.
- FastAPI exposes device-authenticated session request and decision endpoints.
  User access tokens never cross local IPC.
- The IPC-supplied session ID remains authoritative and becomes the backend
  idempotency key.
- Generation-zero relay verification automatically starts authorized target
  capture and controller receive paths.

## Architecture

### Rdesk and local IPC

Rdesk remains a thin shell. It submits `RemoteSessionRequest`, presents exact
consent/session snapshots, and subscribes to typed events. It never handles
backend device tokens, TURN credentials, SDP, ICE candidates, device signing
keys, or raw grants.

`mrd-ipc` adds `RemoteRoutePreference`:

- `Auto`: choose LAN only when the service already has a fresh, signed,
  public-key-pinned discovery record for the target; otherwise immediately use
  WAN relay.
- `Lan`: require the secure LAN path and do not fall back.
- `WanRelay`: skip LAN discovery and require the WAN relay path.

The field uses a serde default of `Auto` so old local callers remain readable.

### Backend authorization and relay access

FastAPI adds device-authenticated request, inspect, approve, reject, close, and
revoke operations. The backend derives the bound user from the authenticated
device and enforces these role rules:

- the requesting device belongs to the requester and cannot be the target;
- only the exact target device can approve or reject;
- only either bound participant can inspect or close;
- the same session ID is idempotent only for the same requester device, target
  device, request payload digest, and active policy;
- any conflicting reuse fails without revealing another session.

Approval transactionally binds the policy revision and deadline, selects the
primary plus different-failure-domain backups, and reserves bounded capacity.
The backend creates one immutable relay access generation for the session. Both
participant devices receive the same signed directory ID, candidate ordering,
endpoint set, reservation IDs, and expiry. TURN credentials may be separately
issued per participant, but their node/URL digest must match the shared signed
directory.

A refresh that needs a new relay access generation is serialized by the
session row. Migration signaling names that generation's directory ID. The
other peer fetches that exact active generation before accepting migration.

### Signaling protocol v3

The realtime server remains a routing and connection-authentication boundary;
it never receives TURN credentials. End-to-end device signatures cover all
session semantics.

`SessionIntentV3` binds:

- session ID and retry-stable idempotency key;
- controller and target device identities through signed claims;
- attended access mode;
- normalized requested permissions and optional media profile;
- backend request/payload commitment;
- relay-only route policy;
- issue and expiry times.

`SessionGrantV3` binds:

- the exact intent commitment;
- approved permissions and media constraints;
- backend policy revision and expiry;
- relay directory ID and primary node ID;
- relay-only route policy.

`WebRtcOfferV3` and `WebRtcAnswerV3` bind the grant commitment, SDP, and a
non-empty bounded set of candidate fingerprints. `WebRtcCandidateV3` binds the
grant commitment, description role, candidate payload, optional MID/index and
username fragment, and its computed domain-separated fingerprint.

Candidates are authenticated by the peer signature and accepted only if their
fingerprint appears in that peer's exact signed description manifest. This
removes the v2 circular dependency in which a grant had to commit candidates
that did not exist until after the grant.

The service signaling runtime gains a bounded generic authenticated-session
outbound bus. Relay migration can use the same transport later, but its
generation and route-token invariants remain separate from generation zero.

### Service WAN session coordinator

`mrd-service::wan_session` owns the initial WAN workflow. It coordinates the
backend client, authorization registry, authenticated signaling bus, verified
relay directory client, WebRTC host, relay failover coordinator, media runtime,
input barrier, audit projection, deadlines, and cleanup.

No UI or realtime-server code can directly install transport or permission
state. `install_connected_relay_session` becomes an internal step invoked only
after the coordinator proves generation-zero route evidence.

## End-to-end flow

1. The controller validates the IPC request. `Auto` uses LAN only from an
   already-fresh authenticated discovery entry; otherwise it selects WAN.
2. The controller uses its service-owned device token to idempotently create
   the same session ID in FastAPI.
3. The controller installs a pending controller authorization aggregate and
   sends signed `SessionIntentV3`.
4. The target verifies the signer and claims, independently fetches the backend
   request using its device token, compares the complete request commitment,
   and creates an attended-consent event. It creates no WebRTC peer and consumes
   no relay capacity yet.
5. On approval, the target calls the device-authenticated approve endpoint.
   FastAPI commits policy, relay selection, cross-failure-domain reservations,
   and the shared relay access generation.
6. The target fetches and verifies the signed relay access, installs its exact
   local grant, and sends `SessionGrantV3` naming the shared directory and
   primary node.
7. The controller verifies the grant and backend state, fetches the same relay
   access generation, and installs its local grant.
8. The controller opens a relay-only Offerer using its node credential, creates
   an offer, collects all bounded local candidates, sends the signed Offer
   manifest, and then sends each matching candidate.
9. The target buffers and verifies the complete controller manifest, opens a
   relay-only Answerer from the same directory node, applies the offer, collects
   candidates, sends the signed Answer manifest, and sends each matching
   candidate.
10. Each side applies only the candidate set committed by the remote
    description. Out-of-order messages use a bounded per-session buffer; no
    uncommitted candidate reaches WebRTC.
11. Both sides wait for connection and prove the nominated generation-zero
    selected pair is relay/relay on the exact signed-directory URL digest.
12. Each side registers the verified session with the failover coordinator.
    The target starts authorized capture/sending, the controller starts
    receiving/rendering, and the session becomes Streaming only after media and
    control evidence is available.
13. Generation 1 and later use the existing authenticated relay-migration
    protocol and stable logical mux.

## State model

The authoritative role-specific workflow projects onto these irreversible
logical phases:

```text
Created
  -> BackendBound
  -> AwaitingConsent
  -> Granted
  -> AccessBound
  -> Negotiating
  -> RelayVerified
  -> Streaming
  -> Closed | Failed
```

Every phase is bound to the session ID, both device IDs and public keys,
backend policy revision, relay access generation, and a strict absolute
deadline. Exact duplicate signed messages are idempotent. Conflicting duplicates,
skipped phases, role changes, key changes, policy changes, and terminal-state
updates fail closed.

Grant installation precedes candidate application. Relay verification precedes
media and input activation. Permission changes, revocation, expiry, or identity
changes terminate installed relay failover state before another route can be
published.

## Failure handling and cleanup

- Backend denial, invalid target, capacity exhaustion, or inconsistent relay
  generation produces no protocol grant and releases all new reservations.
- User denial or consent expiry records the backend rejection, sends signed
  denial when possible, and terminalizes both pending aggregates.
- Before connection, transient backend or signaling failures receive bounded
  retries within one total negotiation deadline. Deadline expiry closes WebRTC,
  cancels tasks, revokes/closes the backend session, and releases reservations.
- Signature, replay, identity, intent, policy, directory, candidate-manifest, or
  selected-route mismatches are terminal security failures. They freeze and
  release input, close transport, revoke the session, and clear all queued
  signaling.
- After connection, a backend outage permits only an unexpired signed access
  generation and its reservations. New negotiation or migration fails closed
  after expiry.
- Service restart does not restore in-memory grants or media authority. Active
  sessions close; backend reservations are released explicitly when possible
  and otherwise expire by TTL.
- All queues, per-session tasks, candidate manifests, message bodies, retry
  counts, and concurrent negotiations are bounded. Cancellation owns and joins
  every resource or hands it to the existing cleanup supervisor.
- TURN credentials remain in zeroizing owners and WebRTC configuration only.
  They never enter IPC, logs, errors, audit details, snapshots, fixtures, or
  persisted session rows.

## Stable failure projection

Existing `RemoteReasonCode` values should be reused where their meanings are
exact. New closed values are added only for distinct actionable failures such
as backend grant mismatch, relay capacity unavailable, signaling negotiation
timeout, candidate commitment mismatch, and relay route evidence mismatch.
Human-readable errors remain sanitized and cannot contain raw SDP, candidate
lines, credentials, tokens, public endpoints with userinfo, or grant bodies.

## Testing and acceptance

### Contract and unit tests

- IPC serialization, the default `Auto` preference, and secret-negative UI
  contracts.
- Device-auth backend role enforcement, idempotency, conflict privacy, policy
  changes, concurrent approval, capacity admission, stable shared relay access
  generation, and deterministic release.
- v3 signed golden vectors, wrong role/peer, replay, expiry, malformed scopes,
  grant commitment mismatch, candidate-manifest mutation, and explicit v2
  initial-message rejection.
- Controller and agent state transitions, message reordering, exact duplicate
  idempotency, conflicting duplicate termination, cancellation, deadline,
  partial construction, and service shutdown.
- Auto-route selection from only fresh signed and pinned LAN evidence.
- No WebRTC before approval, no candidate application before grant, no media
  before relay verification, and no leaked tasks/credentials after every
  failure phase.

### Integration tests

- Two service runtimes exchange v3 envelopes through the realtime server and a
  real coturn instance.
- Forced UDP, TCP, and TLS generation-zero relay sessions prove relay/relay
  selected pairs plus real media, reliable control, and realtime control.
- Initial primary failure and later region failure migrate through a different
  failure domain without changing session authorization.
- Capacity exhaustion, backend outage before approval, backend outage with a
  live unexpired allocation, expired directory, signaling disconnect, target
  rejection, and service restart all produce the specified stable result and
  complete cleanup.

### Product acceptance

Device-lab rows cover Linux-to-Linux and Linux-to-Windows Docker nodes across at
least two regions and different failure domains. Every row must retain
invocation-bound evidence for authorization, reservation, selected pair,
media/control traffic, migration, ReleaseAll, and cleanup. Missing topology is
`INFRA_FAIL`; unit tests, static fixtures, open ports, and ignored live tests do
not count as product evidence.

## Out of scope

- Unattended WAN authorization.
- Direct-first WAN ICE policy.
- Native Windows coturn qualification.
- Restoring active permission grants after service restart.
- Sending credentials, raw signaling, or user access tokens through local IPC.
