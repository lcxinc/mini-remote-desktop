# Multi-Region TURN Relay Design

**Date:** 2026-08-22
**Status:** Approved
**Scope:** Production TURN relay control plane, cross-platform node management,
capacity-aware multi-region selection, and active-session failover.

## Objective

Complete the proxy-server portion of MRD by turning the current single-node
coturn configuration and credential endpoint into a production relay system.
The system must run on ordinary Linux hosts and on Windows hosts where coturn is
installed directly or hosted through Docker/WSL2. It must select relays across
regions, enforce capacity, remove failed nodes within 10 seconds, and recover an
active WebRTC session through an alternate relay within 20 seconds.

The relay remains unable to read desktop content. WebRTC DTLS-SRTP and data
channel encryption terminate only at the two MRD peers; coturn forwards the
encrypted packets.

## Decisions

- Keep coturn as the TURN data plane instead of implementing a new TURN server.
- Add a cross-platform Rust `mrd-relay-agent` beside each coturn instance.
- Make `Rdesk-Server` the authoritative relay directory, enrollment,
  credential, lease, and capacity-reservation service.
- Put transport-independent relay policy, health, selection, and signed
  directory contracts in `mrd-relay-control`.
- Authenticate relay nodes to the backend with mTLS.
- Use a unique TURN REST HMAC secret per relay node.
- Sign client-visible relay directories with Ed25519.
- Treat static YAML as bootstrap and disaster-recovery configuration, not as
  live relay truth.
- Use authenticated signaling to carry ICE restart generations; signaling does
  not select relays or issue credentials.

## Scope And Non-Goals

This work includes relay enrollment, certificate lifecycle, heartbeat and
metrics reporting, node state, capacity reservations, directory signing,
short-lived node-scoped TURN credentials, service-side selection, planned
drain, unplanned failover, deployment scripts, observability, and deterministic
plus device-lab verification.

It does not replace coturn, terminate media in a backend service, weaken session
grants, introduce anonymous TURN access, or build a Kubernetes operator. The
backend API remains stateless enough to run multiple replicas over the existing
PostgreSQL database, but database multi-region replication is an operations
concern outside this feature.

## Architecture

```text
coturn -- local metrics/process state --> mrd-relay-agent
                                             |
                                     mTLS registration,
                                     heartbeat, capacity
                                             |
                                             v
                                       Rdesk-Server
                              relay leases + reservations
                              directory + credentials
                                             |
                                  signed directory and
                                  short-lived credentials
                                             |
                                             v
                                        mrd-service
                              selection + ICE restart
                                             |
                                             v
                              encrypted WebRTC/TURN data
```

### `apps/mrd-relay-agent`

The relay agent is a small Rust daemon or Windows service. It owns node identity,
mTLS connection management, enrollment and certificate renewal, coturn health
and metric collection, bounded process supervision, desired drain state,
configuration validation, secret rollout, and audit-safe local logs. It never
receives account tokens, desktop plaintext, session content, or device private
keys.

The process-control and metric-collection interfaces are abstract ports so unit
tests do not start coturn or mutate the host. Production adapters support
systemd on Linux and Windows Service Control Manager on Windows. A Windows host
may point the agent at a native coturn process, Docker container, or WSL2
wrapper, but all variants expose the same local health and process contract.

### `crates/mrd-relay-control`

This crate owns the transport-independent contract:

- `RelayNodeId`, region and failure-domain identifiers;
- node capabilities and public TURN endpoints;
- node lease, health, load, capacity, drain, and revocation states;
- capacity reservation rules;
- versioned signed relay directory envelopes;
- deterministic eligibility filtering and scoring;
- stable selection, rejection, and failure reason codes;
- hysteresis and circuit-breaker decisions.

It does not import FastAPI, SQLAlchemy, coturn, WebRTC, or operating-system APIs.
Rust clients use it directly. Python implements the same wire contract and is
checked against shared golden signature vectors.

### `apps/Rdesk-Server`

The backend stores relay nodes, certificate fingerprints, node leases, current
capacity, reservations, drain state, revocation state, and audit events in
PostgreSQL. It provides node enrollment/heartbeat endpoints, authenticated
client directory and credential endpoints, and administrator drain/revoke
operations.

Capacity admission uses a database transaction so concurrent API replicas
cannot oversubscribe a node. Per-node TURN secrets are encrypted at rest and
never returned through the directory API.

### `apps/mrd-service`

The service fetches and verifies signed directories, measures or consumes
bounded RTT evidence, chooses primary and backup relays, configures the WebRTC
adapter, validates the selected candidate pair, and initiates relay migration.
The UI may request a route policy but cannot inject relay endpoints, skip
directory verification, or weaken capacity and identity checks.

### `apps/realtime-server`

The realtime server forwards authenticated offer, answer, candidate, close, and
migration messages. Migration messages carry a monotonically increasing
`migration_generation`. It does not store relay secrets, decide capacity, or
claim which relay was selected.

## Node Enrollment And Identity

On first start, the relay agent generates a private key and certificate signing
request. It exchanges a one-use, short-lived enrollment token for an approved
node certificate. The certificate binds the node ID and permitted backend role.
The backend stores only a hash of the enrollment token.

Linux protects the private key with a dedicated service user and restrictive
filesystem permissions. Windows protects it with machine-scope DPAPI and a DACL
restricted to the relay-agent service identity and required system principals.
Certificate renewal uses the current mTLS identity. Revoked nodes cannot renew
or silently re-enroll.

In deployments that terminate mTLS at a reverse proxy, the proxy must remove
all incoming certificate headers, verify the client chain and revocation state,
bind only to a private or loopback backend listener, and forward the verified
certificate fingerprint. The application additionally verifies a signed node
request and matches both identities to the stored node record.

## Registration And Health

The agent sends a heartbeat every five seconds. Each heartbeat contains a
strictly increasing sequence, sample time, process and listener health, active
allocation count, ingress and egress bandwidth, configured allocation limit,
packet-loss indicators, CPU and memory pressure, public endpoint capability,
and desired drain state. Fields and cardinality are bounded.

A node lease expires after 15 seconds without an accepted heartbeat. A node
that recovers must produce three consecutive healthy heartbeats before it can
receive new sessions. Old sequence numbers, unreasonable clock movement,
identity mismatch, and unknown critical fields are rejected rather than
silently normalized.

The node state machine is:

```text
enrolling -> ready -> degraded -> draining -> unavailable
                          \----------------------> revoked
```

- `ready` accepts existing and new allocations.
- `degraded` keeps existing allocations and receives a selection penalty.
- `draining` keeps existing allocations but receives no new reservations.
- `unavailable` is absent from newly issued directories.
- `revoked` cannot register, receive credentials, or automatically recover.

The agent attempts at most three coturn restarts with bounded exponential
backoff. Continued failure produces `unavailable`; it never loops indefinitely
while reporting the node as healthy.

## Capacity And Relay Selection

Selection has two stages.

The backend performs hard admission filtering. A candidate must have a valid
node certificate, a fresh ready/degraded lease, working coturn listeners, an
allowed region, a compatible UDP/TCP/TLS endpoint, no drain or revocation, and
free hard capacity. A transactional reservation protects capacity for 30
seconds while ICE creates an allocation.

The deterministic selection policy then scores admitted nodes using region
preference, measured RTT, bandwidth headroom, allocation utilization, recent
failure rate, and degraded status. A node above its soft utilization threshold
receives an increasing penalty. A node at its hard limit is ineligible for new
reservations. Stable node ID is the final tie-breaker, so equal inputs produce
equal results.

The directory returns a preferred node and at least one backup in a different
failure domain whenever policy and capacity allow it. Different ports on one
host are not independent backups. Region policy is a hard filter when required
by policy and a preference otherwise.

WebRTC may receive more than one ICE server, but the configured list is not
selection evidence. MRD accepts a relay result only after runtime statistics
show a relay candidate pair and a sanitized allocation/server identity matching
one directory node.

## Directory And Credential Contracts

A relay directory contains:

- format and policy versions;
- directory ID, issue time, and expiry time;
- session and intended-peer bindings or their non-secret stable digests;
- ordered relay candidates with node, region, failure-domain, endpoint,
  capability, load-class, and selection-reason fields;
- reservation identifiers and expiry;
- the backend signing-key ID and Ed25519 signature.

The signed input has one documented canonical encoding. Rust and Python tests
consume the same positive and negative vectors. Unknown critical fields,
unknown versions, stale policy, expired timestamps, duplicate node IDs, or an
untrusted signing key fail closed. Signing-key rotation uses an explicitly
trusted key set and bounded overlap.

Each node has an independent TURN REST secret. Credentials bind expiry, user,
session, and node ID in the username and use the existing coturn-compatible
HMAC construction. Credential expiry is the minimum of ten minutes, the active
session-grant deadline, directory deadline, and applicable policy deadline.
The backend issues credentials only after session authorization and capacity
reservation. Static credentials and anonymous access are prohibited.

TURN secret rotation uses a controlled drain: stop new reservations, wait for
the maximum old credential lifetime, replace the secret, validate a real
allocation, and resume. This avoids accepting credentials on the wrong node or
breaking existing allocations.

## Active-Session Failover

ICE `disconnected` starts a short grace timer; ICE `failed` begins recovery
immediately. The service performs the following sequence:

1. Send local `ReleaseAll`, freeze new input, and snapshot current route proof.
2. Verify that the exact session grant, scopes, peer binding, lease, and policy
   revision remain valid.
3. Select a backup outside the failed node's failure domain. Refresh the signed
   directory and credentials when they are stale or near expiry.
4. Exchange authenticated ICE restart messages carrying the next migration
   generation.
5. Establish and validate a real relay candidate pair and allocation identity
   for the backup node.
6. Atomically publish the new route, resume media and control, and close the old
   route.

Late messages from an older migration generation cannot replace the winner. If
the underlying WebRTC library cannot update ICE configuration in place, the
adapter rebuilds the PeerConnection while preserving the logical session ID,
grant, TransportMux contract, and feature state. A reachability failure may try
another eligible relay. A signature, certificate, grant, identity, or policy
failure is terminal and cannot trigger an insecure fallback.

The target service levels are removal of a failed node from new selection
within 10 seconds and restoration of an active session within 20 seconds. If
all eligible backups are unavailable or full, the session closes with a stable
failure reason instead of using anonymous TURN, a static password, or broader
permissions.

Planned maintenance sets drain first. New sessions stop immediately, active
sessions migrate at a bounded rate, and coturn shuts down only after allocations
reach the configured threshold or the explicit maintenance deadline expires.

## APIs

The exact resource names may be refined during implementation, but ownership is
fixed:

- relay-node enrollment and certificate renewal;
- relay-node heartbeat and desired-state synchronization;
- authenticated session relay-directory retrieval;
- node-scoped TURN credential issuance;
- administrator list, approve, drain, resume, rotate, and revoke operations.

Node endpoints require mTLS plus request signing. Client endpoints require an
authenticated user, authorized device relationship, and active session grant.
Administrative mutations require an administrator role and produce audit
records. Error responses expose stable reason codes without secrets or internal
network topology.

## Deployment

`deploy/turn` provides:

- hardened coturn configuration with UDP, TCP, TLS, a bounded relay port range,
  quotas, rate limits, loopback-only metrics, and drain support;
- Linux systemd units and install, upgrade, uninstall, firewall, and validation
  scripts;
- Windows Service installation and validation scripts for the relay agent;
- Windows examples for native coturn, Docker, and WSL2-backed coturn;
- certificate enrollment and rotation instructions;
- a versioned multi-region bootstrap YAML example;
- preflight and end-to-end allocation probes.

TURN over TCP/TLS, including configurable port 443 where the host can dedicate
that port, supports UDP-blocked networks. A health check must prove listener
reachability, credentials, allocation, permission, and relayed traffic; process
liveness alone is insufficient.

## Observability

Metrics expose node state, lease age, allocations, reservations, bandwidth,
capacity utilization, restart count, selection results, failover phase and
duration, and stable failure reasons. Metric labels never contain user or
session IDs.

Audit records include node enrollment, certificate renewal/revocation, drain,
secret rotation, directory issuance, capacity rejection, selected node,
migration generation, and cleanup. Logs exclude TURN credentials, private keys,
full session grants, raw user traffic, and credential-bearing URLs. Public
endpoint details are available only where required for operation and are
sanitized elsewhere.

## Failure Rules

- Backend unavailability does not terminate an existing TURN allocation.
- A new session may use a cached directory only while its signature, policy,
  reservation, and credentials are valid.
- Expired cached state produces an explicit unavailable result.
- Reservation expiry is not evidence that an active allocation ended; reported
  allocation metrics remain authoritative for load.
- Database transaction conflicts retry within a bounded budget and never
  oversubscribe capacity.
- Control-plane clock skew outside the configured tolerance is an infrastructure
  fault, not a reason to extend credential validity.
- Revocation and terminal security failures dominate reachability fallback.

## Test Strategy

`mrd-relay-control` unit tests cover hard filters, stable ordering, distinct
failure domains, soft and hard capacity, reservation expiry, hysteresis, drain,
revocation, and stable reason codes.

Backend tests cover one-use enrollment, mTLS and signed-request binding,
certificate renewal and revocation, heartbeat replay protection, concurrent
PostgreSQL reservations, tenant isolation, node-scoped credentials, signed
directories, and secret redaction.

Relay-agent tests use fake metric, process, secret, clock, and backend ports to
cover collection, timeouts, bounded restart, drain, secret rollout, offline
reconnect, and Linux/Windows path handling without mutating the host.

Cross-language contract tests use shared Ed25519 directory vectors. Tests must
reject changed order/encoding, unknown versions, modified nodes, expired
directories, and untrusted keys.

Integration and device-lab tests use at least three real coturn nodes across two
regions and two failure domains. They prove:

1. Expected region/RTT/capacity selection with real relay-pair evidence.
2. Soft-limit deprioritization, hard-limit rejection, and no concurrent
   reservation oversubscription.
3. Backup selection when the preferred node fails before allocation.
4. Active failover after process kill, network outage, or node revocation,
   meeting the 10-second removal and 20-second restoration targets.
5. Video, audio, reliable/realtime control, and pressed-state correctness after
   migration.
6. Real TURN TCP/TLS relay when UDP is blocked.
7. Fail-closed behavior for forged directories, expired credentials, wrong
   node secrets, replayed heartbeats, invalid certificates, and cross-session
   credential use.
8. Existing allocations during a backend outage and honest new-session failure
   after valid cached state expires.
9. Linux systemd and Windows Service install, upgrade, restart, and uninstall
   behavior without secret leakage or orphan services.

Normal CI runs deterministic unit, contract, fake-node, and workflow tests.
Public multi-region and fault-injection tests run only on configured self-hosted
infrastructure. Missing nodes, certificates, ports, or network control produce
`INFRA_FAIL`; they can never be reported as a pass or a silent skip.

## Acceptance

The proxy-server work is complete only when all deterministic suites pass and a
configured device lab produces real selected-relay, allocation, capacity,
failure, migration, media recovery, audit, and cleanup evidence for both Linux
and the declared Windows deployment path. Merely issuing credentials, listing
relay URLs, starting coturn, or passing loopback tests is insufficient.
