# Relay Agent Crash And Concurrency Hardening Design

**Status:** Implemented and verified by the deterministic Task 7 Rust, Python,
and PostgreSQL gates. "Production audit" below means that the code and protocol
findings are closed; it does not claim live forced-relay or performance
acceptance. The tests that require `MRD_TEST_TURN_*` infrastructure and the
transport performance tests remain explicit non-evidence until the required
Task 11 live and performance lanes run.

This addendum closes the second Task 7 production audit without adding Task 8
service-manager integration. The review specification is the approved design
input for this addendum.

## Security boundaries

Every relay-agent backend HTTPS client uses only the configured private CA.
Built-in WebPKI roots are disabled, while normal hostname and SAN verification
remains enabled. The coturn metrics endpoint is restricted to loopback HTTP;
HTTPS is rejected unless a future interface supplies a separate pinned CA, so
metrics cannot silently re-enable the platform trust store. Sensitive
responses, including heartbeat directives, require both
`Cache-Control: private, no-store` and `Pragma: no-cache` before their bodies
are accepted.

All signed `RelayRegistry` PostgreSQL node mutations acquire the same per-node
transaction advisory lock and then issue a fresh `SELECT ... FOR UPDATE` that
refreshes the ORM identity map. Authentication performed before the lock is
only preliminary; fingerprint, identity epoch, sequence, directive and
rotation state are checked again from the locked row. Heartbeat sequence is
monotonic under every signed mutation and rotation upload/commit auditing is
exactly once.

## Portable runtime and crash recovery

The backend worker waits for its monotonic deadline before taking a fresh
shared-health snapshot. The supervisor marks a probe generation in progress
before awaiting it, so an old live result cannot extend a lease. Local and
transient backend failures become fail-closed health samples plus bounded
retry, while protocol, identity and persisted-state corruption remain fatal.
Identity maintenance runs independently from heartbeat cadence and coturn
supervision.

The active certificate identity epoch is authoritative on restart. Equal
epochs are a no-op. An exact `N -> N+1` crash-window may clear the old sequence
only when no secret rotation is in flight; otherwise it fails closed rather
than orphaning epoch-scoped coturn or commit state. Rollback and larger jumps
also fail closed. First activation persists the server-authorized secret
version and digest before the first heartbeat. An active certificate cannot
authorize a replacement v1 secret from configuration, and an inactive
identity cannot reuse a previously activated runtime secret. A commit with an
unknown response is reconciled before any heartbeat that could advertise the
old version.

Persisted probe evidence is never sufficient to start a pending commit. For an
unknown response in the same coturn generation, a fresh validation probe is
required but the agent retries the byte-identical persisted commit proof/body
so the server can recognize the transaction exactly. If the generation
changed, the agent first sends a signed, read-only rotation-status request.
`CommittedExact` establishes the server transaction outcome, but the agent
still reapplies the target secret when necessary and requires a fresh Live
allocation roundtrip in the current coturn generation before it finalizes the
local version or advertises it. `Pending` discards the stale proof and performs
a new current-generation probe and proof before a new commit attempt. Unknown
or mismatched state fails closed. Thus a new proof is never substituted for an
already committed server transaction, old evidence is never used to commit a
still-pending transaction, and neither branch can advertise a version that the
current local generation has not proven Live. Non-evidence remains unavailable
and cannot consume a challenge.

## Secret lifetime and wire consistency

Canonical identifiers use their protocol-specific bounds: node IDs are 1..128
and may contain dots; generated renewal and rotation IDs use rejection sampling
so the first character is always alphanumeric. Boot IDs decode and re-encode
to exactly 16 base64url bytes on both Python and Rust.

Controllable plaintext JSON buffers and temporary decoded/base64 values use
zeroizing mutable storage. Fresh private-key seeds, generated signing-key
owners and generated PKCS#8 documents also have zeroizing drop semantics.
rcgen borrows the source DER, and its internal serialized-key copy is held by a
`Zeroizing<KeyPair>` owner through CSR generation and every error path.
Public TURN endpoints reject userinfo, paths, fragments, non-transport query
values, and embedded credentials. Controllable owned SDP, ICE candidate, ufrag
and accessible ICE-server copies are explicitly cleared on teardown and never
rendered through Debug. Opaque private copies inside webrtc-rs are released
with the peer but are outside its accessible clearing API.

## Migration and lifecycle invariants

The final unpublished v8 schema includes rotation challenge and committed
proof constraints. A real historical v6 schema upgrades contiguously to the
same v8; v7 to v8 remains exactly three mutations, steady-state migration is
read-only, and rollback restores the previous ledger state.

Rotation forces desired drain until atomic commit. A failed or non-evidence
heartbeat cannot erase the desired drain, and admin resume is rejected while a
rotation is pending. Probe health has one shared vocabulary; non-live states do
not renew a healthy lease or cause an unbounded restart loop.
