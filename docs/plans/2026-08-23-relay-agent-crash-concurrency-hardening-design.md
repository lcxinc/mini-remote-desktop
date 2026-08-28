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
are accepted. Renewal error bodies cross the same bounded, no-store boundary
before strict decoding. Only a stable `relay_heartbeat_replayed` 409 is a
sequence-replay candidate; every other well-formed renewal 409 is rejected and
a malformed error body is protocol-invalid.

All signed `RelayRegistry` PostgreSQL node mutations acquire the same per-node
transaction advisory lock and then issue a fresh `SELECT ... FOR UPDATE` that
refreshes the ORM identity map. Authentication performed before the lock is
only preliminary; fingerprint, identity epoch, sequence, directive and
rotation state are checked again from the locked row. Heartbeat sequence is
monotonic under every signed mutation. Rotation status does not change the
rotation outcome, audit history, or business timestamp, but it does consume
and persist its authentication sequence under that same lock. Rotation
upload/commit auditing is exactly once.

## Portable runtime and crash recovery

The backend worker waits for its monotonic deadline before taking a fresh
shared-health snapshot. The supervisor marks a probe generation in progress
before awaiting it, so an old live result cannot extend a lease. Local and
transient backend failures become fail-closed health samples plus bounded
retry, while protocol, identity and persisted-state corruption remain fatal.
The production worker gives heartbeat its own absolute monotonic 5-second
cadence. Identity maintenance synchronously prepares and persists candidate
state plus the consumed request sequence, then places an owned backend/request
future in the event loop; that future never borrows the certificate state or
holds its exclusive owner across a network await. A one-second hard timeout
drops the owned HTTP future well before the next heartbeat. Timeout and 503
retry retain the renewal id, CSR and candidate key, but consume and persist a
fresh sequence and signature after the intervening heartbeat. No maintenance
request is detached with `spawn`. Identity, permission, certificate and
persisted-state errors propagate through the agent's `try_join`, which drops
the in-flight request and cancels coturn supervision; transient network errors
leave both the exact heartbeat cadence and coturn supervision running.
If a renewal committed remotely but its response was lost, only the old
certificate heartbeat's 401 authorization failure is suppressed while the
same-epoch exact renewal retry is pending; a 403 revocation or any other
rejection still stops the agent. The retry then retrieves the cached
certificate with the same renewal id and CSR but a fresh sequence. A 401 from
the renewal request itself remains fatal. A renewal 409 is recoverable only
when both its stable reason is `relay_heartbeat_replayed` and the local
heartbeat watermark proves that exact request sequence was overtaken.

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
changed, the agent first sends a signed rotation-status request. It is
read-only with respect to the rotation result, but consumes the signed request
sequence as an authentication watermark; a replay of that sequence is 409.
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
so the first character is always alphanumeric. Boot IDs decode to exactly 16
bytes and reject every non-canonical base64url spelling on both Python and
Rust.

Controllable plaintext JSON buffers and temporary decoded/base64 values use
zeroizing mutable storage. Relay rotation upload JSON is serialized exactly
once into a zeroizing owner; the same exact bytes are signed and retained by a
`Bytes::from_owner` request body until reqwest drops the request. Enrollment
JSON follows the same owned-body rule instead of reqwest `.json()`. Copies
inside reqwest, hyper, rustls, the kernel and a terminating TLS proxy are
opaque upstream boundaries and are not claimed to be physically zeroized.

Python canonical base64url validation writes directly from the existing
Pydantic string or a memoryview into a mutable bytearray, rejects padding and
non-canonical unused bits, and clears every application-owned decode/encode
buffer in `finally`. Pydantic's input string, the immutable argument required
by AESGCM, Starlette/FastAPI's immutable replay body, and TLS/framework copies
are explicit third-party boundaries. The ASGI boundary still clears its final
controllable request accumulator byte by byte after downstream completion or
failure.

Fresh private-key seeds, generated signing-key owners and generated PKCS#8
documents also have zeroizing drop semantics.
rcgen borrows the source DER, and its internal serialized-key copy is held by a
`Zeroizing<KeyPair>` owner through CSR generation and every error path.
Public TURN endpoints reject userinfo, paths, fragments, non-transport query
values, and embedded credentials. Controllable owned SDP, ICE candidate, ufrag
and accessible ICE-server copies are explicitly cleared on teardown and never
rendered through Debug. Opaque private copies inside webrtc-rs are released
with the peer but are outside its accessible clearing API.

## Migration and lifecycle invariants

The final unpublished v8 schema includes rotation challenge and committed
proof constraints. A historical `state='draining'` row is backfilled to
`desired_draining=true` in the same migration transaction. A real historical
v6 schema upgrades contiguously to the same v8; v7 to v8 remains exactly three
mutations (the backfill stays inside its existing `DO`), steady-state migration
is read-only, and v7 and generic-upgrade failures roll back schema, data and
ledger together.

`desired_draining` is durable administrator provenance. Rotation safety drain
is derived from the locked transaction fields, and effective drain is their
union. Thus a pure rotation directs `draining=true` before commit and returns
to unavailable after commit without manufacturing administrator intent. An
administrator drain set before or during rotation survives commit as
`desired_draining=true` and `state='draining'` until explicit resume. A failed
or non-evidence heartbeat cannot erase effective drain, and admin resume is
rejected while a rotation is pending. Probe health has one shared vocabulary;
non-live states do not renew a healthy lease or cause an unbounded restart
loop.

Certificate renewal reads the freshly locked row. New renewals fail closed
before certificate issuance whenever a rotation intent, pending upload,
challenge, or credential transition window exists. A pure administrator drain
is preserved as desired drain and `draining` state across the new identity
epoch; an ordinary renewal starts unavailable. An exact cached lost-response
retry is available only to the previous identity and may return the
already-issued certificate while advancing only the previous-epoch replay
watermark, never current sequence, drain/rotation state, or audit history. The
current identity receives 409 even when renewal id and CSR match exactly.
