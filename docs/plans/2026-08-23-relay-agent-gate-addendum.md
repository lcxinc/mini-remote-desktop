# Relay Agent Gate Completion Addendum

This addendum closes the Task 7 gaps discovered after the initial relay-agent
core review. It refines the approved multi-region TURN relay design without
adding Linux systemd or Windows SCM integration.

## Wire and identity epochs

The Rust agent and Python control plane share fixed heartbeat request and
response fixtures. The state vocabulary is exactly `available`, `degraded`,
`draining`, `unavailable`, and `revoked`.

Every heartbeat carries a per-process random `boot_id`, a fresh CSPRNG nonce,
the persisted heartbeat sequence, the current identity epoch, process,
listener, and allocation-probe health, bounded capacity and traffic metrics,
resource pressure, configured endpoints, and the applied secret version. A
process restart creates a new boot ID but continues the persisted sequence for
the same identity epoch. Certificate renewal increments the identity epoch and
resets its sequence. Requests and directives from a grace-period certificate's
old epoch cannot mutate the new epoch.

The strict response binds node ID, identity epoch, request sequence, current
state, and desired drain/secret-rotation state. Sensitive relay responses use
`Cache-Control: no-store`. Unknown fields, identities, epochs, states, nonces,
and bounds fail closed.

## Portable orchestration and certificate lifecycle

`run_agent` owns independent identity, heartbeat, and coturn-supervisor tasks.
No coturn or identity lock is held while awaiting the backend. A stalled or
backing-off backend therefore cannot pause local supervision. The supervisor
uses injected 1, 2, and 4 second restart delays, stops after exactly three
failed restarts, and reports unhealthy until a real allocation probe succeeds.

Certificates are validated against an injected trust root and wall clock on
generation, reload, pickup, and renewal. CSR and leaf identity, unique URI SAN,
Basic Constraints, Key Usage, Extended Key Usage, CA authorization, validity,
and wire expiry must all match. A renewal candidate must first produce a usable
mTLS client. Only then may its complete key/certificate pair be atomically
promoted and the backend client hot-swapped. Any failure retains the old pair
and client.

## Node-generated secret rotation

Administrators create only a desired secret version and drain instruction. The
agent persists the intent, drains new traffic, waits for zero active allocations
and the old credential deadline, then creates or resumes one canonical random
secret for that epoch and version. It uploads the secret over mTLS using the
existing body-bound Ed25519 request authentication. The backend stores it as an
AES-GCM encrypted pending value.

After local application and a real allocation/permission/relayed-packet probe,
the agent sends an authenticated commit. The backend atomically switches the
active encrypted secret/version and records an audit event. The agent then
persists completion and resumes only if desired. Epoch, version, idempotency ID,
and secret digest make upload and commit restart-safe and reject conflicting
replays. Secrets never appear in heartbeat responses.

## Evidence and persistence

Only the production local probe implementation can construct live evidence.
Test fakes and unavailable environments produce an explicit non-evidence
result. Runtime intent and directive state use a restrictive, atomic portable
store; secret buffers are zeroized and all debug, display, error, and log paths
remain redacted.
