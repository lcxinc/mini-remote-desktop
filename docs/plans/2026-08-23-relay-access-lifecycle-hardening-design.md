# Relay Access Lifecycle and Operations Hardening Design

## Security boundaries

Device inventory and mutation APIs authenticate before querying device identity. Ordinary users see only devices that are both in their tenant and bound to them; administrators retain inventory access. Device proof uses a separate JWT audience and token type and is bound to a persisted device authentication version, so rotation or revocation invalidates stolen tokens immediately.

Raw motherboard serials remain request-only secrets. The database stores a domain-separated HMAC-SHA256 digest under a dedicated pepper. The nullable legacy serial column is retained only as an upgrade bridge: a versioned migration digests existing values, rejects collisions or missing key material, clears plaintext, and verifies that no plaintext remains. Concurrent registrations acquire the serial-digest advisory lock before enrollment/device rows and map uniqueness races to stable conflicts.

## Locking and capacity

Session workflows acquire a domain advisory transaction lock first, then database rows in the single order Device, sorted Users, SessionRequest. Relay selection reads an unlocked snapshot. Reservation admission locks only one candidate node and its registration at a time, then revalidates health, topology, certificate, capacity, and pending reservations inside that lock.

Reservations carry a directory generation and nullable superseded timestamp. Superseded reservations no longer consume the session's current primary/backup slots, but remain unexpired and count against node capacity until their credentials expire. A successful replacement supersedes omitted current reservations in the same transaction; signing, credential, or admission failures roll the transaction back without changing the previous directory.

All authorization deadlines are floored once to a Unix second. The reservation row, signed directory milliseconds, and TURN username use that same exact second.

## Secrets and response handling

All token, certificate, and relay-credential responses set `Cache-Control: no-store, private` and `Pragma: no-cache`. Relay TURN encryption configuration supplies one active key and a bounded JSON map of prior read keys. Decrypting a prior-key envelope returns a re-encrypted active-key envelope which is persisted in the issuance transaction. Unknown keys remain fail closed. TURN secrets must decode from canonical base64url to exactly 32 bytes and pass explicit repeated/placeholder rejection.

## Grant lifecycle and migrations

Session request, approval, rejection, closure, and revocation are immutable row-locked transitions with participant/owner/admin authorization and durable redacted audits. Terminal transitions set grant/policy deadlines to the current instant and supersede current reservations so access fails immediately while old capacity remains reserved through credential expiry.

Relay access ledger versions drive once-only work. A current-version startup performs catalog/data verification only. Missing versions run their DDL/backfill once under the existing advisory lock and record that version in the same transaction. Contradictory historical ownership fails with a PII-free row count and remediation instruction rather than silently discarding ownership. Extra ordinary nonunique btree operational indexes are accepted; extra constraints, unique/partial/expression/include indexes, or unknown future versions are rejected.

## Verification

Each boundary is introduced with a failing unit or real-PostgreSQL test. Final gates cover expanded device/session/relay suites, migration and concurrency tests on PostgreSQL, the full backend, 27 Rust relay contract tests, production OpenAPI/import, compileall, dependency checks, and clean diffs.
