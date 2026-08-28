# Relay Access Review Fixes Design

## Goal

Make relay access issuable only from a server-approved, tenant-bound session grant;
select capacity with reservation-aware fallback and trusted physical topology; keep
TURN REST secrets node-generated and backend-confined; and fail closed on malformed
PostgreSQL schemas.

## Architecture

Session creation and approval move behind JWT-authenticated server workflows. A
request contains only the target device. The requester comes from the token, and the
target's bound owner is the only approver. Approval locks the session, device, and
participant users, then writes a complete grant using server configuration for every
deadline, policy revision, region, and transport. User, device, and grant rows carry a
canonical tenant ID; relay access locks and revalidates the whole relationship in its
reservation transaction.

Relay enrollment treats topology as a proposal. The administrator must supply the
confirmed failure domain and physical host ID while approving the node. Pending or
legacy registrations without confirmed topology cannot become eligible. Backup
independence is defined by both confirmed failure domain and physical host ID, never
by endpoint hostname, DNS alias, IP literal, or port.

The relay node generates a canonical unpadded base64url 32-byte coturn REST secret
before enrollment. The enrollment request binds its SHA-256 digest and stores only an
AES-GCM ciphertext on the registration. Certificate pickup copies that ciphertext to
the node row and never decrypts or returns the secret. Only credential HMAC issuance
uses a mutable decrypted buffer, which is cleared in `finally`.

Capacity selection locks nodes, counts unexpired pending reservations from other
sessions, and folds that count into effective allocation utilization before filtering
and scoring. Reservation is two-phase inside one outer transaction: reserve the first
available primary with result limit one, then derive backup candidates from the actual
primary and reserve one node with a different confirmed failure domain and physical
host. Repository rejection continues through score order in each phase.

PostgreSQL startup retains relay-control-before-create-all-before-relay-access ordering.
Relay control advances additively for topology/registration ciphertext. Relay access
advances under its own advisory lock, backfills existing users/devices/grants to the
default tenant, leaves legacy topology unconfirmed, and verifies exact relevant types,
lengths, nullability, defaults, checks, foreign keys, indexes, and migration version.

## Error and compatibility policy

- Authorization failures are non-enumerating and do not create reservations.
- Repeated approval with the same completed grant is idempotent only for the same
  target owner; conflicting states are rejected.
- Existing relay vector bytes and public v1 directory shape remain unchanged.
- Existing legacy TURN endpoint remains disabled by default.
- Legacy relay nodes remain manageable, but cannot receive access until an
  administrator confirms topology and a valid encrypted node-held secret exists.

## Testing

Tests cover the real request/approve/access API flow for both participants, spoofing,
anonymous and cross-tenant failures, exact deadline boundaries, topology aliases,
same-domain capacity fallback, repository rejection fallback, secret retry/conflict and
redaction, migration idempotency and malformed-schema rejection, and real PostgreSQL
concurrency. Existing Python focused and Rust golden-vector suites remain gates.
