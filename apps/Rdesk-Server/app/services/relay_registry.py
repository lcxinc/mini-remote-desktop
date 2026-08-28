from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
import secrets
import threading
from collections.abc import Iterable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import AsyncIterator, NoReturn

from pydantic import SecretStr
from sqlalchemy import event, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.mutable_base64url import (
    decode_canonical_base64url,
    encode_unpadded_base64url,
    zeroize,
)

from app.models.relay_audit_event import RelayAuditEvent
from app.models.relay_enrollment import RelayEnrollment
from app.models.relay_node import RelayNode
from app.models.relay_node_registration import RelayNodeRegistration
from app.services.relay_node_auth import (
    IssuedRelayCertificate,
    issue_relay_certificate,
    validate_relay_csr,
)
from app.services.relay_repository import (
    RelayRepositoryError,
    RelaySecretCipher,
    RelaySecretCipherError,
    _validate_endpoints,
    _turn_secret_has_minimum_quality,
)


_ENROLLMENT_CONTEXT = b"MRD_RELAY_ENROLLMENT_V1\x00"
_RECEIPT_CONTEXT = b"MRD_RELAY_RECEIPT_V1\x00"
_RECEIPT_DERIVE_CONTEXT = b"MRD_RELAY_RECEIPT_DERIVE_V1\x00"
_ENROLLMENT_REQUEST_CONTEXT = b"MRD_RELAY_ENROLLMENT_REQUEST_V1\x00"
_ROTATION_PROOF_CONTEXT = b"MRD_RELAY_ROTATION_PROOF_V1\x00"
_TOPOLOGY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_NODE_IDENTITY_LOCK_CONTEXT = b"MRD_RELAY_NODE_IDENTITY_LOCK_V1\x00"
_LOCAL_NODE_LOCKS = tuple(threading.Lock() for _ in range(256))
_LOCAL_NODE_LOCKS_INFO = "relay_registry_local_node_locks"
_LOCAL_NODE_LOCK_LISTENER_INFO = "relay_registry_local_node_lock_listener"


def rotation_proof_message(
    *,
    node_id: str,
    identity_epoch: int,
    rotation_id: str,
    secret_version: int,
    rotation_challenge: str,
    pending_secret_digest: bytes,
    probe_evidence_sha256: bytes,
) -> bytes:
    if (
        _TOPOLOGY_ID.fullmatch(node_id) is None
        or not 1 <= identity_epoch <= 2**63 - 1
        or _TOPOLOGY_ID.fullmatch(rotation_id) is None
        or not 2 <= secret_version <= 2**63 - 1
        or len(rotation_challenge) != 43
        or re.fullmatch(r"[A-Za-z0-9_-]{43}", rotation_challenge) is None
        or len(pending_secret_digest) != 32
        or len(probe_evidence_sha256) != 32
    ):
        raise ValueError("relay rotation proof fields are invalid")
    try:
        decoded_challenge = decode_canonical_base64url(
            rotation_challenge, expected_length=32
        )
    except ValueError:
        raise ValueError("relay rotation proof fields are invalid") from None
    finally:
        if "decoded_challenge" in locals():
            zeroize(decoded_challenge)
    fields = (
        node_id.encode("ascii"),
        str(identity_epoch).encode("ascii"),
        rotation_id.encode("ascii"),
        str(secret_version).encode("ascii"),
        rotation_challenge.encode("ascii"),
        pending_secret_digest,
        probe_evidence_sha256,
    )
    return _ROTATION_PROOF_CONTEXT + b"".join(
        len(field).to_bytes(4, "big") + field for field in fields
    )


class RelayRegistryError(Exception):
    def __init__(self, code: str, status_code: int, message: str) -> None:
        self.code = code
        self.status_code = status_code
        super().__init__(message)


@dataclass(frozen=True)
class RelayIdentity:
    node_id: str
    certificate_fingerprint: str
    signing_public_key: bytes
    state: str
    is_previous: bool = False


@dataclass(frozen=True)
class ApprovedRelay:
    node: RelayNode
    certificate: IssuedRelayCertificate


@dataclass(frozen=True)
class RequestedRelayEnrollment:
    registration: RelayNodeRegistration
    receipt: str = field(repr=False)


@dataclass(frozen=True)
class RelayEnrollmentPickup:
    enrollment_id: str
    node_id: str
    status: str
    certificate_pem: str | None
    ca_certificate_pem: str | None
    expires_at: datetime | None


@dataclass(frozen=True)
class RevokedRelay:
    node_id: str
    state: str


@dataclass(frozen=True)
class RelayRotationStatus:
    node_id: str
    identity_epoch: int
    active_secret_version: int
    status: str


def relay_rotation_in_flight(node: RelayNode) -> bool:
    """Return whether the locked node has any live rotation transaction state."""

    return (
        node.desired_secret_version > node.active_secret_version
        or node.pending_secret_version is not None
        or node.pending_encrypted_turn_secret is not None
        or node.pending_secret_digest is not None
        or node.pending_rotation_id is not None
        or node.pending_secret_uploaded_at is not None
        or node.rotation_challenge is not None
        or node.secret_not_before is not None
        or node.old_credential_deadline is not None
    )


def relay_effective_draining(node: RelayNode) -> bool:
    """Combine durable administrator intent with transient rotation safety."""

    return node.desired_draining or relay_rotation_in_flight(node)


class RelayRegistry:
    def __init__(
        self,
        session: AsyncSession,
        *,
        enrollment_token_pepper: str | SecretStr,
        turn_secret_cipher: RelaySecretCipher | None = None,
    ) -> None:
        self._session = session
        if isinstance(enrollment_token_pepper, SecretStr):
            enrollment_token_pepper = enrollment_token_pepper.get_secret_value()
        try:
            pepper = bytes.fromhex(enrollment_token_pepper)
        except (TypeError, ValueError):
            pepper = b""
        self._pepper = pepper if len(pepper) >= 32 else b""
        self._turn_secret_cipher = turn_secret_cipher

    async def issue_enrollment_token(
        self, *, ttl_seconds: int, actor_id: str, now: datetime
    ) -> tuple[str, datetime]:
        self._require_pepper()
        token = secrets.token_urlsafe(32)
        expires_at = now + timedelta(seconds=ttl_seconds)
        enrollment = RelayEnrollment(
            token_digest=self._token_digest(token),
            expires_at=expires_at,
            created_at=now,
        )
        self._session.add(enrollment)
        self._audit(
            action="relay_enrollment_token_issued",
            node_id=None,
            actor_id=actor_id,
            details={"expires_at": expires_at.isoformat()},
            now=now,
        )
        await self._flush_conflict(
            "relay_enrollment_invalid", "could not issue relay enrollment token"
        )
        return token, expires_at

    async def request_enrollment(
        self,
        *,
        token: str,
        node_id: str,
        region: str,
        failure_domain: str,
        endpoints: list[str],
        max_allocations: int,
        max_egress_bps: int,
        csr_pem: str,
        turn_rest_secret: SecretStr,
        receipt_ttl_seconds: int,
        now: datetime,
    ) -> RequestedRelayEnrollment:
        self._require_pepper()
        canonical_csr, signing_public_key = validate_relay_csr(csr_pem, node_id)
        canonical_endpoints = self._endpoints(endpoints, "relay_enrollment_invalid")
        secret_digest, encrypted_turn_secret = self._protect_turn_secret(
            turn_rest_secret, node_id=node_id
        )
        if not 60 <= receipt_ttl_seconds <= 7 * 86_400:
            self._error(
                "relay_enrollment_invalid", 503, "relay enrollment is not configured"
            )
        request_digest = self._enrollment_request_digest(
            node_id=node_id,
            region=region,
            failure_domain=failure_domain,
            endpoints=canonical_endpoints,
            max_allocations=max_allocations,
            max_egress_bps=max_egress_bps,
            canonical_csr=canonical_csr,
            turn_secret_digest=secret_digest,
        )
        digest = self._token_digest(token)
        enrollment = await self._session.scalar(
            select(RelayEnrollment)
            .where(RelayEnrollment.token_digest == digest)
            .with_for_update()
        )
        if enrollment is None or not hmac.compare_digest(
            enrollment.token_digest, digest
        ):
            self._error("relay_enrollment_invalid", 400, "relay enrollment invalid")
        async with self._node_identity_lock(node_id):
            existing_node, existing_registration = (
                await self._locked_node_and_registration(node_id)
            )
            # SQLite ignores SELECT FOR UPDATE. Re-read after the process lock
            # so a same-token waiter observes the winner's committed one-use
            # state and can return the deterministic receipt.
            await self._session.refresh(enrollment)
            if (
                existing_registration is not None
                and existing_registration.status == "revoked"
            ) or (existing_node is not None and existing_node.state == "revoked"):
                self._error("relay_node_revoked", 403, "relay node revoked")
            if enrollment.used_at is not None:
                return self._idempotent_enrollment_retry(
                    enrollment=enrollment,
                    registration=existing_registration,
                    token=token,
                    request_digest=request_digest,
                )
            if self._as_utc(enrollment.expires_at) <= now:
                self._error("relay_enrollment_invalid", 400, "relay enrollment invalid")
            recoverable = self._registration_recoverable(
                existing_registration, existing_node, now
            )
            if existing_registration is not None and not recoverable:
                self._error("relay_enrollment_pending", 409, "relay enrollment pending")
            if existing_node is not None and existing_registration is None:
                self._error(
                    "relay_enrollment_pending", 409, "relay node already enrolled"
                )
            if existing_node is not None and recoverable:
                existing_node.state = "unavailable"
                existing_node.healthy_heartbeat_streak = 0
                existing_node.lease_expires_at = None
                existing_node.updated_at = now

            receipt = self._derive_receipt(token, enrollment.id, request_digest)
            receipt_expires_at = now + timedelta(seconds=receipt_ttl_seconds)
            if existing_registration is None:
                registration = RelayNodeRegistration(node_id=node_id)
                self._session.add(registration)
                audit_action = "relay_enrollment_requested"
            else:
                registration = existing_registration
                audit_action = "relay_enrollment_reissued"
            registration.enrollment_id = enrollment.id
            registration.region = region
            registration.failure_domain = failure_domain
            registration.endpoints = canonical_endpoints
            registration.max_allocations = max_allocations
            registration.max_egress_bps = max_egress_bps
            registration.csr_pem = canonical_csr
            registration.signing_public_key = signing_public_key
            registration.encrypted_turn_secret = encrypted_turn_secret
            registration.status = "pending"
            registration.request_digest = request_digest
            registration.receipt_digest = self._receipt_digest(receipt)
            registration.receipt_expires_at = receipt_expires_at
            registration.certificate_pem = None
            registration.ca_certificate_pem = None
            registration.certificate_expires_at = None
            registration.approved_at = None
            registration.physical_host_id = None
            registration.topology_approved_at = None
            registration.previous_certificate_fingerprint = None
            registration.previous_signing_public_key = None
            registration.previous_auth_expires_at = None
            registration.previous_certificate_expires_at = None
            registration.renewal_request_id = None
            registration.renewal_csr_sha256 = None
            registration.renewal_certificate_pem = None
            registration.renewal_certificate_expires_at = None
            registration.renewal_record_expires_at = None
            registration.created_at = now
            enrollment.used_at = now
            enrollment.enrolled_node_id = node_id
            self._audit(
                action=audit_action,
                node_id=node_id,
                actor_id=None,
                details={"region": region, "failure_domain": failure_domain},
                now=now,
            )
            await self._session.flush()
            return RequestedRelayEnrollment(
                registration=registration, receipt=receipt
            )

    async def approve(
        self,
        *,
        node_id: str,
        actor_id: str,
        failure_domain: str,
        physical_host_id: str,
        now: datetime,
    ) -> RelayNodeRegistration:
        if (
            _TOPOLOGY_ID.fullmatch(failure_domain) is None
            or _TOPOLOGY_ID.fullmatch(physical_host_id) is None
        ):
            self._error("relay_topology_invalid", 400, "relay topology invalid")
        async with self._node_identity_lock(node_id):
            existing, registration = await self._locked_node_and_registration(node_id)
            if registration is not None and registration.status == "revoked":
                self._error("relay_node_revoked", 403, "relay node revoked")
            if existing is not None and existing.state == "revoked":
                self._error("relay_node_revoked", 403, "relay node revoked")
            if registration is None or registration.status != "pending":
                self._error(
                    "relay_enrollment_pending", 409, "relay enrollment not pending"
                )
            if (
                registration.receipt_expires_at is None
                or self._as_utc(registration.receipt_expires_at) <= now
            ):
                self._error("relay_enrollment_invalid", 409, "relay enrollment invalid")
            registration.status = "approved"
            registration.failure_domain = failure_domain
            registration.physical_host_id = physical_host_id
            registration.topology_approved_at = now
            registration.approved_at = now
            self._audit(
                action="relay_node_approved",
                node_id=node_id,
                actor_id=actor_id,
                details={
                    "failure_domain": failure_domain,
                    "physical_host_id": physical_host_id,
                },
                now=now,
            )
            await self._session.flush()
            return registration

    async def identity(
        self,
        *,
        node_id: str,
        certificate_fingerprint: str,
        allow_previous: bool = False,
        now: datetime | None = None,
    ) -> RelayIdentity:
        now = now or datetime.now(UTC)
        node = await self._session.get(RelayNode, node_id)
        registration = await self._session.get(RelayNodeRegistration, node_id)
        if (
            node is None
            or registration is None
            or registration.status not in {"approved", "revoked"}
        ):
            self._error("relay_certificate_invalid", 401, "relay certificate invalid")
        if hmac.compare_digest(node.certificate_fingerprint, certificate_fingerprint):
            if (
                registration.certificate_expires_at is None
                or self._as_utc(registration.certificate_expires_at) <= now
            ):
                self._error(
                    "relay_certificate_invalid", 401, "relay certificate invalid"
                )
            signing_public_key = registration.signing_public_key
            is_previous = False
        elif (
            allow_previous
            and registration.previous_certificate_fingerprint is not None
            and registration.previous_signing_public_key is not None
            and registration.previous_certificate_expires_at is not None
            and self._as_utc(registration.previous_certificate_expires_at) > now
            and hmac.compare_digest(
                registration.previous_certificate_fingerprint,
                certificate_fingerprint,
            )
        ):
            signing_public_key = registration.previous_signing_public_key
            is_previous = True
        else:
            self._error("relay_certificate_invalid", 401, "relay certificate invalid")
        if len(signing_public_key) != 32:
            self._error("relay_certificate_invalid", 401, "relay certificate invalid")
        return RelayIdentity(
            node_id=node.node_id,
            certificate_fingerprint=certificate_fingerprint,
            signing_public_key=signing_public_key,
            state=node.state,
            is_previous=is_previous,
        )

    async def pickup_enrollment(
        self,
        *,
        enrollment_id: str,
        receipt: str,
        ca_certificate_pem: str,
        ca_private_key_pem: str | SecretStr,
        ca_private_key_password: str | SecretStr,
        validity_seconds: int,
        now: datetime,
    ) -> RelayEnrollmentPickup:
        self._require_pepper()
        digest = self._receipt_digest(receipt)
        node_id = await self._session.scalar(
            select(RelayNodeRegistration.node_id).where(
                RelayNodeRegistration.enrollment_id == enrollment_id
            )
        )
        if node_id is None:
            self._error("relay_enrollment_invalid", 401, "relay enrollment invalid")
        async with self._node_identity_lock(node_id):
            node, registration = await self._locked_node_and_registration(node_id)
            if (
                registration is None
                or registration.enrollment_id != enrollment_id
                or registration.receipt_digest is None
                or registration.receipt_expires_at is None
                or not hmac.compare_digest(registration.receipt_digest, digest)
                or self._as_utc(registration.receipt_expires_at) <= now
                or registration.status == "revoked"
                or (node is not None and node.state == "revoked")
            ):
                self._error("relay_enrollment_invalid", 401, "relay enrollment invalid")
            if registration.status == "pending":
                return RelayEnrollmentPickup(
                    enrollment_id=enrollment_id,
                    node_id=registration.node_id,
                    status="pending",
                    certificate_pem=None,
                    ca_certificate_pem=None,
                    expires_at=None,
                )
            if registration.status != "approved":
                self._error("relay_enrollment_invalid", 401, "relay enrollment invalid")
            if (
                registration.topology_approved_at is None
                or registration.physical_host_id is None
                or registration.encrypted_turn_secret is None
            ):
                self._error("relay_enrollment_invalid", 409, "relay enrollment invalid")
            if registration.certificate_pem is None:
                certificate = issue_relay_certificate(
                    csr_pem=registration.csr_pem,
                    node_id=registration.node_id,
                    ca_certificate_pem=ca_certificate_pem,
                    ca_private_key_pem=ca_private_key_pem,
                    ca_private_key_password=ca_private_key_password,
                    now=now,
                    validity_seconds=validity_seconds,
                )
                if node is None:
                    node = RelayNode(
                        node_id=registration.node_id,
                        encrypted_turn_secret=bytes(
                            registration.encrypted_turn_secret
                        ),
                        created_at=now,
                    )
                    self._session.add(node)
                node.region = registration.region
                node.failure_domain = registration.failure_domain
                node.physical_host_id = registration.physical_host_id
                node.encrypted_turn_secret = bytes(registration.encrypted_turn_secret)
                node.state = "unavailable"
                node.endpoints = registration.endpoints
                node.certificate_fingerprint = certificate.fingerprint
                node.max_allocations = registration.max_allocations
                node.active_allocations = 0
                node.max_egress_bps = registration.max_egress_bps
                node.current_egress_bps = 0
                node.heartbeat_sequence = 0
                node.healthy_heartbeat_streak = 0
                node.lease_expires_at = None
                node.revoked_at = None
                node.updated_at = now
                registration.certificate_pem = certificate.certificate_pem.encode()
                registration.ca_certificate_pem = (
                    certificate.ca_certificate_pem.encode()
                )
                registration.certificate_expires_at = certificate.expires_at
                self._audit(
                    action="relay_certificate_issued",
                    node_id=registration.node_id,
                    actor_id=None,
                    details={
                        "certificate_expires_at": certificate.expires_at.isoformat()
                    },
                    now=now,
                )
                await self._session.flush()
            if (
                registration.certificate_pem is None
                or registration.ca_certificate_pem is None
                or registration.certificate_expires_at is None
                or self._as_utc(registration.certificate_expires_at) <= now
            ):
                self._error("relay_enrollment_invalid", 401, "relay enrollment invalid")
            self._audit(
                action="relay_certificate_picked_up",
                node_id=registration.node_id,
                actor_id=None,
                details={},
                now=now,
            )
            await self._session.flush()
            return RelayEnrollmentPickup(
                enrollment_id=enrollment_id,
                node_id=registration.node_id,
                status="approved",
                certificate_pem=registration.certificate_pem.decode(),
                ca_certificate_pem=registration.ca_certificate_pem.decode(),
                expires_at=self._as_utc(registration.certificate_expires_at),
            )

    async def renew(
        self,
        *,
        identity: RelayIdentity,
        sequence: int,
        renewal_id: str,
        csr_pem: str,
        ca_certificate_pem: str,
        ca_private_key_pem: str | SecretStr,
        ca_private_key_password: str | SecretStr,
        validity_seconds: int,
        renew_before_seconds: int,
        previous_auth_grace_seconds: int,
        renewal_record_retention_seconds: int,
        now: datetime,
    ) -> ApprovedRelay:
        canonical_csr, signing_public_key = validate_relay_csr(
            csr_pem, identity.node_id
        )
        csr_digest = hashlib.sha256(canonical_csr).hexdigest()
        async with self._node_identity_lock(identity.node_id):
            node, registration = await self._locked_node_and_registration(
                identity.node_id
            )
            identity_kind = self._locked_identity_kind(
                identity=identity,
                node=node,
                registration=registration,
                allow_previous=True,
                now=now,
            )
            locked_identity = RelayIdentity(
                node_id=identity.node_id,
                certificate_fingerprint=identity.certificate_fingerprint,
                signing_public_key=identity.signing_public_key,
                state=node.state if node is not None else identity.state,
                is_previous=identity_kind == "previous",
            )
            return await self._renew_locked(
                identity=locked_identity,
                sequence=sequence,
                renewal_id=renewal_id,
                canonical_csr=canonical_csr,
                signing_public_key=signing_public_key,
                csr_digest=csr_digest,
                ca_certificate_pem=ca_certificate_pem,
                ca_private_key_pem=ca_private_key_pem,
                ca_private_key_password=ca_private_key_password,
                validity_seconds=validity_seconds,
                renew_before_seconds=renew_before_seconds,
                previous_auth_grace_seconds=previous_auth_grace_seconds,
                renewal_record_retention_seconds=renewal_record_retention_seconds,
                now=now,
                node=node,
                registration=registration,
            )

    async def _renew_locked(
        self,
        *,
        identity: RelayIdentity,
        sequence: int,
        renewal_id: str,
        canonical_csr: bytes,
        signing_public_key: bytes,
        csr_digest: str,
        ca_certificate_pem: str,
        ca_private_key_pem: str | SecretStr,
        ca_private_key_password: str | SecretStr,
        validity_seconds: int,
        renew_before_seconds: int,
        previous_auth_grace_seconds: int,
        renewal_record_retention_seconds: int,
        now: datetime,
        node: RelayNode | None,
        registration: RelayNodeRegistration | None,
    ) -> ApprovedRelay:
        if registration is None or node is None:
            self._error("relay_certificate_invalid", 401, "relay certificate invalid")
        if node.state == "revoked" or registration.status == "revoked":
            self._error("relay_node_revoked", 403, "relay node revoked")
        previous_sequence = node.previous_identity_sequence or 0
        last_sequence = previous_sequence if identity.is_previous else node.heartbeat_sequence
        if not 1 <= sequence <= 2**63 - 1 or sequence <= last_sequence:
            self._error("relay_heartbeat_replayed", 409, "relay heartbeat replayed")
        if identity.is_previous and (
            registration.previous_certificate_expires_at is None
            or self._as_utc(registration.previous_certificate_expires_at) <= now
        ):
            self._error("relay_renewal_conflict", 409, "relay renewal conflicts")
        rotation_in_flight = relay_rotation_in_flight(node)
        # Only the previous certificate can prove a lost-response retry.  A
        # current-certificate replay means the caller already received the new
        # certificate; advancing its shared sequence here could invalidate an
        # in-flight secret-rotation mutation.
        if rotation_in_flight and not identity.is_previous:
            self._error("relay_renewal_conflict", 409, "relay renewal conflicts")
        record_until = (
            self._as_utc(registration.renewal_record_expires_at)
            if registration.renewal_record_expires_at is not None
            else None
        )
        existing_renewal_id = registration.renewal_request_id
        if existing_renewal_id is not None:
            complete_record = (
                registration.renewal_csr_sha256 is not None
                and registration.renewal_certificate_pem is not None
                and registration.renewal_certificate_expires_at is not None
                and registration.ca_certificate_pem is not None
                and record_until is not None
            )
            if not complete_record:
                self._error("relay_renewal_conflict", 409, "relay renewal conflicts")
            assert record_until is not None
            if record_until <= now:
                self._clear_renewal_record(registration)
                if existing_renewal_id == renewal_id or identity.is_previous:
                    self._error("relay_renewal_conflict", 409, "relay renewal conflicts")
                record_until = None
        if existing_renewal_id is not None and record_until is not None:
            if (
                existing_renewal_id == renewal_id
                and registration.renewal_csr_sha256 == csr_digest
                and registration.renewal_certificate_pem is not None
                and registration.renewal_certificate_expires_at is not None
                and self._as_utc(registration.renewal_certificate_expires_at) > now
            ):
                if not identity.is_previous:
                    self._error(
                        "relay_renewal_conflict", 409, "relay renewal conflicts"
                    )
                assert registration.ca_certificate_pem is not None
                certificate = IssuedRelayCertificate(
                    certificate_pem=registration.renewal_certificate_pem.decode(),
                    ca_certificate_pem=registration.ca_certificate_pem.decode(),
                    fingerprint=node.certificate_fingerprint,
                    expires_at=self._as_utc(
                        registration.renewal_certificate_expires_at
                    ),
                )
                node.previous_identity_sequence = sequence
                await self._session.flush()
                return ApprovedRelay(node=node, certificate=certificate)
            if existing_renewal_id == renewal_id or identity.is_previous:
                self._error("relay_renewal_conflict", 409, "relay renewal conflicts")
        if identity.is_previous:
            self._error("relay_renewal_conflict", 409, "relay renewal conflicts")
        # A new certificate epoch must never consume an in-flight TURN secret
        # transition.  The row was selected under the node identity lock, so
        # these values are the authoritative state for this renewal attempt.
        # The exact previous-certificate retry above is safe: it only advances
        # the separate previous replay watermark and leaves rotation intact.
        if rotation_in_flight:
            self._error("relay_renewal_conflict", 409, "relay renewal conflicts")
        if not hmac.compare_digest(
            node.certificate_fingerprint, identity.certificate_fingerprint
        ):
            self._error("relay_certificate_invalid", 401, "relay certificate invalid")
        current_expiry = registration.certificate_expires_at
        if (
            current_expiry is None
            or self._as_utc(current_expiry) <= now
            or not 300 <= renew_before_seconds <= 86_400
            or self._as_utc(current_expiry) - now > timedelta(seconds=renew_before_seconds)
            or not 30 <= previous_auth_grace_seconds <= 3600
            or not 300 <= renewal_record_retention_seconds <= 7 * 86_400
        ):
            self._error("relay_renewal_conflict", 409, "relay renewal unavailable")
        certificate = issue_relay_certificate(
            csr_pem=canonical_csr,
            node_id=identity.node_id,
            ca_certificate_pem=ca_certificate_pem,
            ca_private_key_pem=ca_private_key_pem,
            ca_private_key_password=ca_private_key_password,
            now=now,
            validity_seconds=validity_seconds,
        )
        previous_certificate_expires_at = self._as_utc(current_expiry)
        registration.previous_certificate_fingerprint = node.certificate_fingerprint
        registration.previous_signing_public_key = registration.signing_public_key
        registration.previous_auth_expires_at = min(
            now + timedelta(seconds=previous_auth_grace_seconds),
            previous_certificate_expires_at,
        )
        registration.previous_certificate_expires_at = (
            previous_certificate_expires_at
        )
        registration.csr_pem = canonical_csr
        registration.signing_public_key = signing_public_key
        registration.certificate_pem = certificate.certificate_pem.encode()
        registration.ca_certificate_pem = certificate.ca_certificate_pem.encode()
        registration.certificate_expires_at = certificate.expires_at
        registration.renewal_request_id = renewal_id
        registration.renewal_csr_sha256 = csr_digest
        registration.renewal_certificate_pem = certificate.certificate_pem.encode()
        registration.renewal_certificate_expires_at = certificate.expires_at
        registration.renewal_record_expires_at = max(
            now + timedelta(seconds=renewal_record_retention_seconds),
            previous_certificate_expires_at,
        )
        node.certificate_fingerprint = certificate.fingerprint
        node.identity_epoch += 1
        node.previous_identity_sequence = sequence
        node.heartbeat_sequence = 0
        # Rotation state is scoped to the certificate identity epoch and was
        # rejected above.  Administrator drain is durable desired state, so it
        # remains authoritative across the new epoch.
        preserve_admin_drain = node.desired_draining
        node.desired_draining = preserve_admin_drain
        node.desired_secret_version = node.active_secret_version
        node.secret_not_before = None
        node.old_credential_deadline = None
        node.pending_secret_version = None
        node.pending_encrypted_turn_secret = None
        node.pending_secret_digest = None
        node.pending_rotation_id = None
        node.pending_secret_uploaded_at = None
        node.rotation_challenge = None
        node.committed_rotation_id = None
        node.committed_identity_epoch = None
        node.committed_rotation_challenge = None
        node.committed_probe_evidence_sha256 = None
        node.committed_proof_mac = None
        node.healthy_heartbeat_streak = 0
        node.state = "draining" if preserve_admin_drain else "unavailable"
        node.lease_expires_at = None
        node.updated_at = now
        self._audit(
            action="relay_certificate_renewed",
            node_id=node.node_id,
            actor_id=None,
            details={"certificate_expires_at": certificate.expires_at.isoformat()},
            now=now,
        )
        await self._session.flush()
        return ApprovedRelay(node=node, certificate=certificate)

    async def record_heartbeat(
        self,
        *,
        identity: RelayIdentity,
        sequence: int,
        identity_epoch: int,
        boot_id: str,
        nonce: str,
        process_health: str,
        listener_health: str,
        probe_health: str,
        active_allocations: int,
        current_ingress_bps: int,
        current_egress_bps: int,
        max_allocations: int,
        max_egress_bps: int,
        packet_loss_bps: int,
        cpu_usage_bps: int,
        memory_usage_bps: int,
        applied_secret_version: int,
        measured_rtt_ms: int | None = None,
        recent_failure_bps: int = 0,
        endpoints: list[str],
        now: datetime,
    ) -> RelayNode:
        canonical_endpoints = self._endpoints(endpoints, "relay_metrics_invalid")
        invalid_selection_metrics = (
            measured_rtt_ms is not None
            and (
                type(measured_rtt_ms) is not int
                or not 0 <= measured_rtt_ms <= 2**32 - 1
            )
        ) or (
            type(recent_failure_bps) is not int
            or not 0 <= recent_failure_bps <= 10_000
        )
        health_values_valid = (
            process_health in {"healthy", "degraded", "failed"}
            and listener_health in {"healthy", "degraded", "failed"}
            and probe_health in {"healthy", "failed", "non_evidence"}
        )
        async with self._node_identity_lock(identity.node_id):
            node, registration = await self._locked_node_and_registration(
                identity.node_id
            )
            self._locked_identity_kind(
                identity=identity,
                node=node,
                registration=registration,
                allow_previous=False,
                now=now,
            )
            assert node is not None
            if sequence <= node.heartbeat_sequence:
                self._error(
                    "relay_heartbeat_replayed", 409, "relay heartbeat replayed"
                )
            if (
                identity_epoch != node.identity_epoch
                or active_allocations > node.max_allocations
                or max_allocations != node.max_allocations
                or max_egress_bps != node.max_egress_bps
                or applied_secret_version != node.applied_secret_version
                or not health_values_valid
                or invalid_selection_metrics
            ):
                self._error("relay_metrics_invalid", 400, "relay metrics invalid")
            heartbeat_healthy = (
                process_health == "healthy"
                and listener_health == "healthy"
                and probe_health == "healthy"
            )
            fresh_ready = (
                node.state in {"available", "degraded"}
                and node.lease_expires_at is not None
                and self._as_utc(node.lease_expires_at) > now
            )
            if heartbeat_healthy:
                lease_expires_at = now + timedelta(seconds=15)
                if relay_effective_draining(node) or node.state == "draining":
                    next_streak = node.healthy_heartbeat_streak
                    next_state = "draining"
                elif fresh_ready:
                    next_streak = 3
                    next_state = node.state
                elif node.state == "unavailable":
                    next_streak = min(node.healthy_heartbeat_streak + 1, 3)
                    next_state = (
                        "available"
                        if node.healthy_heartbeat_streak >= 2
                        else "unavailable"
                    )
                else:
                    next_streak = 1
                    next_state = "unavailable"
            else:
                lease_expires_at = now
                next_streak = 0
                next_state = "unavailable"

            node.heartbeat_sequence = sequence
            node.active_allocations = active_allocations
            node.current_ingress_bps = current_ingress_bps
            node.current_egress_bps = current_egress_bps
            node.last_boot_id = boot_id
            node.last_heartbeat_nonce = nonce
            node.process_health = process_health
            node.listener_health = listener_health
            node.probe_health = probe_health
            node.packet_loss_bps = packet_loss_bps
            node.cpu_usage_bps = cpu_usage_bps
            node.memory_usage_bps = memory_usage_bps
            node.measured_rtt_ms = measured_rtt_ms
            node.recent_failure_bps = recent_failure_bps
            node.endpoints = canonical_endpoints
            node.lease_expires_at = lease_expires_at
            node.updated_at = now
            node.healthy_heartbeat_streak = next_streak
            node.state = next_state
            self._audit(
                action="relay_heartbeat_recorded",
                node_id=identity.node_id,
                actor_id=None,
                details={"sequence": sequence},
                now=now,
            )
            await self._session.flush()
            return node

    async def list_nodes(self) -> list[RelayNode]:
        nodes = await self._session.scalars(
            select(RelayNode).order_by(RelayNode.node_id)
        )
        return list(nodes)

    async def request_secret_rotation(
        self,
        *,
        node_id: str,
        actor_id: str,
        credential_ttl_seconds: int,
        now: datetime,
    ) -> RelayNode:
        if not 60 <= credential_ttl_seconds <= 3600:
            self._error("relay_secret_rotation_invalid", 400, "relay secret rotation invalid")
        async with self._node_identity_lock(node_id):
            node, _ = await self._locked_node_and_registration(node_id)
            if node is None:
                self._error("relay_node_not_found", 404, "relay node not found")
            if node.state == "revoked":
                self._error("relay_node_revoked", 409, "relay node revoked")
            if relay_rotation_in_flight(node):
                return node
            node.desired_secret_version = node.active_secret_version + 1
            node.secret_not_before = now
            node.old_credential_deadline = now + timedelta(
                seconds=credential_ttl_seconds
            )
            node.pending_secret_version = None
            node.pending_encrypted_turn_secret = None
            node.pending_secret_digest = None
            node.pending_rotation_id = None
            node.pending_secret_uploaded_at = None
            node.rotation_challenge = secrets.token_urlsafe(32)
            node.committed_rotation_id = None
            node.committed_identity_epoch = None
            node.committed_rotation_challenge = None
            node.committed_probe_evidence_sha256 = None
            node.committed_proof_mac = None
            node.state = "draining"
            node.lease_expires_at = now
            node.healthy_heartbeat_streak = 0
            node.updated_at = now
            self._audit(
                action="relay_secret_rotation_requested",
                node_id=node_id,
                actor_id=actor_id,
                details={"secret_version": node.desired_secret_version},
                now=now,
            )
            await self._session.flush()
            return node

    async def upload_secret_rotation(
        self,
        *,
        identity: RelayIdentity,
        sequence: int,
        identity_epoch: int,
        rotation_id: str,
        secret_version: int,
        turn_rest_secret: SecretStr,
        now: datetime,
    ) -> RelayNode:
        secret_digest, encrypted_secret = self._protect_turn_secret(
            turn_rest_secret, node_id=identity.node_id
        )
        async with self._node_identity_lock(identity.node_id):
            node, registration = await self._locked_node_and_registration(
                identity.node_id
            )
            identity_kind = self._locked_identity_kind(
                identity=identity,
                node=node,
                registration=registration,
                allow_previous=True,
                now=now,
            )
            assert node is not None
            if identity_kind == "previous":
                self._error(
                    "relay_identity_epoch_invalid", 409, "relay identity epoch invalid"
                )
            if identity_epoch != node.identity_epoch:
                self._error("relay_identity_epoch_invalid", 409, "relay identity epoch invalid")
            if sequence <= node.heartbeat_sequence:
                self._error("relay_heartbeat_replayed", 409, "relay heartbeat replayed")
            if (
                not relay_rotation_in_flight(node)
                or secret_version != node.desired_secret_version
                or secret_version <= node.active_secret_version
                or node.rotation_challenge is None
            ):
                self._error("relay_secret_rotation_invalid", 409, "relay secret rotation invalid")
            if node.pending_secret_version is not None:
                if (
                    node.pending_secret_version != secret_version
                    or node.pending_rotation_id != rotation_id
                    or node.pending_secret_digest is None
                    or not hmac.compare_digest(node.pending_secret_digest, secret_digest)
                ):
                    self._error(
                        "relay_secret_rotation_conflict",
                        409,
                        "relay secret rotation conflict",
                    )
            else:
                node.pending_secret_version = secret_version
                node.pending_encrypted_turn_secret = encrypted_secret
                node.pending_secret_digest = secret_digest
                node.pending_rotation_id = rotation_id
                node.pending_secret_uploaded_at = now
                self._audit(
                    action="relay_secret_rotation_uploaded",
                    node_id=identity.node_id,
                    actor_id=None,
                    details={"secret_version": secret_version},
                    now=now,
                )
            node.heartbeat_sequence = sequence
            node.updated_at = now
            await self._session.flush()
            return node

    async def commit_secret_rotation(
        self,
        *,
        identity: RelayIdentity,
        sequence: int,
        identity_epoch: int,
        rotation_id: str,
        secret_version: int,
        rotation_challenge: str,
        probe_evidence_sha256: str,
        proof_mac: str,
        now: datetime,
    ) -> RelayNode:
        if re.fullmatch(r"[0-9a-f]{64}", probe_evidence_sha256) is None:
            self._error("relay_probe_invalid", 400, "relay allocation probe invalid")
        if re.fullmatch(r"[0-9a-f]{64}", proof_mac) is None:
            self._error("relay_rotation_proof_invalid", 400, "relay rotation proof invalid")
        try:
            evidence = bytes.fromhex(probe_evidence_sha256)
            supplied_proof = bytes.fromhex(proof_mac)
        except ValueError:
            self._error("relay_rotation_proof_invalid", 400, "relay rotation proof invalid")
        async with self._node_identity_lock(identity.node_id):
            node, registration = await self._locked_node_and_registration(
                identity.node_id
            )
            identity_kind = self._locked_identity_kind(
                identity=identity,
                node=node,
                registration=registration,
                allow_previous=True,
                now=now,
            )
            assert node is not None
            if identity_kind == "previous":
                self._error(
                    "relay_identity_epoch_invalid", 409, "relay identity epoch invalid"
                )
            if identity_epoch != node.identity_epoch:
                self._error("relay_identity_epoch_invalid", 409, "relay identity epoch invalid")
            if sequence <= node.heartbeat_sequence:
                self._error("relay_heartbeat_replayed", 409, "relay heartbeat replayed")
            # A lost commit response is retried with a fresh signed request
            # sequence but the same persisted rotation id. Acknowledge only
            # the exact already-active transaction and never audit twice.
            if (
                node.active_secret_version == secret_version
                and node.applied_secret_version == secret_version
                and node.committed_rotation_id == rotation_id
                and node.committed_identity_epoch == identity_epoch
                and node.committed_rotation_challenge == rotation_challenge
                and node.committed_probe_evidence_sha256 is not None
                and hmac.compare_digest(node.committed_probe_evidence_sha256, evidence)
                and node.committed_proof_mac is not None
                and hmac.compare_digest(node.committed_proof_mac, supplied_proof)
                and node.pending_secret_version is None
                and node.pending_encrypted_turn_secret is None
            ):
                node.heartbeat_sequence = sequence
                node.updated_at = now
                await self._session.flush()
                return node
            deadline = (
                self._as_utc(node.old_credential_deadline)
                if node.old_credential_deadline is not None
                else None
            )
            if (
                not relay_rotation_in_flight(node)
                or node.active_allocations != 0
                or deadline is None
                or now < deadline
                or node.pending_secret_version != secret_version
                or node.pending_rotation_id != rotation_id
                or node.pending_encrypted_turn_secret is None
                or node.pending_secret_digest is None
                or secret_version != node.desired_secret_version
                or node.rotation_challenge != rotation_challenge
            ):
                self._error("relay_secret_rotation_unsafe", 409, "relay secret rotation unsafe")
            cipher = self._turn_secret_cipher
            if cipher is None:
                self._error("relay_access_unavailable", 503, "relay access unavailable")
            try:
                canonical_secret = cipher.decrypt_mutable(
                    bytes(node.pending_encrypted_turn_secret),
                    associated_data=identity.node_id.encode("utf-8"),
                )
            except RelaySecretCipherError:
                self._error("relay_rotation_proof_invalid", 409, "relay rotation proof invalid")
            try:
                try:
                    decoded_secret = decode_canonical_base64url(
                        memoryview(canonical_secret), expected_length=32
                    )
                except ValueError:
                    self._error(
                        "relay_rotation_proof_invalid", 409, "relay rotation proof invalid"
                    )
                try:
                    pending_digest = hashlib.sha256(decoded_secret).digest()
                finally:
                    zeroize(decoded_secret)
                if not hmac.compare_digest(pending_digest, node.pending_secret_digest):
                    self._error(
                        "relay_rotation_proof_invalid", 409, "relay rotation proof invalid"
                    )
                try:
                    proof_message = rotation_proof_message(
                        node_id=identity.node_id,
                        identity_epoch=identity_epoch,
                        rotation_id=rotation_id,
                        secret_version=secret_version,
                        rotation_challenge=rotation_challenge,
                        pending_secret_digest=pending_digest,
                        probe_evidence_sha256=evidence,
                    )
                except ValueError:
                    self._error(
                        "relay_rotation_proof_invalid", 409, "relay rotation proof invalid"
                    )
                expected_proof = hmac.new(
                    canonical_secret, proof_message, hashlib.sha256
                ).digest()
                if not hmac.compare_digest(expected_proof, supplied_proof):
                    self._error(
                        "relay_rotation_proof_invalid", 409, "relay rotation proof invalid"
                    )
            finally:
                for index in range(len(canonical_secret)):
                    canonical_secret[index] = 0
            node.encrypted_turn_secret = bytes(node.pending_encrypted_turn_secret)
            node.active_secret_version = secret_version
            node.applied_secret_version = secret_version
            node.pending_secret_version = None
            node.pending_encrypted_turn_secret = None
            node.pending_secret_digest = None
            node.pending_rotation_id = None
            node.pending_secret_uploaded_at = None
            node.committed_rotation_id = rotation_id
            node.committed_identity_epoch = identity_epoch
            node.committed_rotation_challenge = rotation_challenge
            node.committed_probe_evidence_sha256 = evidence
            node.committed_proof_mac = supplied_proof
            node.rotation_challenge = None
            node.secret_not_before = None
            node.old_credential_deadline = None
            node.state = "draining" if node.desired_draining else "unavailable"
            node.lease_expires_at = None
            node.healthy_heartbeat_streak = 0
            node.heartbeat_sequence = sequence
            node.updated_at = now
            self._audit(
                action="relay_secret_rotation_committed",
                node_id=identity.node_id,
                actor_id=None,
                details={"secret_version": secret_version},
                now=now,
            )
            await self._session.flush()
            return node

    async def secret_rotation_status(
        self,
        *,
        identity: RelayIdentity,
        sequence: int,
        identity_epoch: int,
        rotation_id: str,
        secret_version: int,
        rotation_challenge: str,
        probe_evidence_sha256: str,
        proof_mac: str,
        now: datetime,
    ) -> RelayRotationStatus:
        if (
            re.fullmatch(r"[0-9a-f]{64}", probe_evidence_sha256) is None
            or re.fullmatch(r"[0-9a-f]{64}", proof_mac) is None
        ):
            self._error("relay_rotation_proof_invalid", 400, "relay rotation proof invalid")
        try:
            evidence = bytes.fromhex(probe_evidence_sha256)
            supplied_proof = bytes.fromhex(proof_mac)
        except ValueError:
            self._error("relay_rotation_proof_invalid", 400, "relay rotation proof invalid")
        async with self._node_identity_lock(identity.node_id):
            node, registration = await self._locked_node_and_registration(
                identity.node_id
            )
            self._locked_identity_kind(
                identity=identity,
                node=node,
                registration=registration,
                allow_previous=False,
                now=now,
            )
            assert node is not None
            if sequence <= node.heartbeat_sequence:
                self._error(
                    "relay_heartbeat_replayed", 409, "relay heartbeat replayed"
                )
            committed_exact = (
                node.active_secret_version == secret_version
                and node.applied_secret_version == secret_version
                and node.committed_rotation_id == rotation_id
                and node.committed_identity_epoch == identity_epoch
                and node.committed_rotation_challenge == rotation_challenge
                and node.committed_probe_evidence_sha256 is not None
                and hmac.compare_digest(node.committed_probe_evidence_sha256, evidence)
                and node.committed_proof_mac is not None
                and hmac.compare_digest(node.committed_proof_mac, supplied_proof)
                and node.pending_secret_version is None
                and node.pending_encrypted_turn_secret is None
            )
            pending = (
                node.identity_epoch == identity_epoch
                and node.pending_rotation_id == rotation_id
                and node.pending_secret_version == secret_version
                and node.desired_secret_version == secret_version
                and node.rotation_challenge == rotation_challenge
                and node.pending_encrypted_turn_secret is not None
                and node.pending_secret_digest is not None
            )
            status = (
                "committed_exact"
                if committed_exact
                else "pending"
                if pending
                else "unknown"
            )
            node.heartbeat_sequence = sequence
            await self._session.flush()
            return RelayRotationStatus(
                node_id=node.node_id,
                identity_epoch=node.identity_epoch,
                active_secret_version=node.active_secret_version,
                status=status,
            )

    async def transition(
        self, *, node_id: str, action: str, actor_id: str, now: datetime
    ) -> RelayNode:
        async with self._node_identity_lock(node_id):
            node, _ = await self._locked_node_and_registration(node_id)
            if node is None:
                self._error("relay_node_not_found", 404, "relay node not found")
            if node.state == "revoked":
                self._error("relay_node_revoked", 409, "relay node revoked")
            audit_action: str
            should_audit: bool
            if action == "drain":
                should_audit = not node.desired_draining
                node.desired_draining = True
                node.state = "draining"
                audit_action = "relay_node_drained"
            elif action == "resume":
                if relay_rotation_in_flight(node):
                    self._error(
                        "relay_secret_rotation_conflict",
                        409,
                        "relay secret rotation conflict",
                    )
                if node.desired_draining and node.active_allocations > 0:
                    self._error(
                        "relay_node_drain_in_progress",
                        409,
                        "relay node drain in progress",
                    )
                should_audit = node.desired_draining or node.state == "draining"
                node.desired_draining = False
                node.state = "unavailable"
                node.healthy_heartbeat_streak = 0
                node.lease_expires_at = None
                audit_action = "relay_node_resumed"
            else:  # pragma: no cover - route constants only
                raise ValueError("unknown relay transition")
            node.updated_at = now
            if should_audit:
                self._audit(
                    action=audit_action,
                    node_id=node_id,
                    actor_id=actor_id,
                    details={},
                    now=now,
                )
            await self._session.flush()
            return node

    async def revoke(
        self, *, node_id: str, actor_id: str, now: datetime
    ) -> RevokedRelay:
        async with self._node_identity_lock(node_id):
            node, registration = await self._locked_node_and_registration(node_id)
            if node is None and registration is None:
                self._error("relay_node_not_found", 404, "relay node not found")
            already_revoked = (
                node is not None and node.state == "revoked"
            ) or (
                registration is not None and registration.status == "revoked"
            )
            if node is not None:
                node.state = "revoked"
                node.revoked_at = node.revoked_at or now
                node.lease_expires_at = now
                node.healthy_heartbeat_streak = 0
                node.updated_at = now
            if registration is not None:
                registration.status = "revoked"
            if not already_revoked:
                self._audit(
                    action="relay_node_revoked",
                    node_id=node_id,
                    actor_id=actor_id,
                    details={},
                    now=now,
                )
            await self._session.flush()
            return RevokedRelay(node_id=node_id, state="revoked")

    @asynccontextmanager
    async def _node_identity_lock(self, node_id: str) -> AsyncIterator[None]:
        key_digest = hashlib.sha256(
            _NODE_IDENTITY_LOCK_CONTEXT + node_id.encode("utf-8")
        ).digest()
        if self._dialect_name() == "postgresql":
            lock_key = int.from_bytes(key_digest[:8], "big", signed=True)
            await self._session.execute(
                text("SELECT pg_advisory_xact_lock(:lock_key)"),
                {"lock_key": lock_key},
            )
            yield
            return
        # SQLite has no cross-row/advisory lock. Its supported deployment is a
        # single process, so a fixed lock stripe serializes node identities
        # without an attacker-controlled, unbounded lock map.
        sync_session = getattr(self._session, "sync_session", None)
        if sync_session is None:
            sync_session = getattr(self._session, "session", None)
        if sync_session is None:  # pragma: no cover - invalid session adapter
            raise RuntimeError("relay registry requires a SQLAlchemy session")
        stripe = key_digest[0]
        held_locks = sync_session.info.setdefault(_LOCAL_NODE_LOCKS_INFO, {})
        if stripe in held_locks:
            yield
            return
        lock = _LOCAL_NODE_LOCKS[stripe]
        acquire_task = asyncio.create_task(asyncio.to_thread(lock.acquire))
        try:
            await asyncio.shield(acquire_task)
        except BaseException:
            await acquire_task
            lock.release()
            raise
        held_locks[stripe] = lock
        if not sync_session.info.get(_LOCAL_NODE_LOCK_LISTENER_INFO):
            event.listen(
                sync_session,
                "after_transaction_end",
                self._release_local_node_locks,
            )
            sync_session.info[_LOCAL_NODE_LOCK_LISTENER_INFO] = True
        yield

    @staticmethod
    def _release_local_node_locks(session: object, transaction: object) -> None:
        if getattr(transaction, "parent", None) is not None:
            return
        info = getattr(session, "info", {})
        held_locks = info.pop(_LOCAL_NODE_LOCKS_INFO, {})
        for lock in held_locks.values():
            lock.release()

    def _dialect_name(self) -> str:
        session = self._session
        get_bind = getattr(session, "get_bind", None)
        if get_bind is None:
            session = getattr(session, "session", session)
            get_bind = getattr(session, "get_bind", None)
        if get_bind is None:  # pragma: no cover - invalid session adapter
            return "unknown"
        bind = get_bind()
        return str(bind.dialect.name)

    async def _locked_node_and_registration(
        self, node_id: str
    ) -> tuple[RelayNode | None, RelayNodeRegistration | None]:
        node = await self._session.scalar(
            select(RelayNode)
            .where(RelayNode.node_id == node_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        registration = await self._session.scalar(
            select(RelayNodeRegistration)
            .where(RelayNodeRegistration.node_id == node_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        return node, registration

    def _locked_identity_kind(
        self,
        *,
        identity: RelayIdentity,
        node: RelayNode | None,
        registration: RelayNodeRegistration | None,
        allow_previous: bool,
        now: datetime,
    ) -> str:
        """Reclassify preliminary authentication from freshly locked rows."""

        if node is None or registration is None or registration.status not in {
            "approved",
            "revoked",
        }:
            self._error("relay_certificate_invalid", 401, "relay certificate invalid")
        current_matches = (
            hmac.compare_digest(
                node.certificate_fingerprint, identity.certificate_fingerprint
            )
            and hmac.compare_digest(
                registration.signing_public_key, identity.signing_public_key
            )
            and registration.certificate_expires_at is not None
            and self._as_utc(registration.certificate_expires_at) > now
        )
        previous_matches = (
            allow_previous
            and registration.previous_certificate_fingerprint is not None
            and registration.previous_signing_public_key is not None
            and registration.previous_certificate_expires_at is not None
            and self._as_utc(registration.previous_certificate_expires_at) > now
            and hmac.compare_digest(
                registration.previous_certificate_fingerprint,
                identity.certificate_fingerprint,
            )
            and hmac.compare_digest(
                registration.previous_signing_public_key,
                identity.signing_public_key,
            )
        )
        if not current_matches and not previous_matches:
            self._error("relay_certificate_invalid", 401, "relay certificate invalid")
        if node.state == "revoked" or registration.status == "revoked":
            self._error("relay_node_revoked", 403, "relay node revoked")
        return "current" if current_matches else "previous"

    def _token_digest(self, token: str) -> str:
        if not isinstance(token, str) or not 20 <= len(token) <= 512 or not token.isascii():
            self._error("relay_enrollment_invalid", 400, "relay enrollment invalid")
        return hmac.new(
            self._pepper, _ENROLLMENT_CONTEXT + token.encode("ascii"), hashlib.sha256
        ).hexdigest()

    def _receipt_digest(self, receipt: str) -> str:
        if (
            not isinstance(receipt, str)
            or not 20 <= len(receipt) <= 512
            or not receipt.isascii()
        ):
            self._error("relay_enrollment_invalid", 401, "relay enrollment invalid")
        return hmac.new(
            self._pepper, _RECEIPT_CONTEXT + receipt.encode("ascii"), hashlib.sha256
        ).hexdigest()

    def _protect_turn_secret(
        self, value: SecretStr, *, node_id: str
    ) -> tuple[bytes, bytes]:
        cipher = self._turn_secret_cipher
        if cipher is None or not isinstance(value, SecretStr):
            self._error(
                "relay_access_unavailable", 503, "relay access unavailable"
            )
        encoded = value.get_secret_value()
        if (
            len(encoded) != 43
            or not encoded.isascii()
            or re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded) is None
        ):
            self._error("relay_enrollment_invalid", 400, "relay enrollment invalid")
        canonical: bytearray | None = None
        try:
            try:
                decoded = decode_canonical_base64url(encoded, expected_length=32)
            except ValueError:
                self._error("relay_enrollment_invalid", 400, "relay enrollment invalid")
            if not _turn_secret_has_minimum_quality(decoded):
                self._error(
                    "relay_enrollment_invalid", 400, "relay enrollment invalid"
                )
            digest = hashlib.sha256(decoded).digest()
            # Preserve the canonical configured value as coturn's actual HMAC
            # key. The decoded bytes are used only for quality validation and
            # the stable enrollment request digest.
            canonical = encode_unpadded_base64url(memoryview(decoded))
            try:
                # AESGCM requires immutable plaintext.  That library-owned copy
                # is beyond this boundary; ``canonical`` remains controllable.
                encrypted = cipher.encrypt(
                    bytes(canonical), associated_data=node_id.encode("utf-8")
                )
            finally:
                zeroize(canonical)
            return digest, encrypted
        finally:
            if "decoded" in locals():
                zeroize(decoded)

    def _derive_receipt(
        self, token: str, enrollment_id: str, request_digest: str
    ) -> str:
        material = self._length_prefixed(
            (enrollment_id.encode("ascii"), bytes.fromhex(request_digest))
        )
        digest = hmac.new(
            token.encode("ascii"),
            _RECEIPT_DERIVE_CONTEXT + material,
            hashlib.sha256,
        ).digest()
        encoded = encode_unpadded_base64url(memoryview(digest))
        try:
            # Pydantic/HTTP response fields are immutable strings; the mutable
            # encoding owner is cleared immediately after crossing that API.
            return encoded.decode("ascii")
        finally:
            zeroize(encoded)

    @classmethod
    def _enrollment_request_digest(
        cls,
        *,
        node_id: str,
        region: str,
        failure_domain: str,
        endpoints: list[str],
        max_allocations: int,
        max_egress_bps: int,
        canonical_csr: bytes,
        turn_secret_digest: bytes,
    ) -> str:
        fields = (
            node_id.encode("utf-8"),
            region.encode("utf-8"),
            failure_domain.encode("utf-8"),
            len(endpoints).to_bytes(4, "big"),
            *(endpoint.encode("ascii") for endpoint in endpoints),
            max_allocations.to_bytes(8, "big"),
            max_egress_bps.to_bytes(8, "big"),
            canonical_csr,
            turn_secret_digest,
        )
        return hashlib.sha256(
            _ENROLLMENT_REQUEST_CONTEXT + cls._length_prefixed(fields)
        ).hexdigest()

    def _idempotent_enrollment_retry(
        self,
        *,
        enrollment: RelayEnrollment,
        registration: RelayNodeRegistration | None,
        token: str,
        request_digest: str,
    ) -> RequestedRelayEnrollment:
        if (
            registration is None
            or registration.enrollment_id != enrollment.id
            or registration.request_digest is None
            or not hmac.compare_digest(registration.request_digest, request_digest)
        ):
            self._error(
                "relay_enrollment_already_used",
                409,
                "relay enrollment already used",
            )
        receipt = self._derive_receipt(token, enrollment.id, request_digest)
        if (
            registration.receipt_digest is None
            or not hmac.compare_digest(
                registration.receipt_digest, self._receipt_digest(receipt)
            )
        ):
            self._error(
                "relay_enrollment_already_used",
                409,
                "relay enrollment already used",
            )
        return RequestedRelayEnrollment(registration=registration, receipt=receipt)

    @classmethod
    def _registration_recoverable(
        cls,
        registration: RelayNodeRegistration | None,
        node: RelayNode | None,
        now: datetime,
    ) -> bool:
        if registration is None:
            return False
        if registration.status == "revoked" or (
            node is not None and node.state == "revoked"
        ):
            return False
        certificate_is_valid = (
            registration.certificate_pem is not None
            and registration.certificate_expires_at is not None
            and cls._as_utc(registration.certificate_expires_at) > now
        )
        if certificate_is_valid:
            return False
        certificate_is_expired = (
            registration.certificate_expires_at is not None
            and cls._as_utc(registration.certificate_expires_at) <= now
        )
        receipt_is_expired = (
            registration.receipt_expires_at is None
            or cls._as_utc(registration.receipt_expires_at) <= now
        )
        return certificate_is_expired or receipt_is_expired

    @staticmethod
    def _clear_renewal_record(registration: RelayNodeRegistration) -> None:
        registration.renewal_request_id = None
        registration.renewal_csr_sha256 = None
        registration.renewal_certificate_pem = None
        registration.renewal_certificate_expires_at = None
        registration.renewal_record_expires_at = None

    @staticmethod
    def _length_prefixed(fields: Iterable[bytes]) -> bytes:
        encoded = bytearray()
        for field_bytes in fields:
            if len(field_bytes) > 2**32 - 1:
                raise ValueError("relay enrollment field is too large")
            encoded.extend(len(field_bytes).to_bytes(4, "big"))
            encoded.extend(field_bytes)
        return bytes(encoded)

    def _require_pepper(self) -> None:
        if not self._pepper:
            self._error(
                "relay_enrollment_invalid", 503, "relay enrollment is not configured"
            )

    @staticmethod
    def _endpoints(endpoints: list[str], code: str) -> list[str]:
        try:
            return _validate_endpoints(endpoints)
        except RelayRepositoryError:
            raise RelayRegistryError(code, 400, "relay endpoint metrics invalid") from None

    def _audit(
        self,
        *,
        action: str,
        node_id: str | None,
        actor_id: str | None,
        details: dict[str, object],
        now: datetime,
    ) -> None:
        self._session.add(
            RelayAuditEvent(
                action=action,
                node_id=node_id,
                actor_id=actor_id,
                details=details,
                created_at=now,
            )
        )

    async def _flush_conflict(self, code: str, message: str) -> None:
        try:
            await self._session.flush()
        except IntegrityError:
            await self._session.rollback()
            self._error(code, 409, message)

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @staticmethod
    def _error(code: str, status_code: int, message: str) -> NoReturn:
        raise RelayRegistryError(code, status_code, message)
