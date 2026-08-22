from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from pydantic import SecretStr
from sqlalchemy import and_, case, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.relay_audit_event import RelayAuditEvent
from app.models.relay_enrollment import RelayEnrollment
from app.models.relay_node import RelayNode
from app.models.relay_node_registration import RelayNodeRegistration
from app.services.relay_node_auth import (
    IssuedRelayCertificate,
    issue_relay_certificate,
    validate_relay_csr,
)
from app.services.relay_repository import RelayRepositoryError, _validate_endpoints


_ENROLLMENT_CONTEXT = b"MRD_RELAY_ENROLLMENT_V1\x00"
_RECEIPT_CONTEXT = b"MRD_RELAY_RECEIPT_V1\x00"
_RECEIPT_DERIVE_CONTEXT = b"MRD_RELAY_RECEIPT_DERIVE_V1\x00"
_ENROLLMENT_REQUEST_CONTEXT = b"MRD_RELAY_ENROLLMENT_REQUEST_V1\x00"


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


class RelayRegistry:
    def __init__(
        self, session: AsyncSession, *, enrollment_token_pepper: str | SecretStr
    ) -> None:
        self._session = session
        if isinstance(enrollment_token_pepper, SecretStr):
            enrollment_token_pepper = enrollment_token_pepper.get_secret_value()
        try:
            pepper = bytes.fromhex(enrollment_token_pepper)
        except (TypeError, ValueError):
            pepper = b""
        self._pepper = pepper if len(pepper) >= 32 else b""

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
        receipt_ttl_seconds: int,
        now: datetime,
    ) -> RequestedRelayEnrollment:
        self._require_pepper()
        canonical_csr, signing_public_key = validate_relay_csr(csr_pem, node_id)
        canonical_endpoints = self._endpoints(endpoints, "relay_enrollment_invalid")
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
        if enrollment.used_at is not None:
            return await self._idempotent_enrollment_retry(
                enrollment=enrollment,
                token=token,
                request_digest=request_digest,
                now=now,
            )
        if self._as_utc(enrollment.expires_at) <= now:
            self._error("relay_enrollment_invalid", 400, "relay enrollment invalid")
        existing_node = await self._session.get(RelayNode, node_id)
        existing_registration = await self._session.get(RelayNodeRegistration, node_id)
        if existing_node is not None:
            if existing_node.state == "revoked":
                self._error("relay_node_revoked", 403, "relay node revoked")
        recoverable = self._registration_recoverable(
            existing_registration, existing_node, now
        )
        if existing_registration is not None and not recoverable:
            self._error("relay_enrollment_pending", 409, "relay enrollment pending")
        if existing_node is not None and existing_registration is None:
            self._error("relay_enrollment_pending", 409, "relay node already enrolled")
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
        registration.status = "pending"
        registration.request_digest = request_digest
        registration.receipt_digest = self._receipt_digest(receipt)
        registration.receipt_expires_at = receipt_expires_at
        registration.certificate_pem = None
        registration.ca_certificate_pem = None
        registration.certificate_expires_at = None
        registration.approved_at = None
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
        try:
            await self._session.flush()
        except IntegrityError:
            await self._session.rollback()
            concurrent_enrollment = await self._session.scalar(
                select(RelayEnrollment).where(
                    RelayEnrollment.token_digest == digest
                )
            )
            if concurrent_enrollment is not None:
                return await self._idempotent_enrollment_retry(
                    enrollment=concurrent_enrollment,
                    token=token,
                    request_digest=request_digest,
                    now=now,
                )
            self._error(
                "relay_enrollment_pending", 409, "relay enrollment already pending"
            )
        return RequestedRelayEnrollment(registration=registration, receipt=receipt)

    async def approve(
        self,
        *,
        node_id: str,
        actor_id: str,
        now: datetime,
    ) -> RelayNodeRegistration:
        registration = await self._session.scalar(
            select(RelayNodeRegistration)
            .where(RelayNodeRegistration.node_id == node_id)
            .with_for_update()
        )
        if registration is None or registration.status != "pending":
            self._error("relay_enrollment_pending", 409, "relay enrollment not pending")
        if (
            registration.receipt_expires_at is None
            or self._as_utc(registration.receipt_expires_at) <= now
        ):
            self._error("relay_enrollment_invalid", 409, "relay enrollment invalid")
        existing = await self._session.get(RelayNode, node_id)
        if existing is not None:
            if existing.state == "revoked":
                self._error("relay_node_revoked", 403, "relay node revoked")
        registration.status = "approved"
        registration.approved_at = now
        self._audit(
            action="relay_node_approved",
            node_id=node_id,
            actor_id=actor_id,
            details={},
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
        registration = await self._session.scalar(
            select(RelayNodeRegistration)
            .where(RelayNodeRegistration.enrollment_id == enrollment_id)
            .with_for_update()
        )
        if (
            registration is None
            or registration.receipt_digest is None
            or registration.receipt_expires_at is None
            or not hmac.compare_digest(registration.receipt_digest, digest)
            or self._as_utc(registration.receipt_expires_at) <= now
            or registration.status == "revoked"
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
            node = await self._session.get(RelayNode, registration.node_id)
            if node is not None and node.state == "revoked":
                self._error("relay_enrollment_invalid", 401, "relay enrollment invalid")
            if node is None:
                node = RelayNode(
                    node_id=registration.node_id,
                    encrypted_turn_secret=b"\x00",
                    created_at=now,
                )
                self._session.add(node)
            node.region = registration.region
            node.failure_domain = registration.failure_domain
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
            registration.ca_certificate_pem = certificate.ca_certificate_pem.encode()
            registration.certificate_expires_at = certificate.expires_at
            self._audit(
                action="relay_certificate_issued",
                node_id=registration.node_id,
                actor_id=None,
                details={"certificate_expires_at": certificate.expires_at.isoformat()},
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
        # Match administrator transition lock ordering (node, then
        # registration) so revoke and renewal cannot deadlock each other.
        node = await self._session.scalar(
            select(RelayNode)
            .where(RelayNode.node_id == identity.node_id)
            .with_for_update()
        )
        registration = await self._session.scalar(
            select(RelayNodeRegistration)
            .where(RelayNodeRegistration.node_id == identity.node_id)
            .with_for_update()
        )
        if registration is None or node is None:
            self._error("relay_certificate_invalid", 401, "relay certificate invalid")
        if node.state == "revoked" or registration.status == "revoked":
            self._error("relay_node_revoked", 403, "relay node revoked")
        record_until = (
            self._as_utc(registration.renewal_record_expires_at)
            if registration.renewal_record_expires_at is not None
            else None
        )
        if record_until is not None and record_until <= now:
            self._clear_renewal_record(registration)
            record_until = None
        if registration.renewal_request_id is not None and record_until is not None:
            if (
                registration.renewal_request_id == renewal_id
                and registration.renewal_csr_sha256 == csr_digest
                and registration.renewal_certificate_pem is not None
                and registration.renewal_certificate_expires_at is not None
                and self._as_utc(registration.renewal_certificate_expires_at) > now
            ):
                certificate = IssuedRelayCertificate(
                    certificate_pem=registration.renewal_certificate_pem.decode(),
                    ca_certificate_pem=(registration.ca_certificate_pem or b"").decode(),
                    fingerprint=node.certificate_fingerprint,
                    expires_at=self._as_utc(
                        registration.renewal_certificate_expires_at
                    ),
                )
                return ApprovedRelay(node=node, certificate=certificate)
            if registration.renewal_request_id == renewal_id or identity.is_previous:
                self._error("relay_renewal_conflict", 409, "relay renewal conflicts")
        if identity.is_previous:
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
        node.heartbeat_sequence = 0
        node.healthy_heartbeat_streak = 0
        node.state = "unavailable"
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
        active_allocations: int,
        current_egress_bps: int,
        endpoints: list[str],
        now: datetime,
    ) -> RelayNode:
        canonical_endpoints = self._endpoints(endpoints, "relay_metrics_invalid")
        node = await self._session.get(RelayNode, identity.node_id)
        if node is None:
            self._error("relay_certificate_invalid", 401, "relay certificate invalid")
        if node.state == "revoked":
            self._error("relay_node_revoked", 403, "relay node revoked")
        if active_allocations > node.max_allocations:
            self._error("relay_metrics_invalid", 400, "relay metrics invalid")
        lease_expires_at = now + timedelta(seconds=15)
        fresh_ready = and_(
            RelayNode.state.in_(("available", "degraded")),
            RelayNode.lease_expires_at.is_not(None),
            RelayNode.lease_expires_at > now,
        )
        next_streak = case(
            (RelayNode.state == "draining", RelayNode.healthy_heartbeat_streak),
            (fresh_ready, 3),
            (
                RelayNode.state == "unavailable",
                case(
                    (RelayNode.healthy_heartbeat_streak < 3,
                     RelayNode.healthy_heartbeat_streak + 1),
                    else_=3,
                ),
            ),
            else_=1,
        )
        result = await self._session.execute(
            update(RelayNode)
            .where(
                RelayNode.node_id == identity.node_id,
                RelayNode.certificate_fingerprint == identity.certificate_fingerprint,
                RelayNode.state != "revoked",
                RelayNode.heartbeat_sequence < sequence,
            )
            .values(
                heartbeat_sequence=sequence,
                active_allocations=active_allocations,
                current_egress_bps=current_egress_bps,
                endpoints=canonical_endpoints,
                lease_expires_at=lease_expires_at,
                updated_at=now,
                healthy_heartbeat_streak=next_streak,
                state=case(
                    (RelayNode.state == "draining", "draining"),
                    (fresh_ready, RelayNode.state),
                    (
                        and_(
                            RelayNode.state == "unavailable",
                            RelayNode.healthy_heartbeat_streak >= 2,
                        ),
                        "available",
                    ),
                    else_="unavailable",
                ),
            )
            .returning(RelayNode.node_id)
        )
        if result.scalar_one_or_none() is None:
            current = await self._session.scalar(
                select(RelayNode)
                .where(RelayNode.node_id == identity.node_id)
                .execution_options(populate_existing=True)
            )
            if current is not None and current.state == "revoked":
                self._error("relay_node_revoked", 403, "relay node revoked")
            self._error("relay_heartbeat_replayed", 409, "relay heartbeat replayed")
        self._audit(
            action="relay_heartbeat_recorded",
            node_id=identity.node_id,
            actor_id=None,
            details={"sequence": sequence},
            now=now,
        )
        await self._session.flush()
        refreshed = await self._session.get(RelayNode, identity.node_id)
        if refreshed is None:  # pragma: no cover - guarded by atomic update
            self._error("relay_certificate_invalid", 401, "relay certificate invalid")
        await self._session.refresh(refreshed)
        return refreshed

    async def list_nodes(self) -> list[RelayNode]:
        nodes = await self._session.scalars(
            select(RelayNode).order_by(RelayNode.node_id)
        )
        return list(nodes)

    async def transition(
        self, *, node_id: str, action: str, actor_id: str, now: datetime
    ) -> RelayNode:
        node = await self._session.scalar(
            select(RelayNode).where(RelayNode.node_id == node_id).with_for_update()
        )
        if node is None:
            self._error("relay_node_not_found", 404, "relay node not found")
        if node.state == "revoked":
            if action == "revoke":
                return node
            self._error("relay_node_revoked", 409, "relay node revoked")
        audit_action: str
        if action == "drain":
            node.state = "draining"
            audit_action = "relay_node_drained"
        elif action == "resume":
            node.state = "unavailable"
            node.healthy_heartbeat_streak = 0
            node.lease_expires_at = None
            audit_action = "relay_node_resumed"
        elif action == "revoke":
            node.state = "revoked"
            node.revoked_at = now
            node.lease_expires_at = now
            node.healthy_heartbeat_streak = 0
            registration = await self._session.get(RelayNodeRegistration, node_id)
            if registration is not None:
                registration.status = "revoked"
            audit_action = "relay_node_revoked"
        else:  # pragma: no cover - route constants only
            raise ValueError("unknown relay transition")
        node.updated_at = now
        self._audit(
            action=audit_action,
            node_id=node_id,
            actor_id=actor_id,
            details={},
            now=now,
        )
        await self._session.flush()
        return node

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
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

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
        )
        return hashlib.sha256(
            _ENROLLMENT_REQUEST_CONTEXT + cls._length_prefixed(fields)
        ).hexdigest()

    async def _idempotent_enrollment_retry(
        self,
        *,
        enrollment: RelayEnrollment,
        token: str,
        request_digest: str,
        now: datetime,
    ) -> RequestedRelayEnrollment:
        del now
        registration = await self._session.scalar(
            select(RelayNodeRegistration).where(
                RelayNodeRegistration.enrollment_id == enrollment.id
            )
        )
        if (
            registration is None
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
        for field in fields:
            if len(field) > 2**32 - 1:
                raise ValueError("relay enrollment field is too large")
            encoded.extend(len(field).to_bytes(4, "big"))
            encoded.extend(field)
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
    def _error(code: str, status_code: int, message: str) -> None:
        raise RelayRegistryError(code, status_code, message)
