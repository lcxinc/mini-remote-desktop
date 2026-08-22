from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import case, select, update
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


@dataclass(frozen=True)
class ApprovedRelay:
    node: RelayNode
    certificate: IssuedRelayCertificate


class RelayRegistry:
    def __init__(self, session: AsyncSession, *, enrollment_token_pepper: str) -> None:
        self._session = session
        try:
            pepper = bytes.fromhex(enrollment_token_pepper)
        except ValueError:
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
        now: datetime,
    ) -> RelayNodeRegistration:
        self._require_pepper()
        canonical_csr, signing_public_key = validate_relay_csr(csr_pem, node_id)
        canonical_endpoints = self._endpoints(endpoints, "relay_enrollment_invalid")
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
            self._error(
                "relay_enrollment_already_used", 409, "relay enrollment token already used"
            )
        if self._as_utc(enrollment.expires_at) <= now:
            self._error("relay_enrollment_invalid", 400, "relay enrollment invalid")
        existing_node = await self._session.get(RelayNode, node_id)
        if existing_node is not None:
            if existing_node.state == "revoked":
                self._error("relay_node_revoked", 403, "relay node revoked")
            self._error("relay_enrollment_pending", 409, "relay node already enrolled")
        existing_registration = await self._session.get(RelayNodeRegistration, node_id)
        if existing_registration is not None:
            self._error("relay_enrollment_pending", 409, "relay enrollment pending")

        registration = RelayNodeRegistration(
            node_id=node_id,
            enrollment_id=enrollment.id,
            region=region,
            failure_domain=failure_domain,
            endpoints=canonical_endpoints,
            max_allocations=max_allocations,
            max_egress_bps=max_egress_bps,
            csr_pem=canonical_csr,
            signing_public_key=signing_public_key,
            status="pending",
            created_at=now,
        )
        enrollment.used_at = now
        enrollment.enrolled_node_id = node_id
        self._session.add(registration)
        self._audit(
            action="relay_enrollment_requested",
            node_id=node_id,
            actor_id=None,
            details={"region": region, "failure_domain": failure_domain},
            now=now,
        )
        await self._flush_conflict(
            "relay_enrollment_pending", "relay enrollment already pending"
        )
        return registration

    async def approve(
        self,
        *,
        node_id: str,
        actor_id: str,
        ca_certificate_pem: str,
        ca_private_key_pem: str,
        validity_seconds: int,
        now: datetime,
    ) -> ApprovedRelay:
        registration = await self._session.scalar(
            select(RelayNodeRegistration)
            .where(RelayNodeRegistration.node_id == node_id)
            .with_for_update()
        )
        if registration is None or registration.status != "pending":
            self._error("relay_enrollment_pending", 409, "relay enrollment not pending")
        existing = await self._session.get(RelayNode, node_id)
        if existing is not None:
            if existing.state == "revoked":
                self._error("relay_node_revoked", 403, "relay node revoked")
            self._error("relay_enrollment_already_used", 409, "relay node already approved")

        certificate = issue_relay_certificate(
            csr_pem=registration.csr_pem,
            node_id=node_id,
            ca_certificate_pem=ca_certificate_pem,
            ca_private_key_pem=ca_private_key_pem,
            now=now,
            validity_seconds=validity_seconds,
        )
        node = RelayNode(
            node_id=node_id,
            region=registration.region,
            failure_domain=registration.failure_domain,
            state="unavailable",
            endpoints=registration.endpoints,
            certificate_fingerprint=certificate.fingerprint,
            # TURN credential material is provisioned by Task 5.  This marker is
            # neither a usable credential nor a hard-coded production secret.
            encrypted_turn_secret=b"\x00",
            max_allocations=registration.max_allocations,
            active_allocations=0,
            max_egress_bps=registration.max_egress_bps,
            current_egress_bps=0,
            heartbeat_sequence=0,
            created_at=now,
            updated_at=now,
        )
        registration.status = "approved"
        registration.approved_at = now
        registration.certificate_pem = certificate.certificate_pem.encode()
        registration.certificate_expires_at = certificate.expires_at
        self._session.add(node)
        self._audit(
            action="relay_node_approved",
            node_id=node_id,
            actor_id=actor_id,
            details={"certificate_expires_at": certificate.expires_at.isoformat()},
            now=now,
        )
        await self._flush_conflict(
            "relay_enrollment_already_used", "relay node already approved"
        )
        return ApprovedRelay(node=node, certificate=certificate)

    async def identity(
        self, *, node_id: str, certificate_fingerprint: str
    ) -> RelayIdentity:
        node = await self._session.get(RelayNode, node_id)
        registration = await self._session.get(RelayNodeRegistration, node_id)
        if node is not None and node.state == "revoked":
            self._error("relay_node_revoked", 403, "relay node revoked")
        if (
            node is None
            or registration is None
            or registration.status != "approved"
            or registration.certificate_expires_at is None
            or self._as_utc(registration.certificate_expires_at) <= datetime.now(UTC)
            or not hmac.compare_digest(
                node.certificate_fingerprint, certificate_fingerprint
            )
            or len(registration.signing_public_key) != 32
        ):
            self._error("relay_certificate_invalid", 401, "relay certificate invalid")
        return RelayIdentity(
            node_id=node.node_id,
            certificate_fingerprint=node.certificate_fingerprint,
            signing_public_key=registration.signing_public_key,
            state=node.state,
        )

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
                state=case(
                    (RelayNode.state == "unavailable", "available"),
                    else_=RelayNode.state,
                ),
            )
            .returning(RelayNode.node_id)
        )
        if result.scalar_one_or_none() is None:
            current = await self._session.get(RelayNode, identity.node_id)
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
            node.lease_expires_at = None
            audit_action = "relay_node_resumed"
        elif action == "revoke":
            node.state = "revoked"
            node.revoked_at = now
            node.lease_expires_at = now
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
