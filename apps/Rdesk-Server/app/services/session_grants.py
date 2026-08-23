from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Callable

from sqlalchemy import select

from app.models.device import Device
from app.models.session_request import SessionRequest
from app.models.user import User


_REGION = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TRANSPORTS = {"udp", "tcp", "tls"}


class SessionGrantError(Exception):
    def __init__(self, code: str, status_code: int, message: str) -> None:
        self.code = code
        self.status_code = status_code
        super().__init__(message)


@dataclass(frozen=True)
class SessionGrantPolicy:
    grant_ttl_seconds: int
    policy_ttl_seconds: int
    revision: int
    allowed_regions: tuple[str, ...]
    preferred_regions: tuple[str, ...]
    accepted_transports: tuple[str, ...]


class SessionGrantService:
    def __init__(
        self,
        session: object,
        *,
        policy: SessionGrantPolicy,
        signaling_url: str,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._session = session
        self._policy = policy
        self.signaling_url = signaling_url
        self._now = now or (lambda: datetime.now(UTC))

    async def request(
        self, *, current_user_id: str, target_device_id: str
    ) -> SessionRequest:
        requester = await self._session.scalar(
            select(User).where(User.id == current_user_id).with_for_update()
        )
        target = await self._session.scalar(
            select(Device).where(Device.id == target_device_id).with_for_update()
        )
        if requester is None or target is None or not target.is_bound:
            _deny()
        owner = await self._session.scalar(
            select(User).where(User.id == target.bound_user_id).with_for_update()
        )
        if (
            owner is None
            or owner.id == requester.id
            or not _valid_tenant(requester.tenant_id)
            or requester.tenant_id != owner.tenant_id
            or target.tenant_id != owner.tenant_id
        ):
            _deny()
        grant = SessionRequest(
            requester_user_id=requester.id,
            target_device_id=target.id,
            signaling_room="session-" + secrets.token_hex(24),
            tenant_id=requester.tenant_id,
            status="requested",
        )
        self._session.add(grant)
        await self._session.flush()
        return grant

    async def approve(
        self, *, session_id: str, current_user_id: str
    ) -> SessionRequest:
        validate_session_grant_policy(self._policy)
        grant = await self._session.scalar(
            select(SessionRequest)
            .where(SessionRequest.id == session_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if grant is None:
            _deny()
        target = await self._session.scalar(
            select(Device)
            .where(Device.id == grant.target_device_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if target is None or not target.is_bound:
            _deny()
        user_ids = {
            grant.requester_user_id,
            target.bound_user_id,
            current_user_id,
        }
        users = list(
            await self._session.scalars(
                select(User)
                .where(User.id.in_(user_ids))
                .order_by(User.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        )
        by_id = {user.id: user for user in users}
        requester = by_id.get(grant.requester_user_id)
        owner = by_id.get(target.bound_user_id)
        approver = by_id.get(current_user_id)
        if grant.status != "requested":
            raise SessionGrantError(
                "session_grant_conflict", 409, "session grant state conflicts"
            )
        if (
            requester is None
            or owner is None
            or approver is None
            or approver.id != owner.id
            or approver.id == requester.id
            or not _valid_tenant(grant.tenant_id)
            or grant.tenant_id != requester.tenant_id
            or owner.tenant_id != grant.tenant_id
            or target.tenant_id != grant.tenant_id
        ):
            _deny()
        now = _utc(self._now())
        grant.status = "approved"
        grant.grant_expires_at = now + timedelta(
            seconds=self._policy.grant_ttl_seconds
        )
        grant.policy_revision = self._policy.revision
        grant.policy_expires_at = now + timedelta(
            seconds=self._policy.policy_ttl_seconds
        )
        grant.intended_peer_id = target.id
        grant.relay_allowed_regions = list(self._policy.allowed_regions)
        grant.relay_preferred_regions = list(self._policy.preferred_regions)
        grant.relay_accepted_transports = list(self._policy.accepted_transports)
        await self._session.flush()
        return grant


def configured_session_grant_policy(configuration: object) -> SessionGrantPolicy:
    allowed = _csv(getattr(configuration, "relay_allowed_regions", ""), region=True)
    preferred = _csv(
        getattr(configuration, "relay_preferred_regions", ""), region=True
    )
    if not preferred:
        preferred = allowed
    accepted = _csv(
        getattr(configuration, "relay_accepted_transports", ""), region=False
    )
    return SessionGrantPolicy(
        grant_ttl_seconds=getattr(configuration, "session_grant_ttl_seconds", 0),
        policy_ttl_seconds=getattr(configuration, "relay_policy_ttl_seconds", 0),
        revision=getattr(configuration, "relay_policy_revision", 0),
        allowed_regions=allowed,
        preferred_regions=preferred,
        accepted_transports=accepted,
    )


def _csv(value: object, *, region: bool) -> tuple[str, ...]:
    if not isinstance(value, str):
        return ()
    values = tuple(
        dict.fromkeys(item.strip() for item in value.split(",") if item.strip())
    )
    if not 1 <= len(values) <= 8:
        return ()
    if region:
        return values if all(_REGION.fullmatch(item) for item in values) else ()
    return values if all(item in _TRANSPORTS for item in values) else ()


def validate_session_grant_policy(policy: SessionGrantPolicy) -> None:
    valid = (
        isinstance(policy.grant_ttl_seconds, int)
        and not isinstance(policy.grant_ttl_seconds, bool)
        and 1 <= policy.grant_ttl_seconds <= 3600
        and isinstance(policy.policy_ttl_seconds, int)
        and not isinstance(policy.policy_ttl_seconds, bool)
        and 1 <= policy.policy_ttl_seconds <= policy.grant_ttl_seconds
        and isinstance(policy.revision, int)
        and not isinstance(policy.revision, bool)
        and 1 <= policy.revision <= 2**63 - 1
        and 1 <= len(policy.allowed_regions) <= 8
        and 1 <= len(policy.preferred_regions) <= 8
        and all(region in policy.allowed_regions for region in policy.preferred_regions)
        and 1 <= len(policy.accepted_transports) <= 3
    )
    if not valid:
        raise SessionGrantError(
            "session_policy_unavailable", 503, "session policy unavailable"
        )


def _valid_tenant(value: object) -> bool:
    return isinstance(value, str) and _TENANT.fullmatch(value) is not None


def _deny() -> None:
    raise SessionGrantError("session_grant_denied", 403, "session grant denied")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
