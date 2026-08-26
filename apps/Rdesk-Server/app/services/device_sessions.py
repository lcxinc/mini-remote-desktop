from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Callable

from pydantic import ValidationError
from sqlalchemy import select, update

from app.core.security import DeviceAuthSnapshot
from app.models.device import Device
from app.models.relay_audit_event import RelayAuditEvent
from app.models.relay_reservation import RelayReservation
from app.models.session_request import SessionRequest
from app.models.user import User
from app.schemas.session import (
    DeviceSessionApprovalIn,
    DeviceSessionCanonicalRequest,
    DeviceSessionCreateIn,
    DeviceSessionOut,
)
from app.services.relay_directory import RelayAccessService
from app.services.session_grants import (
    SessionGrantError,
    bind_session_grant_policy,
    session_grant_identity_lock,
    validate_session_grant_policy,
)


_REQUEST_COMMITMENT_CONTEXT = b"MRD_WAN_SESSION_REQUEST_V3\x00"


class DeviceSessionError(Exception):
    def __init__(self, code: str, status_code: int, message: str) -> None:
        self.code = code
        self.status_code = status_code
        super().__init__(message)


class DeviceSessionService:
    def __init__(
        self,
        session: object,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._session = session
        self._now = now or (lambda: datetime.now(UTC))

    async def create(
        self,
        *,
        current_device: Device,
        payload: DeviceSessionCreateIn,
    ) -> SessionRequest:
        if not _is_active_device(current_device):
            _deny()
        canonical = canonical_wan_request(payload, current_device=current_device)
        normalized = canonical.model_dump(mode="json")
        commitment = wan_request_commitment(canonical)
        async with session_grant_identity_lock(
            self._session, "session:" + canonical.session_id
        ):
            existing = await self._session.scalar(
                select(SessionRequest)
                .where(SessionRequest.id == canonical.session_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if existing is not None:
                if not await self._is_exact_retry(
                    existing,
                    current_device=current_device,
                    normalized=normalized,
                    commitment=commitment,
                ):
                    _conflict()
                return existing

            target_preview = await self._session.scalar(
                select(Device).where(Device.device_id == canonical.target_device_id)
            )
            if target_preview is None:
                _deny()
            device_ids = sorted({current_device.id, target_preview.id})
            devices = list(
                await self._session.scalars(
                    select(Device)
                    .where(Device.id.in_(device_ids))
                    .order_by(Device.id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
            )
            by_id = {device.id: device for device in devices}
            requester = by_id.get(current_device.id)
            target = by_id.get(target_preview.id)
            if (
                requester is None
                or target is None
                or requester.id == target.id
                or requester.device_id != canonical.controller_device_id
                or target.device_id != canonical.target_device_id
                or not requester.is_bound
                or not target.is_bound
                or requester.bound_user_id is None
                or target.bound_user_id is None
                or requester.auth_revoked_at is not None
                or target.auth_revoked_at is not None
                or not _valid_tenant(requester.tenant_id)
                or requester.tenant_id != target.tenant_id
            ):
                _deny()

            user_ids = sorted({requester.bound_user_id, target.bound_user_id})
            users = list(
                await self._session.scalars(
                    select(User)
                    .where(User.id.in_(user_ids))
                    .order_by(User.id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
            )
            by_user_id = {user.id: user for user in users}
            requester_user = by_user_id.get(requester.bound_user_id)
            target_user = by_user_id.get(target.bound_user_id)
            if (
                requester_user is None
                or target_user is None
                or requester_user.tenant_id != requester.tenant_id
                or target_user.tenant_id != target.tenant_id
            ):
                _deny()

            row = SessionRequest(
                id=canonical.session_id,
                requester_user_id=requester_user.id,
                requester_device_id=requester.id,
                target_device_id=target.id,
                signaling_room=canonical.session_id,
                tenant_id=requester.tenant_id,
                status="requested",
                request_payload=normalized,
                request_commitment=commitment,
                access_mode=canonical.access_mode,
                route_policy=canonical.route_policy,
                requested_scopes=list(canonical.requested_scopes),
                requested_profile=(
                    canonical.requested_profile.model_dump(mode="json")
                    if canonical.requested_profile is not None
                    else None
                ),
            )
            self._session.add(row)
            await self._session.flush()
            self._audit(
                action="wan_session_requested",
                row=row,
                actor_device_id=requester.id,
            )
            await self._session.flush()
            return row

    async def inspect(
        self, *, session_id: str, current_device: Device
    ) -> SessionRequest:
        row = await self._session.scalar(
            select(SessionRequest).where(SessionRequest.id == session_id)
        )
        if row is None or not _is_authorized_participant(row, current_device):
            _not_found()
        return row

    async def approve(
        self,
        *,
        session_id: str,
        current_device: Device,
        auth_snapshot: DeviceAuthSnapshot,
        payload: DeviceSessionApprovalIn,
        relay_access: RelayAccessService,
    ) -> SessionRequest:
        try:
            validate_session_grant_policy(relay_access.current_policy)
        except SessionGrantError as error:
            raise DeviceSessionError(
                error.code, error.status_code, str(error)
            ) from None
        async with session_grant_identity_lock(self._session, "session:" + session_id):
            preview = await self._session.scalar(
                select(SessionRequest).where(SessionRequest.id == session_id)
            )
            if preview is None or preview.requester_device_id is None:
                _not_found()
            devices = list(
                await self._session.scalars(
                    select(Device)
                    .where(
                        Device.id.in_(
                            {
                                preview.requester_device_id,
                                preview.target_device_id,
                                auth_snapshot.row_id,
                            }
                        )
                    )
                    .order_by(Device.id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
            )
            by_device_id = {device.id: device for device in devices}
            controller = by_device_id.get(preview.requester_device_id)
            target = by_device_id.get(preview.target_device_id)
            caller = by_device_id.get(auth_snapshot.row_id)
            user_ids = sorted(
                {
                    user_id
                    for user_id in (
                        preview.requester_user_id,
                        getattr(controller, "bound_user_id", None),
                        getattr(target, "bound_user_id", None),
                        getattr(caller, "bound_user_id", None),
                    )
                    if isinstance(user_id, str)
                }
            )
            users = list(
                await self._session.scalars(
                    select(User)
                    .where(User.id.in_(user_ids))
                    .order_by(User.id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
            )
            users_by_id = {user.id: user for user in users}
            row = await self._session.scalar(
                select(SessionRequest)
                .where(SessionRequest.id == session_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if (
                row is None
                or row.requester_device_id != getattr(controller, "id", None)
                or row.target_device_id != getattr(target, "id", None)
                or caller is None
                or current_device.id != auth_snapshot.row_id
                or not _matches_auth_snapshot(caller, auth_snapshot)
                or not _is_authorized_participant(row, caller)
                or controller is None
                or target is None
                or not _is_active_device(controller)
                or not _is_active_device(target)
                or controller.bound_user_id != row.requester_user_id
                or users_by_id.get(controller.bound_user_id) is None
                or users_by_id.get(target.bound_user_id) is None
                or users_by_id[controller.bound_user_id].tenant_id != row.tenant_id
                or users_by_id[target.bound_user_id].tenant_id != row.tenant_id
            ):
                _not_found()
            request = device_session_out(row).request
            if (
                request.controller_device_id != controller.device_id
                or request.target_device_id != target.device_id
            ):
                _not_found()
            if row.target_device_id != caller.id:
                _deny()
            approved_scopes = list(payload.approved_scopes)
            approved_profile = (
                payload.approved_profile.model_dump(mode="json")
                if payload.approved_profile is not None
                else None
            )
            if (
                not approved_scopes
                or row.requested_scopes is None
                or any(scope not in row.requested_scopes for scope in approved_scopes)
                or not _profile_within(approved_profile, row.requested_profile)
            ):
                _deny()
            now = _utc(self._now())
            if row.status == "approved":
                active_generation = row.active_relay_generation
                policy = relay_access.current_policy
                if (
                    row.approved_scopes != approved_scopes
                    or row.approved_profile != approved_profile
                    or row.policy_revision != policy.revision
                    or row.relay_allowed_regions != list(policy.allowed_regions)
                    or row.relay_preferred_regions != list(policy.preferred_regions)
                    or row.relay_accepted_transports != list(policy.accepted_transports)
                    or row.intended_peer_id != target.id
                    or not isinstance(row.grant_expires_at, datetime)
                    or _utc(row.grant_expires_at) <= now
                    or not isinstance(row.policy_expires_at, datetime)
                    or _utc(row.policy_expires_at) <= now
                    or not isinstance(active_generation, int)
                    or isinstance(active_generation, bool)
                    or active_generation < 0
                ):
                    _conflict()
                await relay_access.validate_wan_generation_locked(
                    grant=row,
                    target_device=target,
                    generation=active_generation,
                )
                return row
            if row.status != "requested":
                _conflict()

            bind_session_grant_policy(
                grant=row,
                target_device_id=target.id,
                policy=relay_access.current_policy,
                now=now,
                set_status=False,
            )
            row.approved_scopes = approved_scopes
            row.approved_profile = approved_profile
            await relay_access.create_wan_generation_locked(
                grant=row,
                target_device=target,
                generation=0,
            )
            self._audit(
                action="wan_session_approved",
                row=row,
                actor_device_id=caller.id,
            )
            await self._session.flush()
            return row

    async def transition(
        self,
        *,
        session_id: str,
        current_device: Device,
        action: str,
    ) -> SessionRequest:
        rules: dict[str, tuple[set[str], str, str]] = {
            "reject": ({"requested"}, "rejected", "target"),
            "close": ({"requested", "approved"}, "closed", "participant"),
            "revoke": ({"approved"}, "revoked", "target"),
        }
        if action not in rules:
            raise ValueError("unsupported WAN session transition")
        expected, terminal, authorization = rules[action]
        async with session_grant_identity_lock(self._session, "session:" + session_id):
            row = await self._session.scalar(
                select(SessionRequest)
                .where(SessionRequest.id == session_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if row is None or not _is_authorized_participant(row, current_device):
                _not_found()
            if authorization == "target" and row.target_device_id != current_device.id:
                _deny()
            if row.status == terminal:
                return row
            if row.status not in expected:
                _conflict()

            now = _utc(self._now())
            row.status = terminal
            if row.grant_expires_at is not None:
                row.grant_expires_at = now
            if row.policy_expires_at is not None:
                row.policy_expires_at = now
            await self._session.execute(
                update(RelayReservation)
                .where(
                    RelayReservation.session_id == session_id,
                    RelayReservation.expires_at > now,
                    RelayReservation.superseded_at.is_(None),
                )
                .values(superseded_at=now)
                .execution_options(synchronize_session=False)
            )
            self._audit(
                action="wan_session_" + terminal,
                row=row,
                actor_device_id=current_device.id,
            )
            await self._session.flush()
            return row

    async def _is_exact_retry(
        self,
        row: SessionRequest,
        *,
        current_device: Device,
        normalized: dict[str, object],
        commitment: str,
    ) -> bool:
        if (
            row.requester_device_id == current_device.id
            and row.requester_user_id != current_device.bound_user_id
        ):
            _deny()
        if (
            row.requester_device_id != current_device.id
            or row.tenant_id != current_device.tenant_id
            or row.request_payload != normalized
            or row.request_commitment != commitment
            or row.access_mode != normalized["access_mode"]
            or row.route_policy != normalized["route_policy"]
            or row.requested_scopes != normalized["requested_scopes"]
            or row.requested_profile != normalized["requested_profile"]
        ):
            return False
        target = await self._session.scalar(
            select(Device).where(Device.id == row.target_device_id)
        )
        if (
            target is None
            or not _is_active_device(target)
            or target.tenant_id != row.tenant_id
        ):
            _deny()
        return (
            target.device_id == normalized["target_device_id"]
            and current_device.device_id == normalized["controller_device_id"]
        )

    def _audit(
        self,
        *,
        action: str,
        row: SessionRequest,
        actor_device_id: str,
    ) -> None:
        self._session.add(
            RelayAuditEvent(
                action=action,
                node_id=None,
                actor_id=actor_device_id,
                details={"session_id": row.id, "status": row.status},
                created_at=_utc(self._now()),
            )
        )


def canonical_wan_request(
    payload: DeviceSessionCreateIn, *, current_device: Device
) -> DeviceSessionCanonicalRequest:
    return DeviceSessionCanonicalRequest(
        session_id=payload.session_id,
        idempotency_key=list(payload.idempotency_key),
        controller_device_id=current_device.device_id,
        target_device_id=payload.target_device_id,
        access_mode=payload.access_mode,
        requested_scopes=list(payload.requested_scopes),
        requested_profile=payload.requested_profile,
        route_policy=payload.route_policy,
    )


def wan_request_commitment(request: DeviceSessionCanonicalRequest) -> str:
    canonical = json.dumps(
        request.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(_REQUEST_COMMITMENT_CONTEXT + canonical).hexdigest()


def device_session_out(row: SessionRequest) -> DeviceSessionOut:
    try:
        if not isinstance(row.request_payload, dict):
            _conflict()
        request = DeviceSessionCanonicalRequest.model_validate(row.request_payload)
        if (
            row.id != request.session_id
            or row.request_commitment != wan_request_commitment(request)
            or row.access_mode != request.access_mode
            or row.route_policy != request.route_policy
            or row.requested_scopes != request.requested_scopes
            or row.requested_profile
            != (
                request.requested_profile.model_dump(mode="json")
                if request.requested_profile is not None
                else None
            )
        ):
            _conflict()
        return DeviceSessionOut(
            session_id=row.id,
            request=request,
            request_commitment=row.request_commitment,
            status=row.status,
            approved_scopes=row.approved_scopes,
            approved_profile=row.approved_profile,
            policy_revision=row.policy_revision,
            policy_expires_at=row.policy_expires_at,
            grant_expires_at=row.grant_expires_at,
            active_relay_generation=row.active_relay_generation,
        )
    except ValidationError:
        _conflict()


def _is_authorized_participant(row: SessionRequest, device: Device) -> bool:
    return (
        _is_active_device(device)
        and row.tenant_id == device.tenant_id
        and row.requester_device_id is not None
        and row.access_mode == "attended"
        and row.route_policy == "relay_only"
        and device.id in {row.requester_device_id, row.target_device_id}
        and (
            device.id != row.requester_device_id
            or device.bound_user_id == row.requester_user_id
        )
    )


def _is_active_device(device: Device) -> bool:
    return (
        device.is_bound
        and device.bound_user_id is not None
        and device.auth_revoked_at is None
        and _valid_tenant(device.tenant_id)
    )


def _matches_auth_snapshot(
    device: Device, snapshot: DeviceAuthSnapshot
) -> bool:
    return (
        snapshot.auth_revoked_at is None
        and snapshot.is_bound
        and device.id == snapshot.row_id
        and device.device_id == snapshot.device_id
        and device.auth_version == snapshot.auth_version
        and device.bound_user_id == snapshot.bound_user_id
        and device.tenant_id == snapshot.tenant_id
        and device.is_bound == snapshot.is_bound
        and device.auth_revoked_at == snapshot.auth_revoked_at
    )


def _profile_within(
    approved: dict[str, object] | None,
    requested: dict[str, object] | None,
) -> bool:
    if approved is None:
        return True
    if requested is None:
        return False
    return (
        approved.get("codec") == requested.get("codec")
        and approved.get("codec_profile") == requested.get("codec_profile")
        and _bounded_profile_value(approved, requested, "width")
        and _bounded_profile_value(approved, requested, "height")
        and _bounded_profile_value(approved, requested, "fps")
        and _bounded_profile_value(approved, requested, "bitrate_mbps")
        and all(
            approved.get(field) == requested.get(field)
            for field in (
                "bit_depth",
                "chroma_subsampling",
                "pixel_format",
                "hdr_enabled",
                "color_mode",
                "color_pipeline",
            )
        )
    )


def _bounded_profile_value(
    approved: dict[str, object], requested: dict[str, object], field: str
) -> bool:
    approved_value = approved.get(field)
    requested_value = requested.get(field)
    return (
        isinstance(approved_value, int)
        and not isinstance(approved_value, bool)
        and isinstance(requested_value, int)
        and not isinstance(requested_value, bool)
        and approved_value <= requested_value
    )


def _valid_tenant(value: object) -> bool:
    if not isinstance(value, str) or not value.isascii() or not 1 <= len(value) <= 64:
        return False
    return value[0].isalnum() and all(
        character.isalnum() or character in "._-" for character in value
    )


def _deny() -> None:
    raise DeviceSessionError("wan_session_denied", 403, "WAN session denied")


def _conflict() -> None:
    raise DeviceSessionError("wan_session_conflict", 409, "WAN session state conflicts")


def _not_found() -> None:
    raise DeviceSessionError("wan_session_not_found", 404, "WAN session is unavailable")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
