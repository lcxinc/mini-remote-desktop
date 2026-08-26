from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass, field as dataclass_field, replace
from datetime import UTC, datetime, timedelta
from typing import Callable, Iterable, NoReturn, Protocol

from sqlalchemy import func, select

from app.core.security import DeviceAuthSnapshot
from app.models.device import Device
from app.models.relay_access_generation import RelayAccessGeneration
from app.models.relay_audit_event import RelayAuditEvent
from app.models.relay_node import RelayNode
from app.models.relay_node_registration import RelayNodeRegistration
from app.models.relay_reservation import RelayReservation
from app.models.session_request import SessionRequest
from app.models.user import User
from app.services.relay_repository import RelayRepository, RelayRepositoryError
from app.services.relay_signing import (
    RelayDirectoryCandidateOut,
    RelayDirectoryEndpointOut,
    RelayDirectoryPayloadOut,
    RelayReservationOut,
    SignedRelayDirectoryOut,
    canonical_directory_bytes,
)
from app.services.session_grants import (
    SessionGrantError,
    SessionGrantPolicy,
    session_grant_identity_lock,
    validate_session_grant_policy,
)
from app.services.turn_credentials import NodeTurnCredential, NodeTurnCredentialService


_ENDPOINT = re.compile(
    r"^(?P<scheme>turn|turns):(?P<host>\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+):"
    r"(?P<port>[0-9]{1,5})(?:\?transport=(?P<transport>udp|tcp))?$",
    re.IGNORECASE | re.ASCII,
)
_CREDENTIAL_SCOPE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_BASIS_POINTS = 10_000
_UNKNOWN_RTT_MS = 2**32 - 1
_U64_MAX = 2**64 - 1


class RelayAccessError(Exception):
    def __init__(self, code: str, status_code: int, message: str) -> None:
        self.code = code
        self.status_code = status_code
        super().__init__(message)


@dataclass(frozen=True)
class RelayNodeView:
    node_id: str
    region: str
    failure_domain: str
    physical_host_id: str | None
    topology_approved: bool
    state: str
    lease_expires_at: datetime | None
    revoked_at: datetime | None
    registration_status: str
    certificate_expires_at: datetime | None
    endpoints: tuple[str, ...]
    active_allocations: int
    max_allocations: int
    current_egress_bps: int
    max_egress_bps: int
    measured_rtt_ms: int | None = None
    recent_failure_bps: int = 0


@dataclass(frozen=True)
class RelayScoreWeights:
    base_score: int = 1_000_000_000
    region_preference: int = 100_000_000
    rtt_penalty_per_ms: int = 10_000
    allocation_utilization_penalty: int = 250_000_000
    bandwidth_headroom_reward: int = 100_000_000
    recent_failure_penalty: int = 300_000_000
    soft_full_penalty: int = 100_000_000
    degraded_penalty: int = 200_000_000


@dataclass(frozen=True)
class RelaySelectionPolicy:
    revision: int
    allowed_regions: tuple[str, ...]
    preferred_regions: tuple[str, ...]
    accepted_transports: tuple[str, ...]
    max_backups: int = 1
    soft_allocation_limit_bps: int = 8_500
    weights: RelayScoreWeights = RelayScoreWeights()


@dataclass(frozen=True)
class RelayRejection:
    node_id: str
    code: str


@dataclass(frozen=True)
class RelaySelectedNode:
    node_id: str
    region: str
    failure_domain: str
    physical_host_id: str
    endpoints: tuple[str, ...]
    score: int
    selection_reason: str = "eligible"


@dataclass(frozen=True)
class RelaySelectionDecision:
    selected: tuple[RelaySelectedNode, ...]
    eligible: tuple[RelaySelectedNode, ...]
    rejections: tuple[RelayRejection, ...]


@dataclass(frozen=True)
class RelayAccessResult:
    directory: SignedRelayDirectoryOut
    credentials: tuple[NodeTurnCredential, ...] = dataclass_field(repr=False)
    generation: int | None = None
    relay_url_digest: str | None = None


class RelayDirectorySigner(Protocol):
    def sign(self, payload: RelayDirectoryPayloadOut) -> SignedRelayDirectoryOut: ...


class RelayAccessService:
    def __init__(
        self,
        *,
        session: object,
        repository: RelayRepository,
        signer: RelayDirectorySigner,
        credential_issuer: NodeTurnCredentialService,
        current_policy: SessionGrantPolicy,
        directory_ttl_seconds: int = 30,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not 1 <= directory_ttl_seconds <= 300:
            raise ValueError("relay directory TTL must be between 1 and 300 seconds")
        self._session = session
        self._repository = repository
        self._signer = signer
        self._credential_issuer = credential_issuer
        self._current_policy = current_policy
        self._directory_ttl_seconds = directory_ttl_seconds
        self._now = now or (lambda: datetime.now(UTC))

    @property
    def current_policy(self) -> SessionGrantPolicy:
        return self._current_policy

    async def issue_access(
        self,
        *,
        current_user_id: str,
        session_id: str,
        policy_revision: int,
        intended_peer_id: str,
    ) -> RelayAccessResult:
        async with session_grant_identity_lock(self._session, "session:" + session_id):
            return await self._issue_access_locked(
                current_user_id=current_user_id,
                session_id=session_id,
                policy_revision=policy_revision,
                intended_peer_id=intended_peer_id,
            )

    async def create_wan_generation_locked(
        self,
        *,
        grant: SessionRequest,
        target_device: Device,
        generation: int,
    ) -> RelayAccessGeneration:
        """Create and persist one immutable public WAN generation.

        The caller owns the session identity lock, the row lock, and the outer
        transaction. This method never commits and never derives participant
        credentials.
        """

        now = _utc(self._now())
        if (
            grant.requester_device_id is None
            or grant.target_device_id != target_device.id
            or grant.intended_peer_id != target_device.id
            or grant.status != ("requested" if generation == 0 else "approved")
            or not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation < 0
            or generation
            != (
                0
                if grant.active_relay_generation is None
                else grant.active_relay_generation + 1
            )
        ):
            _deny_access()
        try:
            persisted = await self._build_and_persist_wan_generation(
                grant=grant,
                target_device=target_device,
                generation=generation,
                now=now,
            )
            grant.active_relay_generation = generation
            grant.status = "approved"
            await self._session.flush()
            return persisted
        except RelayAccessError:
            raise
        except RelayRepositoryError as error:
            if error.code in {
                "INVALID_SESSION_ID",
                "INVALID_USER_ID",
                "SESSION_OWNER_MISMATCH",
            }:
                _deny_access()
            raise RelayAccessError(
                "relay_capacity_unavailable", 503, "relay capacity unavailable"
            ) from None

    async def validate_wan_generation_locked(
        self,
        *,
        grant: SessionRequest,
        target_device: Device,
        generation: int,
    ) -> RelayAccessGeneration:
        persisted = await self._session.scalar(
            select(RelayAccessGeneration)
            .where(
                RelayAccessGeneration.session_id == grant.id,
                RelayAccessGeneration.generation == generation,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if persisted is None:
            _deny_access()
        directory = self._validate_persisted_wan_generation(
            grant=grant,
            target_device=target_device,
            persisted=persisted,
            now=_utc(self._now()),
        )
        await self._validate_wan_reservations_locked(
            grant=grant,
            persisted=persisted,
            directory=directory,
        )
        return persisted

    async def issue_wan_access(
        self,
        *,
        auth_snapshot: DeviceAuthSnapshot,
        session_id: str,
        policy_revision: int,
        intended_peer_id: str,
        generation: int,
        refresh: bool = False,
    ) -> RelayAccessResult:
        if refresh:
            async with session_grant_identity_lock(
                self._session, "session:" + session_id
            ):
                try:
                    async with _issuance_transaction(self._session):
                        now = _utc(self._now())
                        (
                            grant,
                            controller,
                            target,
                            caller,
                        ) = await self._locked_wan_context(
                            auth_snapshot=auth_snapshot,
                            session_id=session_id,
                        )
                        self._authorize_wan_access(
                            grant=grant,
                            controller=controller,
                            target=target,
                            caller=caller,
                            auth_snapshot=auth_snapshot,
                            requested_policy_revision=policy_revision,
                            requested_peer_id=intended_peer_id,
                            requested_generation=generation,
                            now=now,
                        )
                        await self.create_wan_generation_locked(
                            grant=grant,
                            target_device=target,
                            generation=generation + 1,
                        )
                except RelayAccessError:
                    raise
                except RelayRepositoryError:
                    raise RelayAccessError(
                        "relay_capacity_unavailable",
                        503,
                        "relay capacity unavailable",
                    ) from None
            generation += 1
        return await self._fetch_wan_access(
            auth_snapshot=auth_snapshot,
            session_id=session_id,
            policy_revision=policy_revision,
            intended_peer_id=intended_peer_id,
            generation=generation,
        )

    async def issue_authenticated_access(
        self,
        *,
        current_device: Device,
        auth_snapshot: DeviceAuthSnapshot,
        session_id: str,
        policy_revision: int,
        intended_peer_id: str,
        generation: int | None,
        refresh: bool,
    ) -> RelayAccessResult:
        preview = await self._session.scalar(
            select(SessionRequest).where(SessionRequest.id == session_id)
        )
        if preview is None:
            _deny_access()
        if preview.requester_device_id is None:
            if generation is not None or refresh:
                _deny_access()
            if not current_device.is_bound or current_device.bound_user_id is None:
                _deny_access()
            return await self.issue_access(
                current_user_id=current_device.bound_user_id,
                session_id=session_id,
                policy_revision=policy_revision,
                intended_peer_id=intended_peer_id,
            )
        if generation is None:
            _deny_access()
        return await self.issue_wan_access(
            auth_snapshot=auth_snapshot,
            session_id=session_id,
            policy_revision=policy_revision,
            intended_peer_id=intended_peer_id,
            generation=generation,
            refresh=refresh,
        )

    async def _fetch_wan_access(
        self,
        *,
        auth_snapshot: DeviceAuthSnapshot,
        session_id: str,
        policy_revision: int,
        intended_peer_id: str,
        generation: int,
    ) -> RelayAccessResult:
        async with session_grant_identity_lock(self._session, "session:" + session_id):
            try:
                async with _issuance_transaction(self._session):
                    now = _utc(self._now())
                    grant, controller, target, caller = await self._locked_wan_context(
                        auth_snapshot=auth_snapshot,
                        session_id=session_id,
                    )
                    self._authorize_wan_access(
                        grant=grant,
                        controller=controller,
                        target=target,
                        caller=caller,
                        auth_snapshot=auth_snapshot,
                        requested_policy_revision=policy_revision,
                        requested_peer_id=intended_peer_id,
                        requested_generation=generation,
                        now=now,
                    )
                    persisted = await self._session.scalar(
                        select(RelayAccessGeneration)
                        .where(
                            RelayAccessGeneration.session_id == session_id,
                            RelayAccessGeneration.generation == generation,
                        )
                        .with_for_update()
                        .execution_options(populate_existing=True)
                    )
                    if persisted is None:
                        _deny_access()
                    directory = self._validate_persisted_wan_generation(
                        grant=grant,
                        target_device=target,
                        persisted=persisted,
                        now=now,
                    )
                    credentials = await self._issue_wan_credentials_locked(
                        grant=grant,
                        caller=caller,
                        persisted=persisted,
                        directory=directory,
                        now=now,
                    )
                    for candidate in directory.payload.candidates:
                        self._session.add(
                            RelayAuditEvent(
                                action="wan_relay_access_issued",
                                node_id=candidate.node_id,
                                actor_id=caller.id,
                                details={"generation": persisted.generation},
                                created_at=now,
                            )
                        )
                    await self._session.flush()
                    return RelayAccessResult(
                        directory=directory,
                        credentials=credentials,
                        generation=persisted.generation,
                        relay_url_digest=persisted.relay_url_digest,
                    )
            except RelayAccessError:
                raise
            except RelayRepositoryError:
                raise RelayAccessError(
                    "relay_capacity_unavailable", 503, "relay capacity unavailable"
                ) from None

    async def _locked_wan_context(
        self,
        *,
        auth_snapshot: DeviceAuthSnapshot,
        session_id: str,
    ) -> tuple[SessionRequest, Device, Device, Device]:
        preview = await self._session.scalar(
            select(SessionRequest)
            .where(SessionRequest.id == session_id)
            .execution_options(populate_existing=True)
        )
        if preview is None or preview.requester_device_id is None:
            _deny_access()
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
        by_id = {device.id: device for device in devices}
        controller = by_id.get(preview.requester_device_id)
        target = by_id.get(preview.target_device_id)
        caller = by_id.get(auth_snapshot.row_id)
        if controller is None or target is None or caller is None:
            _deny_access()
        user_ids = sorted(
            {
                value
                for value in (
                    preview.requester_user_id,
                    controller.bound_user_id,
                    target.bound_user_id,
                    caller.bound_user_id,
                )
                if isinstance(value, str)
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
        grant = await self._session.scalar(
            select(SessionRequest)
            .where(SessionRequest.id == session_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if (
            grant is None
            or grant.requester_device_id != controller.id
            or grant.target_device_id != target.id
            or users_by_id.get(controller.bound_user_id) is None
            or users_by_id.get(target.bound_user_id) is None
            or users_by_id[controller.bound_user_id].tenant_id != grant.tenant_id
            or users_by_id[target.bound_user_id].tenant_id != grant.tenant_id
        ):
            _deny_access()
        return grant, controller, target, caller

    def _authorize_wan_access(
        self,
        *,
        grant: SessionRequest,
        controller: Device | None,
        target: Device | None,
        caller: Device | None,
        auth_snapshot: DeviceAuthSnapshot,
        requested_policy_revision: int,
        requested_peer_id: str,
        requested_generation: int,
        now: datetime,
    ) -> None:
        participant_ids = {grant.requester_device_id, grant.target_device_id}
        valid = (
            controller is not None
            and target is not None
            and caller is not None
            and _matches_auth_snapshot(caller, auth_snapshot)
            and caller.id in participant_ids
            and controller.id != target.id
            and controller.is_bound
            and target.is_bound
            and caller.is_bound
            and controller.auth_revoked_at is None
            and target.auth_revoked_at is None
            and caller.auth_revoked_at is None
            and controller.bound_user_id == grant.requester_user_id
            and controller.tenant_id == grant.tenant_id
            and target.tenant_id == grant.tenant_id
            and caller.tenant_id == grant.tenant_id
            and _wan_request_binding_valid(
                grant=grant,
                controller=controller,
                target=target,
            )
            and target.device_id == requested_peer_id
            and grant.intended_peer_id == target.id
            and grant.status == "approved"
            and isinstance(grant.grant_expires_at, datetime)
            and _utc(grant.grant_expires_at) > now
            and isinstance(grant.policy_expires_at, datetime)
            and _utc(grant.policy_expires_at) > now
            and requested_policy_revision == grant.policy_revision
            and requested_generation == grant.active_relay_generation
            and _grant_conforms_to_current_policy(
                grant=grant,
                current_policy=self._current_policy,
                requested_policy_revision=requested_policy_revision,
                now=now,
            )
        )
        if not valid:
            _deny_access()

    async def _build_and_persist_wan_generation(
        self,
        *,
        grant: SessionRequest,
        target_device: Device,
        generation: int,
        now: datetime,
    ) -> RelayAccessGeneration:
        policy = _policy_from_grant(grant)
        rows = await self._session.execute(
            select(RelayNode, RelayNodeRegistration)
            .join(
                RelayNodeRegistration,
                RelayNodeRegistration.node_id == RelayNode.node_id,
            )
            .order_by(RelayNode.node_id)
        )
        records = list(rows.all())
        views = [_view(node, registration) for node, registration in records]
        pending_rows = await self._session.execute(
            select(RelayReservation.node_id, func.count(RelayReservation.id))
            .where(
                RelayReservation.node_id.in_([node.node_id for node, _ in records]),
                RelayReservation.session_id != grant.id,
                RelayReservation.expires_at > now,
            )
            .group_by(RelayReservation.node_id)
        )
        pending_by_node = {node_id: int(count) for node_id, count in pending_rows.all()}
        views = [
            replace(
                view,
                active_allocations=(
                    view.active_allocations + pending_by_node.get(view.node_id, 0)
                ),
            )
            for view in views
        ]
        decision = select_relay_nodes(policy, views, now=now)
        by_id = {
            node.node_id: (node, registration, view)
            for (node, registration), view in zip(records, views, strict=True)
        }
        required_count = 1 + policy.max_backups
        if len(decision.selected) < required_count:
            raise RelayAccessError(
                "relay_capacity_unavailable", 503, "relay capacity unavailable"
            )
        selected_ids = {item.node_id for item in decision.selected}
        ordered_candidates = (
            *decision.selected,
            *(
                item
                for item in decision.eligible
                if item.node_id not in selected_ids
            ),
        )[:8]
        server_deadline_seconds = min(
            int((now + timedelta(seconds=self._directory_ttl_seconds)).timestamp()),
            _unix_seconds(grant.grant_expires_at),
            _unix_seconds(grant.policy_expires_at),
        )
        server_deadline = datetime.fromtimestamp(server_deadline_seconds, tz=UTC)
        if server_deadline <= now:
            _deny_access()
        directory_id = new_directory_id()
        reservation_ttl = int((server_deadline - now).total_seconds())
        if reservation_ttl <= 0:
            _deny_access()
        preexisting_reservation_ids = set(
            (
                await self._session.scalars(
                    select(RelayReservation.id).where(
                        RelayReservation.session_id == grant.id,
                        RelayReservation.expires_at > now,
                    )
                )
            ).all()
        )
        try:
            reservations = await self._repository.reserve_capacity(
                session_id=grant.id,
                user_id=grant.requester_user_id,
                ordered_node_ids=[item.node_id for item in ordered_candidates],
                now=now,
                ttl_seconds=reservation_ttl,
                expires_at=server_deadline,
                directory_generation=directory_id,
                require_registration=True,
                require_distinct_topology=True,
                result_limit=required_count,
            )
        except BaseException:
            await self._release_uncommitted_capacity(
                session_id=grant.id,
                directory_id=directory_id,
                reservation_ids=None,
            )
            raise
        new_reservation_ids = [
            item.id
            for item in reservations
            if item.id not in preexisting_reservation_ids
        ]
        if len(reservations) != required_count:
            await self._release_uncommitted_capacity(
                session_id=grant.id,
                directory_id=directory_id,
                reservation_ids=new_reservation_ids,
            )
            raise RelayAccessError(
                "relay_capacity_unavailable", 503, "relay capacity unavailable"
            )
        existing_reservations = [
            item for item in reservations if item.id in preexisting_reservation_ids
        ]
        try:
            reservations, reservation_expiry = await _cohere_reservations(
                session=self._session,
                reservations=reservations,
                existing_reservations=existing_reservations,
                by_id=by_id,
                server_deadline=server_deadline,
            )
        except Exception:
            await self._release_uncommitted_capacity(
                session_id=grant.id,
                directory_id=directory_id,
                reservation_ids=new_reservation_ids,
            )
            raise
        if len(reservations) != required_count or reservation_expiry <= now:
            await self._release_uncommitted_capacity(
                session_id=grant.id,
                directory_id=directory_id,
                reservation_ids=new_reservation_ids,
            )
            raise RelayAccessError(
                "relay_capacity_unavailable", 503, "relay capacity unavailable"
            )
        await self._session.flush()
        selection_order = {
            item.node_id: index for index, item in enumerate(reservations)
        }
        reservation_by_node = {item.node_id: item for item in reservations}
        signed_candidates: list[RelayDirectoryCandidateOut] = []
        urls_by_node: dict[str, list[str]] = {}
        for node_id in sorted(
            reservation_by_node, key=lambda value: value.encode("utf-8")
        ):
            node, registration, _ = by_id[node_id]
            locked_endpoints = tuple(
                endpoint
                for endpoint in node.endpoints
                if endpoint_transport(endpoint) in policy.accepted_transports
            )
            if not locked_endpoints:
                await self._release_uncommitted_capacity(
                    session_id=grant.id,
                    directory_id=directory_id,
                    reservation_ids=new_reservation_ids,
                )
                raise RelayAccessError(
                    "relay_capacity_unavailable", 503, "relay capacity unavailable"
                )
            endpoints = sorted(
                (endpoint_parts(url) for url in locked_endpoints),
                key=lambda item: (
                    {"udp": 1, "tcp": 2, "tls": 3}[item[0]],
                    item[1].encode("utf-8"),
                    item[2],
                ),
            )
            endpoint_models = [
                RelayDirectoryEndpointOut(
                    transport=transport,
                    host=_signed_endpoint_host(host),
                    port=port,
                )
                for transport, host, port in endpoints
            ]
            urls_by_node[node_id] = [
                _canonical_endpoint_url(item) for item in endpoint_models
            ]
            signed_candidates.append(
                RelayDirectoryCandidateOut(
                    node_id=node_id,
                    region=node.region,
                    failure_domain=node.failure_domain,
                    endpoints=endpoint_models,
                    capabilities=_capabilities(locked_endpoints),
                    load_class=_load_class(_view(node, registration)),
                    selection_reason=(
                        "preferred-region"
                        if selection_order[node_id] == 0
                        else "failure-domain-backup"
                    ),
                    reservation=RelayReservationOut(
                        reservation_id=reservation_by_node[node_id].id,
                        expires_at_ms=_unix_ms(reservation_by_node[node_id].expires_at),
                    ),
                )
            )
        payload = RelayDirectoryPayloadOut(
            format_version=1,
            policy_revision=grant.policy_revision,
            directory_id=directory_id,
            issued_at_ms=_unix_ms(now),
            expires_at_ms=_unix_ms(reservation_expiry),
            session_id=grant.id,
            intended_peer_digest=intended_peer_digest(target_device.device_id),
            candidates=signed_candidates,
        )
        try:
            directory = self._signer.sign(payload)
            if directory.payload != payload:
                raise ValueError("signed directory payload changed")
            canonical_directory_bytes(directory.payload)
        except Exception:
            await self._release_uncommitted_capacity(
                session_id=grant.id,
                directory_id=directory_id,
                reservation_ids=new_reservation_ids,
            )
            raise RelayAccessError(
                "relay_signing_unavailable", 503, "relay access unavailable"
            ) from None
        primary_node_id = next(
            candidate.node_id
            for candidate in signed_candidates
            if candidate.selection_reason == "preferred-region"
        )
        persisted = RelayAccessGeneration(
            session_id=grant.id,
            generation=generation,
            directory_id=directory.payload.directory_id,
            signed_directory=directory.model_dump(mode="json"),
            signing_key_id=directory.signing_key_id,
            signature_b64=directory.signature_b64,
            relay_url_digest=relay_url_digest(urls_by_node[primary_node_id]),
            primary_node_id=primary_node_id,
            reservation_ids=[
                candidate.reservation.reservation_id for candidate in signed_candidates
            ],
            expires_at=reservation_expiry,
            created_at=now,
        )
        self._session.add(persisted)
        await self._session.flush()
        return persisted

    async def _release_uncommitted_capacity(
        self,
        *,
        session_id: str,
        directory_id: str,
        reservation_ids: list[str] | None,
    ) -> None:
        if reservation_ids == []:
            return
        try:
            await self._repository.release_uncommitted_generation(
                session_id=session_id,
                directory_generation=directory_id,
                reservation_ids=reservation_ids,
            )
        except Exception:
            # The outer transaction rollback remains the final ReleaseAll
            # authority if the database cannot service this guarded cleanup.
            return

    def _validate_persisted_wan_generation(
        self,
        *,
        grant: SessionRequest,
        target_device: Device,
        persisted: RelayAccessGeneration,
        now: datetime,
    ) -> SignedRelayDirectoryOut:
        try:
            directory = SignedRelayDirectoryOut.model_validate(
                persisted.signed_directory
            )
            canonical_directory_bytes(directory.payload)
            reservation_ids = [
                candidate.reservation.reservation_id
                for candidate in directory.payload.candidates
            ]
            primary_ids = [
                candidate.node_id
                for candidate in directory.payload.candidates
                if candidate.selection_reason == "preferred-region"
            ]
            primary = next(
                candidate
                for candidate in directory.payload.candidates
                if candidate.node_id == persisted.primary_node_id
            )
            urls = [_canonical_endpoint_url(endpoint) for endpoint in primary.endpoints]
            expected_signature = self._signer.sign(directory.payload)
            valid = (
                persisted.session_id == grant.id
                and persisted.generation == grant.active_relay_generation
                and _utc(persisted.expires_at) > now
                and directory.payload.expires_at_ms == _unix_ms(persisted.expires_at)
                and directory.payload.session_id == grant.id
                and directory.payload.policy_revision == grant.policy_revision
                and directory.payload.directory_id == persisted.directory_id
                and directory.payload.intended_peer_digest
                == intended_peer_digest(target_device.device_id)
                and directory.signing_key_id == persisted.signing_key_id
                and directory.signature_b64 == persisted.signature_b64
                and expected_signature.signing_key_id == directory.signing_key_id
                and hmac.compare_digest(
                    expected_signature.signature_b64, directory.signature_b64
                )
                and reservation_ids == persisted.reservation_ids
                and primary_ids == [persisted.primary_node_id]
                and all(endpoint_transport(url) is not None for url in urls)
                and relay_url_digest(urls) == persisted.relay_url_digest
            )
        except Exception:
            valid = False
        if not valid:
            _deny_access()
        return directory

    async def _validate_wan_reservations_locked(
        self,
        *,
        grant: SessionRequest,
        persisted: RelayAccessGeneration,
        directory: SignedRelayDirectoryOut,
    ) -> None:
        rows = list(
            await self._session.scalars(
                select(RelayReservation)
                .where(RelayReservation.id.in_(persisted.reservation_ids))
                .order_by(RelayReservation.id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        )
        by_id = {row.id: row for row in rows}
        if len(by_id) != len(persisted.reservation_ids):
            _deny_access()
        for candidate in directory.payload.candidates:
            reservation = by_id.get(candidate.reservation.reservation_id)
            if (
                reservation is None
                or reservation.session_id != grant.id
                or reservation.user_id != grant.requester_user_id
                or reservation.node_id != candidate.node_id
                or reservation.directory_generation != persisted.directory_id
                or reservation.superseded_at is not None
                or _utc(reservation.expires_at) != _utc(persisted.expires_at)
                or candidate.reservation.expires_at_ms
                != _unix_ms(reservation.expires_at)
            ):
                _deny_access()

    async def _issue_wan_credentials_locked(
        self,
        *,
        grant: SessionRequest,
        caller: Device,
        persisted: RelayAccessGeneration,
        directory: SignedRelayDirectoryOut,
        now: datetime,
    ) -> tuple[NodeTurnCredential, ...]:
        node_ids = [candidate.node_id for candidate in directory.payload.candidates]
        await self._validate_wan_reservations_locked(
            grant=grant,
            persisted=persisted,
            directory=directory,
        )
        nodes = list(
            await self._session.scalars(
                select(RelayNode)
                .where(RelayNode.node_id.in_(node_ids))
                .order_by(RelayNode.node_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        )
        registrations = list(
            await self._session.scalars(
                select(RelayNodeRegistration)
                .where(RelayNodeRegistration.node_id.in_(node_ids))
                .order_by(RelayNodeRegistration.node_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        )
        registrations_by_id = {row.node_id: row for row in registrations}
        by_id = {
            node.node_id: (node, registrations_by_id[node.node_id])
            for node in nodes
            if node.node_id in registrations_by_id
        }
        credentials: list[NodeTurnCredential] = []
        primary_urls: list[str] | None = None
        policy = _policy_from_grant(grant)
        for candidate in directory.payload.candidates:
            pair = by_id.get(candidate.node_id)
            if pair is None:
                _deny_access()
            node, registration = pair
            urls = [_canonical_endpoint_url(item) for item in candidate.endpoints]
            if candidate.node_id == persisted.primary_node_id:
                primary_urls = urls
            registered_urls = [
                _canonical_endpoint_url(
                    RelayDirectoryEndpointOut(
                        transport=endpoint_parts(url)[0],
                        host=endpoint_parts(url)[1],
                        port=endpoint_parts(url)[2],
                    )
                )
                for url in node.endpoints
                if endpoint_transport(url) in policy.accepted_transports
            ]
            certificate_expiry = registration.certificate_expires_at
            lease_expiry = node.lease_expires_at
            if (
                sorted(urls) != sorted(registered_urls)
                or node.state not in {"available", "degraded"}
                or node.revoked_at is not None
                or registration.status != "approved"
                or registration.topology_approved_at is None
                or node.physical_host_id is None
                or registration.physical_host_id is None
                or registration.failure_domain != candidate.failure_domain
                or registration.physical_host_id != node.physical_host_id
                or node.failure_domain != candidate.failure_domain
                or not isinstance(certificate_expiry, datetime)
                or not isinstance(lease_expiry, datetime)
            ):
                _deny_access()
            node_deadline = min(_utc(certificate_expiry), _utc(lease_expiry))
            if node_deadline < _utc(persisted.expires_at):
                _deny_access()
            try:
                credential = self._credential_issuer.issue(
                    user_id=caller.device_id,
                    session_id=grant.id,
                    node_id=node.node_id,
                    urls=urls,
                    encrypted_secret=bytes(node.encrypted_turn_secret),
                    grant_deadline_unix_seconds=_unix_seconds(grant.grant_expires_at),
                    directory_deadline_unix_seconds=_unix_seconds(persisted.expires_at),
                    policy_deadline_unix_seconds=_unix_seconds(grant.policy_expires_at),
                    node_deadline_unix_seconds=_unix_seconds(node_deadline),
                )
            except Exception:
                raise RelayAccessError(
                    "relay_credential_unavailable", 503, "relay access unavailable"
                ) from None
            if credential.reencrypted_secret is not None:
                node.encrypted_turn_secret = credential.reencrypted_secret
                registration.encrypted_turn_secret = credential.reencrypted_secret
            credentials.append(credential)
        if (
            primary_urls is None
            or relay_url_digest(primary_urls) != persisted.relay_url_digest
        ):
            _deny_access()
        return tuple(credentials)

    async def _issue_access_locked(
        self,
        *,
        current_user_id: str,
        session_id: str,
        policy_revision: int,
        intended_peer_id: str,
    ) -> RelayAccessResult:
        now = _utc(self._now())
        try:
            async with _issuance_transaction(self._session):
                grant_preview = await self._session.scalar(
                    select(SessionRequest).where(SessionRequest.id == session_id)
                )
                if grant_preview is None:
                    _deny_access()
                target_device = await self._session.scalar(
                    select(Device)
                    .where(Device.id == grant_preview.target_device_id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
                if target_device is None:
                    _deny_access()
                if not target_device.is_bound or target_device.bound_user_id is None:
                    _deny_access()
                participant_rows = await self._session.scalars(
                    select(User)
                    .where(
                        User.id.in_(
                            {
                                grant_preview.requester_user_id,
                                target_device.bound_user_id,
                                current_user_id,
                            }
                        )
                    )
                    .order_by(User.id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
                participants = {user.id: user for user in participant_rows}
                grant = await self._session.scalar(
                    select(SessionRequest)
                    .where(SessionRequest.id == session_id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
                if grant is None or grant.target_device_id != target_device.id:
                    _deny_access()
                authorize_relay_grant(
                    grant=grant,
                    target_device=target_device,
                    requester_user=participants.get(grant.requester_user_id),
                    target_owner=participants.get(target_device.bound_user_id),
                    current_user=participants.get(current_user_id),
                    current_user_id=current_user_id,
                    requested_policy_revision=policy_revision,
                    requested_peer_id=intended_peer_id,
                    now=now,
                    current_policy=self._current_policy,
                )
                policy = _policy_from_grant(grant)
                rows = await self._session.execute(
                    select(RelayNode, RelayNodeRegistration)
                    .join(
                        RelayNodeRegistration,
                        RelayNodeRegistration.node_id == RelayNode.node_id,
                    )
                    .order_by(RelayNode.node_id)
                )
                records = list(rows.all())
                views = [_view(node, registration) for node, registration in records]
                pending_rows = await self._session.execute(
                    select(
                        RelayReservation.node_id,
                        func.count(RelayReservation.id),
                    )
                    .where(
                        RelayReservation.node_id.in_(
                            [node.node_id for node, _ in records]
                        ),
                        RelayReservation.session_id != session_id,
                        RelayReservation.expires_at > now,
                    )
                    .group_by(RelayReservation.node_id)
                )
                pending_by_node = {
                    node_id: int(count) for node_id, count in pending_rows.all()
                }
                views = [
                    replace(
                        view,
                        active_allocations=(
                            view.active_allocations
                            + pending_by_node.get(view.node_id, 0)
                        ),
                    )
                    for view in views
                ]
                decision = select_relay_nodes(policy, views, now=now)
                by_id = {
                    node.node_id: (node, registration, view)
                    for (node, registration), view in zip(records, views, strict=True)
                }
                ordered_candidates = decision.eligible[:8]
                if not ordered_candidates:
                    raise RelayAccessError(
                        "relay_capacity_unavailable", 503, "relay capacity unavailable"
                    )
                server_deadline_seconds = min(
                    int(
                        (
                            now + timedelta(seconds=self._directory_ttl_seconds)
                        ).timestamp()
                    ),
                    _unix_seconds(grant.grant_expires_at),
                    _unix_seconds(grant.policy_expires_at),
                )
                server_deadline = datetime.fromtimestamp(
                    server_deadline_seconds, tz=UTC
                )
                if server_deadline <= now:
                    _deny_access()
                directory_id = new_directory_id()
                # This snapshot is intentionally unlocked. Admission locks and
                # revalidates only this bounded candidate set, never the table.
                reservation_ttl = int((server_deadline - now).total_seconds())
                if reservation_ttl < 0:
                    _deny_access()
                preexisting_reservation_ids = set(
                    (
                        await self._session.scalars(
                            select(RelayReservation.id).where(
                                RelayReservation.session_id == session_id,
                                RelayReservation.expires_at > now,
                            )
                        )
                    ).all()
                )
                reservations = await self._repository.reserve_capacity(
                    session_id=session_id,
                    # Capacity belongs to the server-verified grant, not whichever
                    # of its two participants happens to request credentials first.
                    user_id=grant.requester_user_id,
                    ordered_node_ids=[item.node_id for item in ordered_candidates],
                    now=now,
                    ttl_seconds=reservation_ttl,
                    expires_at=server_deadline,
                    directory_generation=directory_id,
                    require_registration=True,
                    require_distinct_topology=True,
                    result_limit=1 + policy.max_backups,
                )
                if not reservations:
                    raise RelayAccessError(
                        "relay_capacity_unavailable", 503, "relay capacity unavailable"
                    )
                existing_reservations = [
                    item
                    for item in reservations
                    if item.id in preexisting_reservation_ids
                ]
                reservations, reservation_expiry = await _cohere_reservations(
                    session=self._session,
                    reservations=reservations,
                    existing_reservations=existing_reservations,
                    by_id=by_id,
                    server_deadline=server_deadline,
                )
                if not reservations or reservation_expiry <= now:
                    raise RelayAccessError(
                        "relay_capacity_unavailable", 503, "relay capacity unavailable"
                    )
                await self._session.flush()
                selection_order = {
                    item.node_id: index for index, item in enumerate(reservations)
                }
                reservation_by_node = {item.node_id: item for item in reservations}
                signed_candidates: list[RelayDirectoryCandidateOut] = []
                for node_id in sorted(
                    reservation_by_node, key=lambda value: value.encode("utf-8")
                ):
                    node, registration, view = by_id[node_id]
                    selected = next(
                        item for item in ordered_candidates if item.node_id == node_id
                    )
                    endpoints = sorted(
                        (endpoint_parts(url) for url in selected.endpoints),
                        key=lambda item: (
                            {"udp": 1, "tcp": 2, "tls": 3}[item[0]],
                            item[1].encode(),
                            item[2],
                        ),
                    )
                    signed_candidates.append(
                        RelayDirectoryCandidateOut(
                            node_id=node_id,
                            region=node.region,
                            failure_domain=node.failure_domain,
                            endpoints=[
                                RelayDirectoryEndpointOut(
                                    transport=transport, host=host, port=port
                                )
                                for transport, host, port in endpoints
                            ],
                            capabilities=_capabilities(selected.endpoints),
                            load_class=_load_class(view),
                            selection_reason=(
                                "preferred-region"
                                if selection_order[node_id] == 0
                                else "failure-domain-backup"
                            ),
                            reservation=RelayReservationOut(
                                reservation_id=reservation_by_node[node_id].id,
                                expires_at_ms=_unix_ms(
                                    reservation_by_node[node_id].expires_at
                                ),
                            ),
                        )
                    )
                payload = RelayDirectoryPayloadOut(
                    format_version=1,
                    policy_revision=grant.policy_revision,
                    directory_id=directory_id,
                    issued_at_ms=_unix_ms(now),
                    expires_at_ms=_unix_ms(reservation_expiry),
                    session_id=grant.id,
                    intended_peer_digest=intended_peer_digest(grant.intended_peer_id),
                    candidates=signed_candidates,
                )
                try:
                    directory = self._signer.sign(payload)
                except Exception:
                    raise RelayAccessError(
                        "relay_signing_unavailable", 503, "relay access unavailable"
                    ) from None
                credentials: list[NodeTurnCredential] = []
                for candidate in signed_candidates:
                    node, registration, _ = by_id[candidate.node_id]
                    try:
                        issued_credential = self._credential_issuer.issue(
                            user_id=current_user_id,
                            session_id=grant.id,
                            node_id=node.node_id,
                            urls=sorted(
                                (
                                    url
                                    for url in node.endpoints
                                    if endpoint_transport(url)
                                    in policy.accepted_transports
                                ),
                                key=lambda url: (
                                    {"udp": 1, "tcp": 2, "tls": 3}[
                                        endpoint_parts(url)[0]
                                    ],
                                    endpoint_parts(url)[1].encode("utf-8"),
                                    endpoint_parts(url)[2],
                                ),
                            ),
                            encrypted_secret=bytes(node.encrypted_turn_secret),
                            grant_deadline_unix_seconds=_unix_seconds(
                                grant.grant_expires_at
                            ),
                            directory_deadline_unix_seconds=_unix_seconds(
                                reservation_expiry
                            ),
                            policy_deadline_unix_seconds=_unix_seconds(
                                grant.policy_expires_at
                            ),
                            node_deadline_unix_seconds=_unix_seconds(
                                min(
                                    _utc(registration.certificate_expires_at),
                                    _utc(node.lease_expires_at),
                                )
                            ),
                        )
                    except Exception:
                        raise RelayAccessError(
                            "relay_credential_unavailable",
                            503,
                            "relay access unavailable",
                        ) from None
                    if issued_credential.reencrypted_secret is not None:
                        # The repository locked/revalidated both rows during
                        # admission; rotate their envelope in this same issuance
                        # transaction without ever materializing a string secret.
                        node.encrypted_turn_secret = (
                            issued_credential.reencrypted_secret
                        )
                        registration.encrypted_turn_secret = (
                            issued_credential.reencrypted_secret
                        )
                    credentials.append(issued_credential)
                for candidate in signed_candidates:
                    self._session.add(
                        RelayAuditEvent(
                            action="relay_access_issued",
                            node_id=candidate.node_id,
                            actor_id=current_user_id,
                            details={
                                "policy_revision": grant.policy_revision,
                                "selection_reason": candidate.selection_reason,
                            },
                            created_at=now,
                        )
                    )
                await self._session.flush()
                return RelayAccessResult(
                    directory=directory, credentials=tuple(credentials)
                )
        except RelayAccessError as error:
            if error.code == "relay_capacity_unavailable":
                await self._audit_capacity_rejection(now)
            raise
        except RelayRepositoryError as error:
            if error.code in {
                "INVALID_SESSION_ID",
                "INVALID_USER_ID",
                "SESSION_OWNER_MISMATCH",
            }:
                _deny_access()
            await self._audit_capacity_rejection(now)
            raise RelayAccessError(
                "relay_capacity_unavailable", 503, "relay capacity unavailable"
            ) from None

    async def _audit_capacity_rejection(self, now: datetime) -> None:
        """Record a label-free rejection after the issuance transaction rolls back."""

        try:
            async with self._session.begin():
                self._session.add(
                    RelayAuditEvent(
                        action="relay_capacity_rejected",
                        node_id=None,
                        actor_id=None,
                        details={},
                        created_at=now,
                    )
                )
                await self._session.flush()
        except Exception:
            # Audit storage must not turn a stable non-enumerating capacity result
            # into a database traceback. No request identifiers are logged here.
            return


async def _cohere_reservations(
    *,
    session: object,
    reservations: list[RelayReservation],
    existing_reservations: list[RelayReservation],
    by_id: dict[str, tuple[RelayNode, RelayNodeRegistration, RelayNodeView]],
    server_deadline: datetime,
) -> tuple[list[RelayReservation], datetime]:
    """Make a v1-coherent set without invalidating already-issued credentials."""

    if not existing_reservations:
        raw_deadline = min(
            server_deadline,
            *(_utc(item.expires_at) for item in reservations),
            *(_node_deadline(item.node_id, by_id) for item in reservations),
        )
        # PostgreSQL and certificate sources preserve microseconds while TURN
        # REST usernames carry whole Unix seconds. Floor the *final* minimum so
        # the row, signed directory and credential all expire at one instant.
        deadline = datetime.fromtimestamp(int(raw_deadline.timestamp()), tz=UTC)
        for reservation in reservations:
            if _utc(reservation.expires_at) > deadline:
                reservation.expires_at = deadline
        return reservations, deadline

    existing_expiries = {
        _utc(reservation.expires_at) for reservation in existing_reservations
    }
    if len(existing_expiries) != 1:
        raise RelayAccessError(
            "relay_capacity_unavailable", 503, "relay capacity unavailable"
        )
    deadline = next(iter(existing_expiries))
    if deadline > server_deadline or any(
        _node_deadline(item.node_id, by_id) < deadline for item in existing_reservations
    ):
        raise RelayAccessError(
            "relay_capacity_unavailable", 503, "relay capacity unavailable"
        )

    existing_ids = {item.id for item in existing_reservations}
    kept: list[RelayReservation] = []
    for reservation in reservations:
        if reservation.id in existing_ids:
            kept.append(reservation)
            continue
        if (
            _utc(reservation.expires_at) >= deadline
            and _node_deadline(reservation.node_id, by_id) >= deadline
        ):
            reservation.expires_at = deadline
            kept.append(reservation)
        else:
            await session.delete(reservation)
    return kept, deadline


def _node_deadline(
    node_id: str,
    by_id: dict[str, tuple[RelayNode, RelayNodeRegistration, RelayNodeView]],
) -> datetime:
    node, registration, _ = by_id[node_id]
    return min(
        _utc(registration.certificate_expires_at),
        _utc(node.lease_expires_at),
    )


def select_relay_nodes(
    policy: RelaySelectionPolicy,
    nodes: Iterable[RelayNodeView],
    *,
    now: datetime,
) -> RelaySelectionDecision:
    now = _utc(now)
    candidates: list[RelaySelectedNode] = []
    rejections: list[RelayRejection] = []
    for node in nodes:
        compatible = tuple(
            endpoint
            for endpoint in node.endpoints
            if endpoint_transport(endpoint) in policy.accepted_transports
        )
        reason = _rejection_reason(policy, node, compatible, now)
        if reason is not None:
            rejections.append(RelayRejection(node.node_id, reason))
            continue
        candidates.append(
            RelaySelectedNode(
                node_id=node.node_id,
                region=node.region,
                failure_domain=node.failure_domain,
                physical_host_id=node.physical_host_id,
                endpoints=compatible,
                score=_score(policy, node),
            )
        )
    candidates.sort(key=lambda item: (-item.score, item.node_id.encode("utf-8")))
    rejections.sort(key=lambda item: (item.node_id.encode("utf-8"), item.code))

    selected: list[RelaySelectedNode] = []
    used_domains: set[str] = set()
    used_physical_hosts: set[str] = set()
    for candidate in candidates:
        if (
            candidate.failure_domain in used_domains
            or candidate.physical_host_id in used_physical_hosts
        ):
            continue
        reason = "preferred-region" if not selected else "failure-domain-backup"
        selected.append(replace(candidate, selection_reason=reason))
        used_domains.add(candidate.failure_domain)
        used_physical_hosts.add(candidate.physical_host_id)
        if len(selected) >= 1 + max(0, min(policy.max_backups, 7)):
            break
    return RelaySelectionDecision(
        selected=tuple(selected),
        eligible=tuple(candidates),
        rejections=tuple(rejections),
    )


def authorize_relay_grant(
    *,
    grant: object,
    target_device: object,
    requester_user: object,
    target_owner: object,
    current_user: object,
    current_user_id: str,
    requested_policy_revision: int,
    requested_peer_id: str,
    now: datetime,
    current_policy: SessionGrantPolicy,
) -> None:
    """Validate a row-locked grant without revealing which binding failed."""

    now = _utc(now)
    grant_expiry = getattr(grant, "grant_expires_at", None)
    policy_expiry = getattr(grant, "policy_expires_at", None)
    tenant_id = getattr(grant, "tenant_id", None)
    requester_id = getattr(grant, "requester_user_id", None)
    owner_id = getattr(target_device, "bound_user_id", None)
    participant = current_user_id in {requester_id, owner_id}
    valid = (
        participant
        and getattr(grant, "requester_device_id", None) is None
        and requester_id != owner_id
        and getattr(current_user, "id", None) == current_user_id
        and getattr(requester_user, "id", None) == requester_id
        and getattr(target_owner, "id", None) == owner_id
        and isinstance(tenant_id, str)
        and _CREDENTIAL_SCOPE.fullmatch(tenant_id) is not None
        and getattr(current_user, "tenant_id", None) == tenant_id
        and getattr(requester_user, "tenant_id", None) == tenant_id
        and getattr(target_owner, "tenant_id", None) == tenant_id
        and getattr(target_device, "tenant_id", None) == tenant_id
        and getattr(target_device, "id", None)
        == getattr(grant, "target_device_id", None)
        and getattr(grant, "intended_peer_id", None)
        == getattr(target_device, "id", None)
        and getattr(grant, "status", None) == "approved"
        and isinstance(grant_expiry, datetime)
        and _utc(grant_expiry) > now
        and isinstance(policy_expiry, datetime)
        and _utc(policy_expiry) > now
        and isinstance(requested_policy_revision, int)
        and not isinstance(requested_policy_revision, bool)
        and requested_policy_revision > 0
        and requested_policy_revision == getattr(grant, "policy_revision", None)
        and requested_peer_id == getattr(grant, "intended_peer_id", None)
        and _grant_conforms_to_current_policy(
            grant=grant,
            current_policy=current_policy,
            requested_policy_revision=requested_policy_revision,
            now=now,
        )
    )
    if not valid:
        raise RelayAccessError("relay_access_denied", 403, "relay access denied")


def _grant_conforms_to_current_policy(
    *,
    grant: object,
    current_policy: SessionGrantPolicy,
    requested_policy_revision: int,
    now: datetime,
) -> bool:
    try:
        validate_session_grant_policy(current_policy)
    except (SessionGrantError, AttributeError, TypeError):
        return False
    grant_expiry = getattr(grant, "grant_expires_at", None)
    policy_expiry = getattr(grant, "policy_expires_at", None)
    if not isinstance(grant_expiry, datetime) or not isinstance(
        policy_expiry, datetime
    ):
        return False
    grant_deadline = _utc(grant_expiry)
    policy_deadline = _utc(policy_expiry)
    return (
        requested_policy_revision
        == getattr(grant, "policy_revision", None)
        == current_policy.revision
        and getattr(grant, "relay_allowed_regions", None)
        == list(current_policy.allowed_regions)
        and getattr(grant, "relay_preferred_regions", None)
        == list(current_policy.preferred_regions)
        and getattr(grant, "relay_accepted_transports", None)
        == list(current_policy.accepted_transports)
        and policy_deadline <= grant_deadline
        and grant_deadline <= now + timedelta(seconds=current_policy.grant_ttl_seconds)
        and policy_deadline
        <= now + timedelta(seconds=current_policy.policy_ttl_seconds)
    )


def intended_peer_digest(peer_id: str) -> str:
    digest = hashlib.sha256(
        b"MRD_RELAY_PEER_V1\x00" + peer_id.encode("utf-8")
    ).hexdigest()
    return f"peer-sha256-{digest}"


def relay_url_digest(urls: Iterable[str]) -> str:
    canonical = sorted(urls, key=lambda value: value.encode("utf-8"))
    digest = hashlib.sha256(b"MRD_RELAY_URLS_V1\x00")
    for url in canonical:
        encoded = url.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _canonical_endpoint_url(endpoint: RelayDirectoryEndpointOut) -> str:
    host = _signed_endpoint_host(endpoint.host)
    authority = f"[{host}]" if ":" in host else host
    if endpoint.transport == "tls":
        return f"turns:{authority}:{endpoint.port}?transport=tcp"
    return f"turn:{authority}:{endpoint.port}?transport={endpoint.transport}"


def _signed_endpoint_host(host: str) -> str:
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


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


def _wan_request_binding_valid(
    *, grant: SessionRequest, controller: Device, target: Device
) -> bool:
    payload = grant.request_payload
    if not isinstance(payload, dict):
        return False
    try:
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError):
        return False
    commitment = hashlib.sha256(
        b"MRD_WAN_SESSION_REQUEST_V3\x00" + canonical
    ).hexdigest()
    return (
        payload.get("session_id") == grant.id
        and payload.get("controller_device_id") == controller.device_id
        and payload.get("target_device_id") == target.device_id
        and payload.get("access_mode") == "attended"
        and payload.get("route_policy") == "relay_only"
        and payload.get("requested_scopes") == grant.requested_scopes
        and payload.get("requested_profile") == grant.requested_profile
        and grant.request_commitment == commitment
    )


def new_directory_id() -> str:
    return "directory-" + secrets.token_hex(16)


def endpoint_transport(endpoint: str) -> str | None:
    matched = _ENDPOINT.fullmatch(endpoint)
    if matched is None or not 1 <= int(matched.group("port")) <= 65_535:
        return None
    scheme = matched.group("scheme").lower()
    transport = (matched.group("transport") or "").lower()
    if scheme == "turns":
        return "tls" if transport in {"", "tcp"} else None
    return transport or "udp"


def endpoint_parts(endpoint: str) -> tuple[str, str, int]:
    matched = _ENDPOINT.fullmatch(endpoint)
    transport = endpoint_transport(endpoint)
    if matched is None or transport is None:
        raise ValueError("relay endpoint is invalid")
    host = matched.group("host").lower()
    return transport, host, int(matched.group("port"))


def _policy_from_grant(grant: SessionRequest) -> RelaySelectionPolicy:
    allowed = _bounded_string_tuple(grant.relay_allowed_regions, {"region"})
    preferred = _bounded_string_tuple(grant.relay_preferred_regions, {"region"})
    accepted = _bounded_string_tuple(
        grant.relay_accepted_transports, {"udp", "tcp", "tls"}
    )
    if (
        not allowed
        or not preferred
        or not accepted
        or any(region not in allowed for region in preferred)
        or grant.policy_revision is None
        or grant.policy_revision <= 0
    ):
        _deny_access()
    return RelaySelectionPolicy(
        revision=grant.policy_revision,
        allowed_regions=allowed,
        preferred_regions=preferred,
        accepted_transports=accepted,
        max_backups=1,
    )


def _bounded_string_tuple(value: object, allowed_values: set[str]) -> tuple[str, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 8:
        return ()
    if any(
        not isinstance(item, str)
        or not item
        or len(item) > 64
        or (allowed_values != {"region"} and item not in allowed_values)
        for item in value
    ):
        return ()
    return tuple(dict.fromkeys(value))


def _view(node: RelayNode, registration: RelayNodeRegistration) -> RelayNodeView:
    return RelayNodeView(
        node_id=node.node_id,
        region=node.region,
        failure_domain=node.failure_domain,
        physical_host_id=node.physical_host_id,
        topology_approved=(
            registration.topology_approved_at is not None
            and registration.physical_host_id is not None
            and registration.physical_host_id == node.physical_host_id
            and registration.failure_domain == node.failure_domain
        ),
        state=node.state,
        lease_expires_at=node.lease_expires_at,
        revoked_at=node.revoked_at,
        registration_status=registration.status,
        certificate_expires_at=registration.certificate_expires_at,
        endpoints=tuple(node.endpoints),
        active_allocations=node.active_allocations,
        max_allocations=node.max_allocations,
        current_egress_bps=node.current_egress_bps,
        max_egress_bps=node.max_egress_bps,
        measured_rtt_ms=getattr(node, "measured_rtt_ms", None),
        recent_failure_bps=getattr(node, "recent_failure_bps", 0),
    )


def _distinct_domain_candidates(
    candidates: tuple[RelaySelectedNode, ...],
) -> tuple[RelaySelectedNode, ...]:
    selected: list[RelaySelectedNode] = []
    domains: set[str] = set()
    physical_hosts: set[str] = set()
    for candidate in candidates:
        if (
            candidate.failure_domain in domains
            or candidate.physical_host_id in physical_hosts
        ):
            continue
        domains.add(candidate.failure_domain)
        physical_hosts.add(candidate.physical_host_id)
        selected.append(candidate)
        if len(selected) >= 8:
            break
    return tuple(selected)


def _capabilities(endpoints: tuple[str, ...]) -> int:
    bits = {"udp": 1, "tcp": 2, "tls": 4}
    result = 0
    for endpoint in endpoints:
        transport = endpoint_transport(endpoint)
        if transport is not None:
            result |= bits[transport]
    return result


def _endpoint_hosts(endpoints: tuple[str, ...]) -> set[str]:
    return {endpoint_parts(endpoint)[1] for endpoint in endpoints}


def _load_class(node: RelayNodeView) -> int:
    utilization = max(
        _ratio_bps(node.active_allocations, node.max_allocations),
        _ratio_bps(node.current_egress_bps, node.max_egress_bps),
    )
    if utilization < 5_000:
        return 0
    if utilization < 7_500:
        return 1
    if utilization < 9_000:
        return 2
    return 3


def _unix_ms(value: datetime) -> int:
    return int(_utc(value).timestamp() * 1_000)


def _unix_seconds(value: datetime) -> int:
    return int(_utc(value).timestamp())


def _deny_access() -> NoReturn:
    raise RelayAccessError("relay_access_denied", 403, "relay access denied")


@asynccontextmanager
async def _issuance_transaction(session: object):
    """Own the cached request transaction already opened by JWT user lookup."""

    in_transaction = getattr(session, "in_transaction", lambda: False)()
    if not in_transaction:
        async with session.begin():
            yield
        return
    try:
        yield
    except BaseException:
        await session.rollback()
        raise
    else:
        await session.commit()


def _rejection_reason(
    policy: RelaySelectionPolicy,
    node: RelayNodeView,
    compatible: tuple[str, ...],
    now: datetime,
) -> str | None:
    if node.revoked_at is not None or node.state == "revoked":
        return "revoked"
    if node.registration_status != "approved":
        return "certificate_unapproved"
    if not node.topology_approved or node.physical_host_id is None:
        return "topology_unapproved"
    if node.certificate_expires_at is None or _utc(node.certificate_expires_at) <= now:
        return "certificate_expired"
    if node.lease_expires_at is None or _utc(node.lease_expires_at) <= now:
        return "stale_lease"
    if node.state == "draining":
        return "draining"
    if node.state not in {"available", "degraded"}:
        return "unavailable"
    if _CREDENTIAL_SCOPE.fullmatch(node.node_id) is None:
        return "credential_scope_incompatible"
    if node.region not in policy.allowed_regions:
        return "region_disallowed"
    if not compatible:
        return "transport_incompatible"
    if (
        node.max_allocations <= 0
        or node.active_allocations < 0
        or node.active_allocations >= node.max_allocations
        or node.max_egress_bps <= 0
        or node.current_egress_bps < 0
        or node.current_egress_bps >= node.max_egress_bps
    ):
        return "hard_capacity_reached"
    return None


def _score(policy: RelaySelectionPolicy, node: RelayNodeView) -> int:
    allocation_bps = _ratio_bps(node.active_allocations, node.max_allocations)
    bandwidth_bps = _ratio_bps(node.current_egress_bps, node.max_egress_bps)
    bandwidth_headroom = max(0, _BASIS_POINTS - bandwidth_bps)
    try:
        region_index = policy.preferred_regions.index(node.region)
    except ValueError:
        region_reward = 0
    else:
        rank = len(policy.preferred_regions) - region_index
        region_reward = _saturating_multiply(rank, policy.weights.region_preference)
    rewards = _saturating_add(
        _saturating_add(policy.weights.base_score, region_reward),
        _weighted_bps(bandwidth_headroom, policy.weights.bandwidth_headroom_reward),
    )
    rtt = (
        _UNKNOWN_RTT_MS
        if node.measured_rtt_ms is None
        else min(_UNKNOWN_RTT_MS, max(0, node.measured_rtt_ms))
    )
    penalties = _saturating_add(
        _saturating_add(
            _saturating_multiply(rtt, policy.weights.rtt_penalty_per_ms),
            _weighted_bps(
                allocation_bps, policy.weights.allocation_utilization_penalty
            ),
        ),
        _weighted_bps(
            min(_BASIS_POINTS, max(0, node.recent_failure_bps)),
            policy.weights.recent_failure_penalty,
        ),
    )
    if allocation_bps >= policy.soft_allocation_limit_bps:
        penalties = _saturating_add(penalties, policy.weights.soft_full_penalty)
    if node.state == "degraded":
        penalties = _saturating_add(penalties, policy.weights.degraded_penalty)
    return max(0, rewards - penalties)


def _ratio_bps(current: int, maximum: int) -> int:
    if maximum <= 0:
        return _BASIS_POINTS
    return min(max(current, 0), maximum) * _BASIS_POINTS // maximum


def _weighted_bps(value_bps: int, weight: int) -> int:
    return min(
        _U64_MAX,
        max(0, value_bps) * min(_U64_MAX, max(0, weight)) // _BASIS_POINTS,
    )


def _saturating_add(left: int, right: int) -> int:
    return min(_U64_MAX, max(0, left) + max(0, right))


def _saturating_multiply(left: int, right: int) -> int:
    return min(_U64_MAX, max(0, left) * max(0, right))


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
