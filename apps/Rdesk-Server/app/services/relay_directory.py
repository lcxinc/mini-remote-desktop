from __future__ import annotations

import hashlib
import re
import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Callable, Iterable, NoReturn, Protocol

from sqlalchemy import select

from app.models.device import Device
from app.models.relay_audit_event import RelayAuditEvent
from app.models.relay_node import RelayNode
from app.models.relay_node_registration import RelayNodeRegistration
from app.models.relay_reservation import RelayReservation
from app.models.session_request import SessionRequest
from app.services.relay_repository import RelayRepository, RelayRepositoryError
from app.services.relay_signing import (
    RelayDirectoryCandidateOut,
    RelayDirectoryEndpointOut,
    RelayDirectoryPayloadOut,
    RelayReservationOut,
    SignedRelayDirectoryOut,
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
    credentials: tuple[NodeTurnCredential, ...]


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
        directory_ttl_seconds: int = 30,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not 1 <= directory_ttl_seconds <= 300:
            raise ValueError("relay directory TTL must be between 1 and 300 seconds")
        self._session = session
        self._repository = repository
        self._signer = signer
        self._credential_issuer = credential_issuer
        self._directory_ttl_seconds = directory_ttl_seconds
        self._now = now or (lambda: datetime.now(UTC))

    async def issue_access(
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
                grant = await self._session.scalar(
                    select(SessionRequest)
                    .where(SessionRequest.id == session_id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
                if grant is None:
                    _deny_access()
                target_device = await self._session.scalar(
                    select(Device)
                    .where(Device.id == grant.target_device_id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
                if target_device is None:
                    _deny_access()
                authorize_relay_grant(
                    grant=grant,
                    target_device=target_device,
                    current_user_id=current_user_id,
                    requested_policy_revision=policy_revision,
                    requested_peer_id=intended_peer_id,
                    now=now,
                )
                policy = _policy_from_grant(grant)
                rows = await self._session.execute(
                    select(RelayNode, RelayNodeRegistration)
                    .join(
                        RelayNodeRegistration,
                        RelayNodeRegistration.node_id == RelayNode.node_id,
                    )
                    .order_by(RelayNode.node_id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
                records = list(rows.all())
                views = [_view(node, registration) for node, registration in records]
                decision = select_relay_nodes(policy, views, now=now)
                by_id = {
                    node.node_id: (node, registration, view)
                    for (node, registration), view in zip(records, views, strict=True)
                }
                ordered_candidates = _distinct_domain_candidates(decision.eligible)
                if not ordered_candidates:
                    raise RelayAccessError(
                        "relay_capacity_unavailable", 503, "relay capacity unavailable"
                    )
                server_deadline = min(
                    now + timedelta(seconds=self._directory_ttl_seconds),
                    _utc(grant.grant_expires_at),
                    _utc(grant.policy_expires_at),
                )
                reservation_ttl = int((server_deadline - now).total_seconds())
                if reservation_ttl <= 0:
                    _deny_access()
                preexisting_reservation_ids = set(
                    (
                        await self._session.scalars(
                            select(RelayReservation.id)
                            .where(
                                RelayReservation.session_id == session_id,
                                RelayReservation.expires_at > now,
                            )
                            .with_for_update()
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
                                expires_at_ms=_unix_ms(reservation_by_node[node_id].expires_at),
                            ),
                        )
                    )
                payload = RelayDirectoryPayloadOut(
                    format_version=1,
                    policy_revision=grant.policy_revision,
                    directory_id=new_directory_id(),
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
                            grant_deadline_unix_seconds=_unix_seconds(grant.grant_expires_at),
                            directory_deadline_unix_seconds=_unix_seconds(reservation_expiry),
                            policy_deadline_unix_seconds=_unix_seconds(grant.policy_expires_at),
                            node_deadline_unix_seconds=_unix_seconds(
                                min(
                                    _utc(registration.certificate_expires_at),
                                    _utc(node.lease_expires_at),
                                )
                            ),
                        )
                    except Exception:
                        raise RelayAccessError(
                            "relay_credential_unavailable", 503, "relay access unavailable"
                        ) from None
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
                return RelayAccessResult(directory=directory, credentials=tuple(credentials))
        except RelayAccessError as error:
            if error.code == "relay_capacity_unavailable":
                await self._audit_capacity_rejection(now)
            raise
        except RelayRepositoryError as error:
            if error.code in {
                "INVALID_SESSION_ID", "INVALID_USER_ID", "SESSION_OWNER_MISMATCH"
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
    by_id: dict[
        str, tuple[RelayNode, RelayNodeRegistration, RelayNodeView]
    ],
    server_deadline: datetime,
) -> tuple[list[RelayReservation], datetime]:
    """Make a v1-coherent set without invalidating already-issued credentials."""

    if not existing_reservations:
        deadline = min(
            server_deadline,
            *(_utc(item.expires_at) for item in reservations),
            *(_node_deadline(item.node_id, by_id) for item in reservations),
        )
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
        _node_deadline(item.node_id, by_id) < deadline
        for item in existing_reservations
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
            endpoint for endpoint in node.endpoints
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
                endpoints=compatible,
                score=_score(policy, node),
            )
        )
    candidates.sort(key=lambda item: (-item.score, item.node_id.encode("utf-8")))
    rejections.sort(key=lambda item: (item.node_id.encode("utf-8"), item.code))

    selected: list[RelaySelectedNode] = []
    used_domains: set[str] = set()
    used_hosts: set[str] = set()
    for candidate in candidates:
        candidate_hosts = _endpoint_hosts(candidate.endpoints)
        if (
            candidate.failure_domain in used_domains
            or not candidate_hosts.isdisjoint(used_hosts)
        ):
            continue
        reason = "preferred-region" if not selected else "failure-domain-backup"
        selected.append(replace(candidate, selection_reason=reason))
        used_domains.add(candidate.failure_domain)
        used_hosts.update(candidate_hosts)
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
    current_user_id: str,
    requested_policy_revision: int,
    requested_peer_id: str,
    now: datetime,
) -> None:
    """Validate a row-locked grant without revealing which binding failed."""

    now = _utc(now)
    grant_expiry = getattr(grant, "grant_expires_at", None)
    policy_expiry = getattr(grant, "policy_expires_at", None)
    participant = current_user_id == getattr(grant, "requester_user_id", None) or (
        bool(getattr(target_device, "is_bound", False))
        and current_user_id == getattr(target_device, "bound_user_id", None)
    )
    valid = (
        participant
        and getattr(target_device, "id", None) == getattr(grant, "target_device_id", None)
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
    )
    if not valid:
        raise RelayAccessError("relay_access_denied", 403, "relay access denied")


def intended_peer_digest(peer_id: str) -> str:
    digest = hashlib.sha256(b"MRD_RELAY_PEER_V1\x00" + peer_id.encode("utf-8")).hexdigest()
    return f"peer-sha256-{digest}"


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
    hosts: set[str] = set()
    for candidate in candidates:
        candidate_hosts = _endpoint_hosts(candidate.endpoints)
        if (
            candidate.failure_domain in domains
            or not candidate_hosts.isdisjoint(hosts)
        ):
            continue
        domains.add(candidate.failure_domain)
        hosts.update(candidate_hosts)
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
        region_reward = _saturating_multiply(
            rank, policy.weights.region_preference
        )
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
