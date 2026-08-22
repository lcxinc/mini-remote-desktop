from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.v1.relays import (
    RelayAccessResponse,
    get_relay_access_service,
    router,
)
from app.core.security import get_current_user
from app.core.config import settings
from app.services.relay_directory import (
    RelayAccessError,
    RelayAccessService,
    RelayNodeView,
    RelayScoreWeights,
    RelaySelectionPolicy,
    authorize_relay_grant,
    select_relay_nodes,
)
from app.db.session import Base
from app.models.device import Device
from app.models.relay_enrollment import RelayEnrollment
from app.models.relay_audit_event import RelayAuditEvent
from app.models.relay_node import RelayNode
from app.models.relay_node_registration import RelayNodeRegistration
from app.models.relay_reservation import RelayReservation
from app.models.session_request import SessionRequest
from app.models.user import User
from app.schemas.relay import RelayEnrollmentRequest
from app.services.relay_repository import AesGcmRelaySecretCipher, RelayRepository
from app.services.relay_signing import Ed25519RelayDirectorySigner
from app.services.turn_credentials import NodeTurnCredentialService


NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)


def node(
    node_id: str,
    *, region: str = "ap-east", domain: str | None = None,
    state: str = "available", lease_delta: int = 15,
    registration_status: str = "approved", certificate_delta: int = 3600,
    endpoints: tuple[str, ...] | None = None,
    active: int = 1, maximum: int = 10,
    current_egress: int = 100, max_egress: int = 1000,
    rtt_ms: int | None = 20, recent_failure_bps: int = 0,
) -> RelayNodeView:
    return RelayNodeView(
        node_id=node_id, region=region, failure_domain=domain or f"rack-{node_id}",
        state=state, lease_expires_at=NOW + timedelta(seconds=lease_delta),
        revoked_at=NOW if state == "revoked" else None,
        registration_status=registration_status,
        certificate_expires_at=NOW + timedelta(seconds=certificate_delta),
        endpoints=(
            endpoints
            if endpoints is not None
            else (f"turn:{node_id}.relay.test:3478?transport=udp",)
        ),
        active_allocations=active, max_allocations=maximum,
        current_egress_bps=current_egress, max_egress_bps=max_egress,
        measured_rtt_ms=rtt_ms, recent_failure_bps=recent_failure_bps,
    )


POLICY = RelaySelectionPolicy(
    revision=17,
    allowed_regions=("ap-east", "eu-west"),
    preferred_regions=("ap-east", "eu-west"),
    accepted_transports=("udp", "tcp", "tls"),
    max_backups=1,
)


@pytest.mark.parametrize(
    ("candidate", "reason"),
    [
        (node("revoked", state="revoked"), "revoked"),
        (node("draining", state="draining"), "draining"),
        (node("unavailable", state="unavailable"), "unavailable"),
        (node("stale", lease_delta=0), "stale_lease"),
        (node("pending", registration_status="pending"), "certificate_unapproved"),
        (node("expired-cert", certificate_delta=0), "certificate_expired"),
        (node("wrong-region", region="us-west"), "region_disallowed"),
        (
            node("protocol", endpoints=("turns:relay.test:5349?transport=tcp",)),
            "transport_incompatible",
        ),
        (node("alloc-full", active=10, maximum=10), "hard_capacity_reached"),
        (
            node("egress-full", current_egress=1000, max_egress=1000),
            "hard_capacity_reached",
        ),
    ],
)
def test_hard_filters_use_stable_rejection_codes(candidate: RelayNodeView, reason: str):
    policy = POLICY
    if candidate.node_id == "protocol":
        policy = RelaySelectionPolicy(
            revision=17, allowed_regions=("ap-east",), preferred_regions=("ap-east",),
            accepted_transports=("udp",), max_backups=1,
        )
    decision = select_relay_nodes(policy, [candidate], now=NOW)
    assert decision.selected == ()
    assert [(item.node_id, item.code) for item in decision.rejections] == [
        (candidate.node_id, reason)
    ]


def test_integer_score_penalizes_soft_full_degraded_rtt_and_recent_failure():
    healthy = node("healthy")
    candidates = [
        node("soft", active=9, maximum=10), node("degraded", state="degraded"),
        node("slow", rtt_ms=500), node("failing", recent_failure_bps=9000),
        node("bandwidth", current_egress=900, max_egress=1000), healthy,
    ]
    decision = select_relay_nodes(
        RelaySelectionPolicy(
            revision=17, allowed_regions=("ap-east",), preferred_regions=("ap-east",),
            accepted_transports=("udp",), max_backups=8,
        ), candidates, now=NOW,
    )
    scores = {candidate.node_id: candidate.score for candidate in decision.eligible}
    assert scores["healthy"] > scores["soft"]
    assert scores["healthy"] > scores["degraded"]
    assert scores["healthy"] > scores["slow"]
    assert scores["healthy"] > scores["failing"]
    assert scores["healthy"] > scores["bandwidth"]
    assert all(isinstance(score, int) for score in scores.values())


def test_selection_prefers_region_then_stable_node_id_and_distinct_failure_domain():
    candidates = [
        node("relay-b", domain="rack-a"), node("relay-a", domain="rack-a"),
        node("relay-c", region="eu-west", domain="rack-c"),
        node("relay-d", region="eu-west", domain="rack-d", rtt_ms=200),
    ]
    decision = select_relay_nodes(POLICY, candidates, now=NOW)
    assert [item.node_id for item in decision.selected] == ["relay-a", "relay-c"]
    assert decision.selected[0].selection_reason == "preferred-region"
    assert decision.selected[1].selection_reason == "failure-domain-backup"
    assert decision.selected[0].failure_domain != decision.selected[1].failure_domain


def test_different_ports_on_one_host_are_not_independent_backups():
    decision = select_relay_nodes(
        POLICY,
        [
            node(
                "relay-a",
                domain="claimed-rack-a",
                endpoints=("turn:shared.example.test:3478?transport=udp",),
            ),
            node(
                "relay-b",
                domain="claimed-rack-b",
                endpoints=("turn:shared.example.test:3479?transport=udp",),
            ),
        ],
        now=NOW,
    )
    assert [item.node_id for item in decision.selected] == ["relay-a"]


def test_legacy_colon_node_id_is_hard_filtered_before_credential_issuance():
    decision = select_relay_nodes(
        POLICY,
        [node("legacy:relay"), node("relay-safe")],
        now=NOW,
    )
    assert [item.node_id for item in decision.selected] == ["relay-safe"]
    assert [(item.node_id, item.code) for item in decision.rejections] == [
        ("legacy:relay", "credential_scope_incompatible")
    ]


def test_new_enrollment_forbids_turn_username_delimiters_in_node_id():
    with pytest.raises(ValidationError):
        RelayEnrollmentRequest(
            token=SecretStr("t" * 43),
            node_id="relay:hkg:1",
            region="ap-east",
            failure_domain="rack-a",
            endpoints=["turn:relay.example.test:3478?transport=udp"],
            max_allocations=10,
            max_egress_bps=1_000_000,
            csr_pem="x" * 100,
        )


@pytest.mark.parametrize(
    "change",
    [
        {"status": "requested"}, {"status": "rejected"},
        {"grant_expires_at": NOW}, {"policy_expires_at": NOW},
        {"policy_revision": 18}, {"intended_peer_id": "other-peer"},
    ],
)
def test_grant_authorization_fails_closed_without_enumerating_reason(change):
    values = {
        "id": "session-7", "requester_user_id": "user-42",
        "target_device_id": "device-7", "status": "approved",
        "grant_expires_at": NOW + timedelta(minutes=5), "policy_revision": 17,
        "policy_expires_at": NOW + timedelta(minutes=4),
        "intended_peer_id": "device-7",
    }
    values.update(change)
    grant = SimpleNamespace(**values)
    device = SimpleNamespace(id="device-7", bound_user_id="owner-9", is_bound=True)
    with pytest.raises(RelayAccessError) as error:
        authorize_relay_grant(
            grant=grant, target_device=device, current_user_id="user-42",
            requested_policy_revision=17, requested_peer_id="device-7", now=NOW,
        )
    assert error.value.code == "relay_access_denied"
    assert "session-7" not in str(error.value)
    assert "device-7" not in str(error.value)


def test_only_real_session_participants_are_authorized():
    grant = SimpleNamespace(
        id="session-7", requester_user_id="user-42", target_device_id="device-7",
        status="approved", grant_expires_at=NOW + timedelta(minutes=5),
        policy_revision=17, policy_expires_at=NOW + timedelta(minutes=4),
        intended_peer_id="device-7",
    )
    device = SimpleNamespace(id="device-7", bound_user_id="owner-9", is_bound=True)
    authorize_relay_grant(
        grant=grant, target_device=device, current_user_id="owner-9",
        requested_policy_revision=17, requested_peer_id="device-7", now=NOW,
    )
    with pytest.raises(RelayAccessError, match="denied"):
        authorize_relay_grant(
            grant=grant, target_device=device, current_user_id="attacker",
            requested_policy_revision=17, requested_peer_id="device-7", now=NOW,
        )


def test_stored_intended_peer_must_be_the_bound_target_device():
    grant = SimpleNamespace(
        id="session-7", requester_user_id="user-42", target_device_id="device-7",
        status="approved", grant_expires_at=NOW + timedelta(minutes=5),
        policy_revision=17, policy_expires_at=NOW + timedelta(minutes=4),
        intended_peer_id="unrelated-device",
    )
    device = SimpleNamespace(id="device-7", bound_user_id="owner-9", is_bound=True)
    with pytest.raises(RelayAccessError) as error:
        authorize_relay_grant(
            grant=grant, target_device=device, current_user_id="user-42",
            requested_policy_revision=17, requested_peer_id="unrelated-device", now=NOW,
        )
    assert error.value.code == "relay_access_denied"


def test_score_uses_rust_compatible_u64_saturation():
    maximum = 2**64 - 1
    policy = RelaySelectionPolicy(
        revision=17,
        allowed_regions=("ap-east",),
        preferred_regions=("ap-east",),
        accepted_transports=("udp",),
        weights=RelayScoreWeights(
            base_score=maximum,
            region_preference=maximum,
            rtt_penalty_per_ms=maximum,
            allocation_utilization_penalty=maximum,
            bandwidth_headroom_reward=maximum,
            recent_failure_penalty=maximum,
            soft_full_penalty=maximum,
            degraded_penalty=maximum,
        ),
    )
    decision = select_relay_nodes(
        policy,
        [node("relay-a", active=0, current_egress=0, rtt_ms=0)],
        now=NOW,
    )
    assert decision.selected[0].score == maximum


def test_public_access_response_and_openapi_expose_no_secret_configuration_fields():
    response_fields = RelayAccessResponse.model_fields
    assert set(response_fields) == {"directory", "credentials"}
    credential_model = response_fields["credentials"].annotation.__args__[0]
    assert set(credential_model.model_fields) == {
        "node_id", "urls", "username", "credential", "expires_at_unix_seconds",
    }
    test_app = FastAPI()
    test_app.include_router(router, prefix="/api/v1")
    operation = test_app.openapi()["paths"]["/api/v1/relays/access"]["post"]
    operation_text = str(operation).lower()
    assert "authorization" in operation_text or "bearer" in operation_text
    assert "private_key" not in operation_text
    assert "turn_secret" not in operation_text


def test_access_factory_fails_closed_without_explicit_signing_and_encryption_keys(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "relay_directory_signing_key_id", "active-key")
    monkeypatch.setattr(
        settings, "relay_directory_signing_private_key", SecretStr("")
    )
    monkeypatch.setattr(settings, "relay_turn_secret_encryption_key", SecretStr(""))
    monkeypatch.setattr(settings, "relay_enrollment_token_pepper", SecretStr("22" * 32))
    with pytest.raises(HTTPException) as error:
        get_relay_access_service(db=SimpleNamespace())
    assert error.value.status_code == 503
    assert error.value.detail["code"] == "relay_signing_unavailable"
    assert "private" not in str(error.value.detail).lower()


class AsyncSessionShim:
    def __init__(self, session: Session) -> None:
        self.session = session

    @property
    def bind(self):
        return self.session.get_bind()

    def add(self, value):
        self.session.add(value)

    async def scalar(self, *args, **kwargs):
        return self.session.scalar(*args, **kwargs)

    async def scalars(self, *args, **kwargs):
        return self.session.scalars(*args, **kwargs)

    async def execute(self, *args, **kwargs):
        return self.session.execute(*args, **kwargs)

    async def flush(self):
        self.session.flush()

    async def delete(self, value):
        self.session.delete(value)

    def in_transaction(self):
        return self.session.in_transaction()

    async def commit(self):
        self.session.commit()

    async def rollback(self):
        self.session.rollback()

    def begin(self):
        return AsyncTransaction(self.session)


class AsyncTransaction:
    def __init__(self, session: Session) -> None:
        self.transaction = session.begin()

    async def __aenter__(self):
        self.transaction.__enter__()
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return self.transaction.__exit__(exc_type, exc, traceback)


def relay_service_fixture():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine, expire_on_commit=False)
    cipher = AesGcmRelaySecretCipher(bytes.fromhex("11" * 32))
    requester = User(
        id="user-42", username="requester", email="requester@example.test",
        password_hash="unused", role="user",
    )
    owner = User(
        id="owner-9", username="owner", email="owner@example.test",
        password_hash="unused", role="user",
    )
    device = Device(
        id="device-7", name="target", device_id="device-public-7", os="linux",
        is_bound=True, bound_user_id=owner.id,
    )
    grant = SessionRequest(
        id="session-7", requester_user_id=requester.id, target_device_id=device.id,
        signaling_room="room-7", status="approved",
        grant_expires_at=NOW + timedelta(minutes=5), policy_revision=17,
        policy_expires_at=NOW + timedelta(minutes=4), intended_peer_id=device.id,
        relay_allowed_regions=["ap-east", "eu-west"],
        relay_preferred_regions=["ap-east", "eu-west"],
        relay_accepted_transports=["udp", "tcp", "tls"],
    )
    session.add_all([requester, owner, device, grant])
    for index, (node_id, region, domain) in enumerate(
        (("relay-a", "ap-east", "rack-a"), ("relay-b", "eu-west", "rack-b"))
    ):
        enrollment = RelayEnrollment(
            id=f"enrollment-{index}", token_digest=f"{index:064x}",
            expires_at=NOW + timedelta(hours=1), used_at=NOW,
            enrolled_node_id=node_id, created_at=NOW,
        )
        relay = RelayNode(
            node_id=node_id, region=region, failure_domain=domain, state="available",
            endpoints=[f"turn:{node_id}.example.test:3478?transport=udp"],
            certificate_fingerprint="sha256:" + f"{index + 1:064x}",
            encrypted_turn_secret=cipher.encrypt(
                f"{node_id}-unique-turn-secret".encode(), associated_data=node_id.encode()
            ),
            max_allocations=2, active_allocations=0,
            max_egress_bps=1_000_000, current_egress_bps=0,
            heartbeat_sequence=3, healthy_heartbeat_streak=3,
            lease_expires_at=NOW + timedelta(seconds=15), created_at=NOW, updated_at=NOW,
        )
        registration = RelayNodeRegistration(
            node_id=node_id, enrollment_id=enrollment.id, region=region,
            failure_domain=domain, endpoints=relay.endpoints, max_allocations=2,
            max_egress_bps=1_000_000, csr_pem=b"fixture", signing_public_key=b"1" * 32,
            status="approved", certificate_pem=b"fixture",
            certificate_expires_at=NOW + timedelta(hours=1), created_at=NOW,
            approved_at=NOW,
        )
        session.add_all([enrollment, relay, registration])
    session.commit()
    async_session = AsyncSessionShim(session)
    repository = RelayRepository(
        async_session, enrollment_token_pepper=bytes.fromhex("22" * 32),
        secret_cipher=cipher, max_reservations_per_session=2,
    )
    service = RelayAccessService(
        session=async_session, repository=repository,
        signer=Ed25519RelayDirectorySigner(
            key_id="test-key", private_key_seed=bytes([0x42]) * 32
        ),
        credential_issuer=NodeTurnCredentialService(
            cipher=cipher, ttl_seconds=600, now=lambda: int(NOW.timestamp())
        ),
        directory_ttl_seconds=30, now=lambda: NOW,
    )
    return engine, session, service


@pytest.mark.anyio
async def test_both_bound_participants_reuse_capacity_without_double_reserving():
    engine, session, service = relay_service_fixture()
    try:
        requester = await service.issue_access(
            current_user_id="user-42", session_id="session-7",
            policy_revision=17, intended_peer_id="device-7",
        )
        owner = await service.issue_access(
            current_user_id="owner-9", session_id="session-7",
            policy_revision=17, intended_peer_id="device-7",
        )
        assert [item.node_id for item in requester.credentials] == [
            item.node_id for item in requester.directory.payload.candidates
        ]
        assert [item.node_id for item in owner.credentials] == [
            item.node_id for item in owner.directory.payload.candidates
        ]
        assert session.scalar(select(func.count()).select_from(RelayReservation)) == 2
    finally:
        session.close()
        engine.dispose()


@pytest.mark.anyio
async def test_persisted_selection_metrics_drive_production_candidate_order():
    engine, session, service = relay_service_fixture()
    try:
        relay_a = session.get(RelayNode, "relay-a")
        relay_b = session.get(RelayNode, "relay-b")
        relay_a.measured_rtt_ms = 50_000
        relay_b.measured_rtt_ms = 1
        relay_a.recent_failure_bps = 10_000
        relay_b.recent_failure_bps = 0
        session.commit()
        result = await service.issue_access(
            current_user_id="user-42", session_id="session-7",
            policy_revision=17, intended_peer_id="device-7",
        )
        reasons = {
            item.node_id: item.selection_reason
            for item in result.directory.payload.candidates
        }
        assert reasons == {
            "relay-a": "failure-domain-backup",
            "relay-b": "preferred-region",
        }
    finally:
        session.close()
        engine.dispose()


@pytest.mark.anyio
async def test_authenticated_user_lookup_transaction_is_reused_for_atomic_issuance():
    engine, session, service = relay_service_fixture()
    try:
        # FastAPI caches get_db, so get_current_user has already auto-begun this
        # same session transaction before the access-service dependency runs.
        assert session.scalar(select(User).where(User.id == "user-42")) is not None
        assert session.in_transaction()
        result = await service.issue_access(
            current_user_id="user-42", session_id="session-7",
            policy_revision=17, intended_peer_id="device-7",
        )
        assert len(result.credentials) == 2
        assert not session.in_transaction()
        assert session.scalar(select(func.count()).select_from(RelayReservation)) == 2
    finally:
        session.close()
        engine.dispose()


@pytest.mark.anyio
async def test_mixed_existing_and_new_reservations_share_the_directory_deadline():
    engine, session, service = relay_service_fixture()
    try:
        session.add(
            RelayReservation(
                id="existing-reservation",
                session_id="session-7",
                user_id="user-42",
                node_id="relay-a",
                expires_at=NOW + timedelta(seconds=10),
                created_at=NOW,
            )
        )
        session.commit()
        result = await service.issue_access(
            current_user_id="user-42", session_id="session-7",
            policy_revision=17, intended_peer_id="device-7",
        )
        directory_expiry = result.directory.payload.expires_at_ms
        assert len(result.directory.payload.candidates) == 2
        assert {
            item.reservation.expires_at_ms
            for item in result.directory.payload.candidates
        } == {directory_expiry}
        stored_expiries = {
            value.replace(tzinfo=UTC) if value.tzinfo is None else value
            for value in session.scalars(select(RelayReservation.expires_at))
        }
        assert stored_expiries == {NOW + timedelta(seconds=10)}
    finally:
        session.close()
        engine.dispose()


@pytest.mark.anyio
async def test_unselected_fallback_deadline_does_not_shorten_the_directory():
    engine, session, service = relay_service_fixture()
    try:
        service._repository._max_reservations = 1
        relay_b = session.get(RelayNodeRegistration, "relay-b")
        relay_b.certificate_expires_at = NOW + timedelta(seconds=2)
        session.commit()
        result = await service.issue_access(
            current_user_id="user-42", session_id="session-7",
            policy_revision=17, intended_peer_id="device-7",
        )
        assert [item.node_id for item in result.directory.payload.candidates] == [
            "relay-a"
        ]
        assert result.directory.payload.expires_at_ms == int(
            (NOW + timedelta(seconds=15)).timestamp() * 1_000
        )
    finally:
        session.close()
        engine.dispose()


@pytest.mark.anyio
async def test_retry_never_shortens_a_reservation_behind_an_issued_credential():
    engine, session, service = relay_service_fixture()
    try:
        service._repository._max_reservations = 1
        first = await service.issue_access(
            current_user_id="user-42", session_id="session-7",
            policy_revision=17, intended_peer_id="device-7",
        )
        original_expiry = first.credentials[0].expires_at_unix_seconds
        assert original_expiry == int((NOW + timedelta(seconds=15)).timestamp())

        service._repository._max_reservations = 2
        relay_b = session.get(RelayNodeRegistration, "relay-b")
        relay_b.certificate_expires_at = NOW + timedelta(seconds=2)
        session.commit()
        retried = await service.issue_access(
            current_user_id="user-42", session_id="session-7",
            policy_revision=17, intended_peer_id="device-7",
        )

        assert [item.node_id for item in retried.directory.payload.candidates] == [
            "relay-a"
        ]
        reservations = list(session.scalars(select(RelayReservation)))
        assert [(item.node_id, _aware(item.expires_at)) for item in reservations] == [
            ("relay-a", NOW + timedelta(seconds=15))
        ]
        assert first.credentials[0].expires_at_unix_seconds == original_expiry
    finally:
        session.close()
        engine.dispose()


@pytest.mark.anyio
@pytest.mark.parametrize("case", ["missing", "wrong-user"])
async def test_database_authorization_failure_never_leaves_a_reservation(case: str):
    engine, session, service = relay_service_fixture()
    try:
        if case == "missing":
            session.delete(session.get(SessionRequest, "session-7"))
            session.commit()
            session_id = "session-7"
            user_id = "user-42"
        else:
            session_id = "session-7"
            user_id = "attacker"
        with pytest.raises(RelayAccessError) as error:
            await service.issue_access(
                current_user_id=user_id, session_id=session_id,
                policy_revision=17, intended_peer_id="device-7",
            )
        assert error.value.code == "relay_access_denied"
        assert session.scalar(select(func.count()).select_from(RelayReservation)) == 0
    finally:
        session.close()
        engine.dispose()


class FailingSigner:
    def sign(self, payload):
        raise RuntimeError("signer unavailable")


class FailingCredentialIssuer:
    def issue(self, **kwargs):
        raise RuntimeError("decrypted-super-secret")


@pytest.mark.anyio
async def test_signing_failure_rolls_back_every_capacity_reservation():
    engine, session, service = relay_service_fixture()
    service._signer = FailingSigner()
    try:
        with pytest.raises(RelayAccessError) as error:
            await service.issue_access(
                current_user_id="user-42", session_id="session-7",
                policy_revision=17, intended_peer_id="device-7",
            )
        assert error.value.code == "relay_signing_unavailable"
        assert "signer unavailable" not in str(error.value)
        assert session.scalar(select(func.count()).select_from(RelayReservation)) == 0
    finally:
        session.close()
        engine.dispose()


@pytest.mark.anyio
async def test_credential_failure_is_redacted_and_rolls_back_reservations():
    engine, session, service = relay_service_fixture()
    service._credential_issuer = FailingCredentialIssuer()
    try:
        with pytest.raises(RelayAccessError) as error:
            await service.issue_access(
                current_user_id="user-42", session_id="session-7",
                policy_revision=17, intended_peer_id="device-7",
            )
        assert error.value.code == "relay_credential_unavailable"
        assert "decrypted-super-secret" not in str(error.value)
        assert session.scalar(select(func.count()).select_from(RelayReservation)) == 0
    finally:
        session.close()
        engine.dispose()


@pytest.mark.anyio
async def test_capacity_rejection_is_audited_without_user_session_or_secret_labels():
    engine, session, service = relay_service_fixture()
    try:
        for relay in session.scalars(select(RelayNode)):
            relay.active_allocations = relay.max_allocations
        session.commit()
        with pytest.raises(RelayAccessError) as error:
            await service.issue_access(
                current_user_id="user-42", session_id="session-7",
                policy_revision=17, intended_peer_id="device-7",
            )
        assert error.value.code == "relay_capacity_unavailable"
        event = session.scalar(
            select(RelayAuditEvent).where(
                RelayAuditEvent.action == "relay_capacity_rejected"
            )
        )
        assert event is not None
        assert event.node_id is None
        assert event.actor_id is None
        assert event.details == {}
    finally:
        session.close()
        engine.dispose()


def test_access_api_requires_auth_and_returns_only_signed_directory_and_credentials():
    engine, session, service = relay_service_fixture()
    try:
        anonymous_app = FastAPI()
        anonymous_app.include_router(router, prefix="/api/v1")
        anonymous_app.dependency_overrides[get_relay_access_service] = lambda: service
        anonymous = TestClient(anonymous_app).post(
            "/api/v1/relays/access",
            json={
                "session_id": "session-7",
                "policy_revision": 17,
                "intended_peer_id": "device-7",
            },
        )
        assert anonymous.status_code in {401, 403}

        authenticated_app = FastAPI()
        authenticated_app.include_router(router, prefix="/api/v1")
        authenticated_app.dependency_overrides[get_relay_access_service] = lambda: service
        authenticated_app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
            id="user-42"
        )
        invalid = TestClient(authenticated_app).post(
            "/api/v1/relays/access", json={}
        )
        assert invalid.status_code == 400
        assert invalid.json()["detail"]["code"] == "relay_access_invalid"
        response = TestClient(authenticated_app).post(
            "/api/v1/relays/access",
            json={
                "session_id": "session-7",
                "policy_revision": 17,
                "intended_peer_id": "device-7",
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert set(body) == {"directory", "credentials"}
        candidates = body["directory"]["payload"]["candidates"]
        assert [item["node_id"] for item in candidates] == [
            item["node_id"] for item in body["credentials"]
        ]
        directory_text = str(body["directory"]).lower()
        assert "turn_rest_secret" not in directory_text
        assert "encrypted_turn_secret" not in directory_text
        assert "private_key" not in directory_text
    finally:
        session.close()
        engine.dispose()


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
