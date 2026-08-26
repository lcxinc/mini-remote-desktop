import base64
import hashlib
import hmac
import json
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
    _relay_turn_secret_cipher,
    get_relay_access_service,
    router,
)
from app.api.v1.sessions import router as sessions_router
from app.core.security import get_current_device, get_current_user
from app.core.response_security import SensitiveResponseCacheMiddleware
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
from app.db.session import Base, get_db
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
from app.services.session_grants import (
    SessionGrantPolicy,
    configured_session_grant_policy,
)
from app.services.turn_credentials import NodeTurnCredentialService


NOW = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)


def current_grant_policy(
    *, revision: int = 17,
    accepted_transports: tuple[str, ...] = ("udp", "tcp", "tls"),
) -> SessionGrantPolicy:
    return SessionGrantPolicy(
        grant_ttl_seconds=600,
        policy_ttl_seconds=600,
        revision=revision,
        allowed_regions=("ap-east", "eu-west"),
        preferred_regions=("ap-east", "eu-west"),
        accepted_transports=accepted_transports,
    )


def node(
    node_id: str,
    *, region: str = "ap-east", domain: str | None = None,
    state: str = "available", lease_delta: int = 15,
    registration_status: str = "approved", certificate_delta: int = 3600,
    endpoints: tuple[str, ...] | None = None,
    active: int = 1, maximum: int = 10,
    current_egress: int = 100, max_egress: int = 1000,
    rtt_ms: int | None = 20, recent_failure_bps: int = 0,
    physical_host: str | None = None, topology_approved: bool = True,
) -> RelayNodeView:
    return RelayNodeView(
        node_id=node_id, region=region, failure_domain=domain or f"rack-{node_id}",
        physical_host_id=physical_host or f"host-{node_id}",
        topology_approved=topology_approved,
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
                physical_host="shared-host",
                endpoints=("turn:shared.example.test:3478?transport=udp",),
            ),
            node(
                "relay-b",
                domain="claimed-rack-b",
                physical_host="shared-host",
                endpoints=("turn:shared.example.test:3479?transport=udp",),
            ),
        ],
        now=NOW,
    )
    assert [item.node_id for item in decision.selected] == ["relay-a"]


def test_admin_physical_host_identity_defeats_endpoint_aliases() -> None:
    primary = node(
        "relay-a",
        domain="rack-a",
        endpoints=("turn:alias-a.example.test:3478?transport=udp",),
    )
    alias = node(
        "relay-b",
        domain="rack-b",
        endpoints=("turn:alias-b.example.test:3478?transport=udp",),
    )
    independent = node(
        "relay-c",
        domain="rack-c",
        endpoints=("turn:alias-c.example.test:3478?transport=udp",),
    )
    object.__setattr__(primary, "physical_host_id", "host-shared")
    object.__setattr__(alias, "physical_host_id", "host-shared")
    object.__setattr__(independent, "physical_host_id", "host-independent")
    decision = select_relay_nodes(POLICY, [primary, alias, independent], now=NOW)
    assert [item.node_id for item in decision.selected] == ["relay-a", "relay-c"]


def test_unconfirmed_or_missing_physical_topology_is_hard_rejected() -> None:
    missing = node("relay-missing")
    unconfirmed = node("relay-unconfirmed")
    object.__setattr__(missing, "physical_host_id", None)
    object.__setattr__(missing, "topology_approved", False)
    object.__setattr__(unconfirmed, "physical_host_id", "host-untrusted")
    object.__setattr__(unconfirmed, "topology_approved", False)
    decision = select_relay_nodes(POLICY, [missing, unconfirmed], now=NOW)
    assert [(item.node_id, item.code) for item in decision.rejections] == [
        ("relay-missing", "topology_unapproved"),
        ("relay-unconfirmed", "topology_unapproved"),
    ]


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
        "target_device_id": "device-7", "tenant_id": "tenant-a",
        "status": "approved",
        "grant_expires_at": NOW + timedelta(minutes=5), "policy_revision": 17,
        "policy_expires_at": NOW + timedelta(minutes=4),
        "intended_peer_id": "device-7",
        "relay_allowed_regions": ["ap-east", "eu-west"],
        "relay_preferred_regions": ["ap-east", "eu-west"],
        "relay_accepted_transports": ["udp", "tcp", "tls"],
    }
    values.update(change)
    grant = SimpleNamespace(**values)
    device = SimpleNamespace(
        id="device-7", bound_user_id="owner-9", is_bound=True,
        tenant_id="tenant-a",
    )
    with pytest.raises(RelayAccessError) as error:
        authorize_relay_grant(
            grant=grant, target_device=device,
            requester_user=SimpleNamespace(id="user-42", tenant_id="tenant-a"),
            target_owner=SimpleNamespace(id="owner-9", tenant_id="tenant-a"),
            current_user=SimpleNamespace(id="user-42", tenant_id="tenant-a"),
            current_user_id="user-42",
            requested_policy_revision=17, requested_peer_id="device-7", now=NOW,
            current_policy=current_grant_policy(),
        )
    assert error.value.code == "relay_access_denied"
    assert "session-7" not in str(error.value)
    assert "device-7" not in str(error.value)


def test_only_real_session_participants_are_authorized():
    grant = SimpleNamespace(
        id="session-7", requester_user_id="user-42", target_device_id="device-7",
        tenant_id="tenant-a",
        status="approved", grant_expires_at=NOW + timedelta(minutes=5),
        policy_revision=17, policy_expires_at=NOW + timedelta(minutes=4),
        intended_peer_id="device-7",
        relay_allowed_regions=["ap-east", "eu-west"],
        relay_preferred_regions=["ap-east", "eu-west"],
        relay_accepted_transports=["udp", "tcp", "tls"],
    )
    device = SimpleNamespace(
        id="device-7", bound_user_id="owner-9", is_bound=True,
        tenant_id="tenant-a",
    )
    authorize_relay_grant(
        grant=grant, target_device=device,
        requester_user=SimpleNamespace(id="user-42", tenant_id="tenant-a"),
        target_owner=SimpleNamespace(id="owner-9", tenant_id="tenant-a"),
        current_user=SimpleNamespace(id="owner-9", tenant_id="tenant-a"),
        current_user_id="owner-9",
        requested_policy_revision=17, requested_peer_id="device-7", now=NOW,
        current_policy=current_grant_policy(),
    )
    with pytest.raises(RelayAccessError, match="denied"):
        authorize_relay_grant(
            grant=grant, target_device=device,
            requester_user=SimpleNamespace(id="user-42", tenant_id="tenant-a"),
            target_owner=SimpleNamespace(id="owner-9", tenant_id="tenant-a"),
            current_user=SimpleNamespace(id="attacker", tenant_id="tenant-a"),
            current_user_id="attacker",
            requested_policy_revision=17, requested_peer_id="device-7", now=NOW,
            current_policy=current_grant_policy(),
        )


def test_stored_intended_peer_must_be_the_bound_target_device():
    grant = SimpleNamespace(
        id="session-7", requester_user_id="user-42", target_device_id="device-7",
        tenant_id="tenant-a",
        status="approved", grant_expires_at=NOW + timedelta(minutes=5),
        policy_revision=17, policy_expires_at=NOW + timedelta(minutes=4),
        intended_peer_id="unrelated-device",
        relay_allowed_regions=["ap-east", "eu-west"],
        relay_preferred_regions=["ap-east", "eu-west"],
        relay_accepted_transports=["udp", "tcp", "tls"],
    )
    device = SimpleNamespace(
        id="device-7", bound_user_id="owner-9", is_bound=True,
        tenant_id="tenant-a",
    )
    with pytest.raises(RelayAccessError) as error:
        authorize_relay_grant(
            grant=grant, target_device=device,
            requester_user=SimpleNamespace(id="user-42", tenant_id="tenant-a"),
            target_owner=SimpleNamespace(id="owner-9", tenant_id="tenant-a"),
            current_user=SimpleNamespace(id="user-42", tenant_id="tenant-a"),
            current_user_id="user-42",
            requested_policy_revision=17, requested_peer_id="unrelated-device", now=NOW,
            current_policy=current_grant_policy(),
        )
    assert error.value.code == "relay_access_denied"


@pytest.mark.parametrize(
    "case", ["revision-bump", "transport-change", "self-grant"]
)
def test_current_policy_and_distinct_participants_are_revalidated(case: str) -> None:
    requester_id = "user-42"
    owner_id = requester_id if case == "self-grant" else "owner-9"
    grant = SimpleNamespace(
        id="session-7",
        requester_user_id=requester_id,
        target_device_id="device-7",
        tenant_id="tenant-a",
        status="approved",
        grant_expires_at=NOW + timedelta(minutes=5),
        policy_revision=17,
        policy_expires_at=NOW + timedelta(minutes=4),
        intended_peer_id="device-7",
        relay_allowed_regions=["ap-east", "eu-west"],
        relay_preferred_regions=["ap-east", "eu-west"],
        relay_accepted_transports=["udp", "tcp", "tls"],
    )
    device = SimpleNamespace(
        id="device-7",
        bound_user_id=owner_id,
        is_bound=True,
        tenant_id="tenant-a",
    )
    with pytest.raises(RelayAccessError) as error:
        authorize_relay_grant(
            grant=grant,
            target_device=device,
            requester_user=SimpleNamespace(
                id=requester_id, tenant_id="tenant-a"
            ),
            target_owner=SimpleNamespace(id=owner_id, tenant_id="tenant-a"),
            current_user=SimpleNamespace(id=requester_id, tenant_id="tenant-a"),
            current_user_id=requester_id,
            requested_policy_revision=17,
            requested_peer_id="device-7",
            now=NOW,
            current_policy=current_grant_policy(
                revision=18 if case == "revision-bump" else 17,
                accepted_transports=(
                    ("udp",) if case == "transport-change"
                    else ("udp", "tcp", "tls")
                ),
            ),
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


def test_relay_cipher_factory_loads_bounded_previous_read_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_key = bytes.fromhex("31" * 32)
    new_key = bytes.fromhex("32" * 32)
    encode = lambda value: base64.b64encode(value).decode("ascii")
    monkeypatch.setattr(
        settings, "relay_turn_secret_encryption_key", SecretStr(encode(new_key))
    )
    monkeypatch.setattr(settings, "relay_turn_secret_encryption_key_id", "new")
    monkeypatch.setattr(
        settings,
        "relay_turn_secret_encryption_read_keys",
        SecretStr(json.dumps({"old": encode(old_key)})),
    )
    monkeypatch.setattr(
        settings, "relay_turn_secret_encryption_legacy_key_id", "old"
    )
    old = AesGcmRelaySecretCipher(old_key, key_id="old")
    envelope = old.encrypt(b"x" * 32, associated_data=b"relay-a")
    rotated = _relay_turn_secret_cipher()
    assert rotated.needs_reencrypt(envelope)
    assert rotated.decrypt(envelope, associated_data=b"relay-a") == b"x" * 32

    monkeypatch.setattr(
        settings,
        "relay_turn_secret_encryption_read_keys",
        SecretStr(json.dumps({str(index): encode(old_key) for index in range(5)})),
    )
    with pytest.raises(ValueError):
        _relay_turn_secret_cipher()

    monkeypatch.setattr(
        settings,
        "relay_turn_secret_encryption_read_keys",
        SecretStr(
            '{"old":"' + encode(old_key) + '","old":"' + encode(new_key) + '"}'
        ),
    )
    with pytest.raises(ValueError):
        _relay_turn_secret_cipher()


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
        password_hash="unused", role="user", tenant_id="tenant-a",
    )
    owner = User(
        id="owner-9", username="owner", email="owner@example.test",
        password_hash="unused", role="user", tenant_id="tenant-a",
    )
    device = Device(
        id="device-7", name="target", device_id="device-public-7", os="linux",
        is_bound=True, bound_user_id=owner.id, tenant_id="tenant-a",
    )
    grant = SessionRequest(
        id="session-7", requester_user_id=requester.id, target_device_id=device.id,
        signaling_room="room-7", tenant_id="tenant-a", status="approved",
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
            physical_host_id=f"host-{node_id}",
            endpoints=[f"turn:{node_id}.example.test:3478?transport=udp"],
            certificate_fingerprint="sha256:" + f"{index + 1:064x}",
            encrypted_turn_secret=cipher.encrypt(
                hashlib.sha256(f"{node_id}-unique-turn-secret".encode()).digest(),
                associated_data=node_id.encode(),
            ),
            max_allocations=2, active_allocations=0,
            max_egress_bps=1_000_000, current_egress_bps=0,
            heartbeat_sequence=3, healthy_heartbeat_streak=3,
            lease_expires_at=NOW + timedelta(seconds=15), created_at=NOW, updated_at=NOW,
        )
        registration = RelayNodeRegistration(
            node_id=node_id, enrollment_id=enrollment.id, region=region,
            failure_domain=domain, physical_host_id=f"host-{node_id}",
            topology_approved_at=NOW, endpoints=relay.endpoints, max_allocations=2,
            max_egress_bps=1_000_000, csr_pem=b"fixture", signing_public_key=b"1" * 32,
            encrypted_turn_secret=relay.encrypted_turn_secret,
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
        current_policy=current_grant_policy(),
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
async def test_access_progressively_reencrypts_old_node_secret_envelopes():
    engine, session, service = relay_service_fixture()
    old_key = bytes.fromhex("31" * 32)
    old_cipher = AesGcmRelaySecretCipher(old_key, key_id="old")
    rotated = AesGcmRelaySecretCipher(
        bytes.fromhex("32" * 32),
        key_id="current",
        read_keys={"old": old_key},
    )
    expected: dict[str, bytes] = {}
    try:
        for relay in session.scalars(select(RelayNode)):
            secret = base64.urlsafe_b64encode(
                hashlib.sha256(f"rotating-{relay.node_id}".encode()).digest()
            ).rstrip(b"=")
            expected[relay.node_id] = secret
            envelope = old_cipher.encrypt(
                secret, associated_data=relay.node_id.encode()
            )
            relay.encrypted_turn_secret = envelope
            registration = session.get(RelayNodeRegistration, relay.node_id)
            assert registration is not None
            registration.encrypted_turn_secret = envelope
        session.commit()
        service._credential_issuer._cipher = rotated

        await service.issue_access(
            current_user_id="user-42",
            session_id="session-7",
            policy_revision=17,
            intended_peer_id="device-7",
        )

        for relay in session.scalars(select(RelayNode)):
            registration = session.get(RelayNodeRegistration, relay.node_id)
            assert registration is not None
            assert relay.encrypted_turn_secret == registration.encrypted_turn_secret
            assert not rotated.needs_reencrypt(relay.encrypted_turn_secret)
            assert rotated.decrypt(
                relay.encrypted_turn_secret,
                associated_data=relay.node_id.encode(),
            ) == expected[relay.node_id]
    finally:
        session.close()
        engine.dispose()


@pytest.mark.anyio
async def test_access_upgrades_legacy_raw_secret_envelopes_to_wire_strings():
    engine, session, service = relay_service_fixture()
    expected: dict[str, bytes] = {}
    try:
        for relay in session.scalars(select(RelayNode)):
            raw_secret = hashlib.sha256(
                f"legacy-raw-{relay.node_id}".encode()
            ).digest()
            expected[relay.node_id] = base64.urlsafe_b64encode(
                raw_secret
            ).rstrip(b"=")
            envelope = service._credential_issuer._cipher.encrypt(
                raw_secret, associated_data=relay.node_id.encode()
            )
            relay.encrypted_turn_secret = envelope
            registration = session.get(RelayNodeRegistration, relay.node_id)
            assert registration is not None
            registration.encrypted_turn_secret = envelope
        session.commit()

        result = await service.issue_access(
            current_user_id="user-42",
            session_id="session-7",
            policy_revision=17,
            intended_peer_id="device-7",
        )

        credentials = {item.node_id: item for item in result.credentials}
        for relay in session.scalars(select(RelayNode)):
            registration = session.get(RelayNodeRegistration, relay.node_id)
            assert registration is not None
            assert relay.encrypted_turn_secret == registration.encrypted_turn_secret
            decrypted = service._credential_issuer._cipher.decrypt(
                relay.encrypted_turn_secret,
                associated_data=relay.node_id.encode(),
            )
            assert decrypted == expected[relay.node_id]
            issued = credentials[relay.node_id]
            coturn_credential = base64.b64encode(
                hmac.new(
                    expected[relay.node_id],
                    issued.username.encode("utf-8"),
                    hashlib.sha1,
                ).digest()
            ).decode("ascii")
            assert hmac.compare_digest(issued.credential, coturn_credential)
    finally:
        session.close()
        engine.dispose()


@pytest.mark.anyio
async def test_historical_self_grant_is_rejected_before_any_reservation():
    engine, session, service = relay_service_fixture()
    try:
        device = session.get(Device, "device-7")
        device.bound_user_id = "user-42"
        session.commit()
        with pytest.raises(RelayAccessError) as error:
            await service.issue_access(
                current_user_id="user-42",
                session_id="session-7",
                policy_revision=17,
                intended_peer_id="device-7",
            )
        assert error.value.code == "relay_access_denied"
        assert session.scalar(
            select(func.count()).select_from(RelayReservation)
        ) == 0
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
async def test_pending_capacity_is_scored_before_same_domain_primary_deduplication():
    engine, session, service = relay_service_fixture()
    try:
        relay_a = session.get(RelayNode, "relay-a")
        relay_b = session.get(RelayNode, "relay-b")
        registration_b = session.get(RelayNodeRegistration, "relay-b")
        relay_a.max_allocations = 1
        relay_b.failure_domain = relay_a.failure_domain
        registration_b.failure_domain = relay_a.failure_domain
        session.add(
            RelayReservation(
                id="other-session-on-a",
                session_id="other-session",
                user_id="other-user",
                node_id="relay-a",
                expires_at=NOW + timedelta(seconds=10),
                created_at=NOW,
            )
        )
        session.commit()

        result = await service.issue_access(
            current_user_id="user-42",
            session_id="session-7",
            policy_revision=17,
            intended_peer_id="device-7",
        )

        assert [item.node_id for item in result.credentials] == ["relay-b"]
        assert session.get(RelayReservation, "other-session-on-a") is not None
    finally:
        session.close()
        engine.dispose()


@pytest.mark.anyio
async def test_locked_primary_rejection_falls_through_to_next_same_domain_node():
    engine, session, service = relay_service_fixture()
    try:
        relay_a = session.get(RelayNode, "relay-a")
        relay_b = session.get(RelayNode, "relay-b")
        registration_b = session.get(RelayNodeRegistration, "relay-b")
        relay_b.failure_domain = relay_a.failure_domain
        registration_b.failure_domain = relay_a.failure_domain
        session.commit()

        original_reserve = service._repository.reserve_capacity
        calls: list[list[str]] = []

        async def reject_first_locked_candidate(**kwargs):
            calls.append(list(kwargs["ordered_node_ids"]))
            kwargs["ordered_node_ids"] = kwargs["ordered_node_ids"][1:]
            return await original_reserve(**kwargs)

        service._repository.reserve_capacity = reject_first_locked_candidate
        result = await service.issue_access(
            current_user_id="user-42",
            session_id="session-7",
            policy_revision=17,
            intended_peer_id="device-7",
        )

        assert calls[0][:2] == ["relay-a", "relay-b"]
        assert [item.node_id for item in result.credentials] == ["relay-b"]
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
async def test_directory_deadline_is_one_exact_unix_second_everywhere():
    engine, session, service = relay_service_fixture()
    try:
        precise_now = NOW + timedelta(microseconds=987_654)
        service._now = lambda: precise_now
        service._credential_issuer._now = lambda: int(precise_now.timestamp())
        # A node/certificate can be the earliest bound and may carry
        # sub-second precision. It must be floored before touching storage too.
        for relay in session.scalars(select(RelayNode)):
            relay.lease_expires_at = precise_now + timedelta(
                seconds=10, microseconds=654_321
            )
        session.commit()
        result = await service.issue_access(
            current_user_id="user-42",
            session_id="session-7",
            policy_revision=17,
            intended_peer_id="device-7",
        )
        deadline_ms = result.directory.payload.expires_at_ms
        assert deadline_ms % 1000 == 0
        assert {
            item.reservation.expires_at_ms
            for item in result.directory.payload.candidates
        } == {deadline_ms}
        assert {
            item.expires_at_unix_seconds for item in result.credentials
        } == {deadline_ms // 1000}
        assert {
            int(item.username.split(":", 1)[0]) for item in result.credentials
        } == {deadline_ms // 1000}
        assert {
            int(_aware(value).timestamp())
            for value in session.scalars(select(RelayReservation.expires_at))
        } == {deadline_ms // 1000}
    finally:
        session.close()
        engine.dispose()


@pytest.mark.anyio
async def test_draining_backup_is_superseded_and_replaced_without_freeing_capacity():
    engine, session, service = relay_service_fixture()
    try:
        first = await service.issue_access(
            current_user_id="user-42", session_id="session-7",
            policy_revision=17, intended_peer_id="device-7",
        )
        assert len(first.credentials) == 2

        cipher = service._credential_issuer._cipher
        enrollment = RelayEnrollment(
            id="enrollment-c", token_digest="c" * 64,
            expires_at=NOW + timedelta(hours=1), used_at=NOW,
            enrolled_node_id="relay-c", created_at=NOW,
        )
        relay_c = RelayNode(
            node_id="relay-c", region="eu-west", failure_domain="rack-c",
            physical_host_id="host-relay-c", state="available",
            endpoints=["turn:relay-c.example.test:3478?transport=udp"],
            certificate_fingerprint="sha256:" + "c" * 64,
            encrypted_turn_secret=cipher.encrypt(
                hashlib.sha256(b"relay-c-unique-turn-secret").digest(),
                associated_data=b"relay-c",
            ),
            max_allocations=2, active_allocations=0,
            max_egress_bps=1_000_000, current_egress_bps=0,
            heartbeat_sequence=3, healthy_heartbeat_streak=3,
            lease_expires_at=NOW + timedelta(seconds=15),
            created_at=NOW, updated_at=NOW,
        )
        registration_c = RelayNodeRegistration(
            node_id="relay-c", enrollment_id="enrollment-c", region="eu-west",
            failure_domain="rack-c", physical_host_id="host-relay-c",
            topology_approved_at=NOW, endpoints=relay_c.endpoints,
            max_allocations=2, max_egress_bps=1_000_000,
            csr_pem=b"fixture", signing_public_key=b"3" * 32,
            encrypted_turn_secret=relay_c.encrypted_turn_secret,
            status="approved", certificate_pem=b"fixture",
            certificate_expires_at=NOW + timedelta(hours=1),
            created_at=NOW, approved_at=NOW,
        )
        session.add_all([enrollment, relay_c, registration_c])
        session.get(RelayNode, "relay-b").state = "draining"
        session.commit()

        replaced = await service.issue_access(
            current_user_id="user-42", session_id="session-7",
            policy_revision=17, intended_peer_id="device-7",
        )
        assert {item.node_id for item in replaced.credentials} == {"relay-a", "relay-c"}
        reservations = {
            item.node_id: item
            for item in session.scalars(select(RelayReservation))
        }
        assert reservations["relay-b"].superseded_at is not None
        assert _aware(reservations["relay-b"].expires_at) > NOW
        assert reservations["relay-a"].superseded_at is None
        assert reservations["relay-c"].superseded_at is None
        assert len({
            reservations[node_id].directory_generation
            for node_id in ("relay-a", "relay-c")
        }) == 1
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


@pytest.mark.anyio
async def test_access_revalidates_participant_device_owner_and_grant_tenant() -> None:
    engine, session, service = relay_service_fixture()
    try:
        session.get(User, "owner-9").tenant_id = "tenant-b"
        session.commit()
        with pytest.raises(RelayAccessError) as error:
            await service.issue_access(
                current_user_id="user-42",
                session_id="session-7",
                policy_revision=17,
                intended_peer_id="device-7",
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
        anonymous_app.add_middleware(SensitiveResponseCacheMiddleware)
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
        assert anonymous.headers["cache-control"] == "no-store, private"
        assert anonymous.headers["pragma"] == "no-cache"

        authenticated_app = FastAPI()
        authenticated_app.add_middleware(SensitiveResponseCacheMiddleware)
        authenticated_app.include_router(router, prefix="/api/v1")
        authenticated_app.dependency_overrides[get_relay_access_service] = lambda: service
        authenticated_app.dependency_overrides[get_current_device] = lambda: SimpleNamespace(
            id="requester-device", is_bound=True, bound_user_id="user-42"
        )
        invalid = TestClient(authenticated_app).post(
            "/api/v1/relays/access", json={}
        )
        assert invalid.status_code == 400
        assert invalid.headers["cache-control"] == "no-store, private"
        assert invalid.headers["pragma"] == "no-cache"
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
        assert response.headers["cache-control"] == "no-store, private"
        assert response.headers["pragma"] == "no-cache"
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


def test_production_request_owner_approval_and_both_participant_access_flow(
    monkeypatch: pytest.MonkeyPatch,
):
    engine, session, service = relay_service_fixture()
    try:
        anchor = datetime.now(UTC)
        service._now = lambda: datetime.now(UTC)
        service._credential_issuer._now = lambda: int(datetime.now(UTC).timestamp())
        for relay in session.scalars(select(RelayNode)):
            relay.lease_expires_at = anchor + timedelta(seconds=15)
        for registration in session.scalars(select(RelayNodeRegistration)):
            registration.certificate_expires_at = anchor + timedelta(hours=1)
        session.commit()
        for name, value in {
            "session_grant_ttl_seconds": 120,
            "relay_policy_ttl_seconds": 90,
            "relay_policy_revision": 23,
            "relay_allowed_regions": "ap-east,eu-west",
            "relay_preferred_regions": "ap-east,eu-west",
            "relay_accepted_transports": "udp,tcp,tls",
        }.items():
            monkeypatch.setitem(settings.__dict__, name, value)
        service._current_policy = configured_session_grant_policy(settings)
        current = SimpleNamespace(
            user=session.get(User, "user-42"),
            device=SimpleNamespace(
                id="requester-device", is_bound=True, bound_user_id="user-42"
            ),
        )
        async_session = service._session

        async def override_db():
            yield async_session

        async def override_user():
            return current.user

        async def override_device():
            return current.device

        app = FastAPI()
        app.include_router(sessions_router, prefix="/api/v1")
        app.include_router(router, prefix="/api/v1")
        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[get_current_user] = override_user
        app.dependency_overrides[get_current_device] = override_device
        app.dependency_overrides[get_relay_access_service] = lambda: service
        client = TestClient(app)

        requested = client.post(
            "/api/v1/sessions/request",
            json={"target_device_id": "device-7"},
        )
        assert requested.status_code == 200, requested.text
        session_id = requested.json()["request_id"]
        current.user = session.get(User, "owner-9")
        approved = client.post(f"/api/v1/sessions/{session_id}/approve", json={})
        assert approved.status_code == 200, approved.text
        access_payload = {
            "session_id": session_id,
            "policy_revision": approved.json()["policy_revision"],
            "intended_peer_id": approved.json()["intended_peer_id"],
        }

        for user_id in ("user-42", "owner-9"):
            current.user = session.get(User, user_id)
            current.device = SimpleNamespace(
                id=f"device-for-{user_id}", is_bound=True, bound_user_id=user_id
            )
            access = client.post("/api/v1/relays/access", json=access_payload)
            assert access.status_code == 200, access.text
            assert access.json()["credentials"]

        reservations_before_bump = session.scalar(
            select(func.count()).select_from(RelayReservation)
        )
        monkeypatch.setitem(settings.__dict__, "relay_policy_revision", 24)
        service._current_policy = configured_session_grant_policy(settings)
        current.user = session.get(User, "user-42")
        revoked = client.post("/api/v1/relays/access", json=access_payload)
        assert revoked.status_code == 403
        assert revoked.json()["detail"]["code"] == "relay_access_denied"
        assert session.scalar(
            select(func.count()).select_from(RelayReservation)
        ) == reservations_before_bump
    finally:
        session.close()
        engine.dispose()


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
