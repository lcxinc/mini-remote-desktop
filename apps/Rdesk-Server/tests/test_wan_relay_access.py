from __future__ import annotations

import hashlib
import json
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401
from app.api.v1.relays import get_relay_access_service
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.response_security import SensitiveResponseCacheMiddleware
from app.core.security import create_device_access_token
from app.db.session import Base, get_db
from app.models.device import Device
from app.models.relay_access_generation import RelayAccessGeneration
from app.models.relay_enrollment import RelayEnrollment
from app.models.relay_node import RelayNode
from app.models.relay_node_registration import RelayNodeRegistration
from app.models.relay_reservation import RelayReservation
from app.models.session_request import SessionRequest
from app.models.user import User
from app.schemas.session import DeviceSessionApprovalIn
from app.services.device_sessions import DeviceSessionError, DeviceSessionService
import app.services.relay_directory as relay_directory_module
from app.services.relay_directory import (
    RelayAccessError,
    RelayAccessResult,
    RelayAccessService,
    _canonical_endpoint_url,
    relay_url_digest,
)
from app.services.relay_repository import AesGcmRelaySecretCipher, RelayRepository
from app.services.relay_repository import RelayRepositoryError
from app.services.relay_signing import (
    Ed25519RelayDirectorySigner,
    RelayDirectoryEndpointOut,
)
from app.services.session_grants import SessionGrantPolicy
from app.services.turn_credentials import NodeTurnCredentialService
from app.services.turn_credentials import NodeTurnCredential
from test_relay_directory import relay_service_fixture


JWT_SECRET = "J8!vQ2@rL7#cN4$yT9%pS6&wB3*eM5-zD1+uK0="
NOW = datetime(2026, 8, 26, 8, 0, tzinfo=UTC)


class _AsyncTransaction(AbstractAsyncContextManager[None]):
    def __init__(self, session: Session) -> None:
        self._transaction = session.begin()

    async def __aenter__(self) -> None:
        self._transaction.__enter__()

    async def __aexit__(self, exc_type, exc, traceback) -> bool | None:
        return self._transaction.__exit__(exc_type, exc, traceback)


class AsyncSessionShim:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.lock_trace: list[tuple[str, ...]] = []

    def _record_lock(self, statement: object) -> None:
        if getattr(statement, "_for_update_arg", None) is None:
            return
        descriptions = getattr(statement, "column_descriptions", ())
        entities = tuple(
            entity.__name__
            for description in descriptions
            if (entity := description.get("entity")) is not None
        )
        if entities:
            self.lock_trace.append(entities)

    def add(self, value: object) -> None:
        self.session.add(value)

    async def scalar(self, *args: object, **kwargs: object) -> object:
        self._record_lock(args[0])
        return self.session.scalar(*args, **kwargs)

    async def scalars(self, *args: object, **kwargs: object) -> object:
        self._record_lock(args[0])
        return self.session.scalars(*args, **kwargs)

    async def execute(self, *args: object, **kwargs: object) -> object:
        self._record_lock(args[0])
        return self.session.execute(*args, **kwargs)

    async def flush(self) -> None:
        self.session.flush()

    async def delete(self, value: object) -> None:
        self.session.delete(value)

    async def commit(self) -> None:
        self.session.commit()

    async def rollback(self) -> None:
        self.session.rollback()

    def in_transaction(self) -> bool:
        return self.session.in_transaction()

    def begin(self) -> _AsyncTransaction:
        return _AsyncTransaction(self.session)


@dataclass
class WanRelayAPI:
    client: TestClient
    session: Session
    service: RelayAccessService
    devices: dict[str, Device]
    credential_calls: list[tuple[str, str]]
    tokens: dict[str, str] = field(repr=False)


class RecordingCredentialIssuer:
    def __init__(self, delegate: NodeTurnCredentialService) -> None:
        self._delegate = delegate
        self.calls: list[tuple[str, str]] = []

    def issue(self, **kwargs: object):
        self.calls.append((str(kwargs["user_id"]), str(kwargs["node_id"])))
        return self._delegate.issue(**kwargs)


def _user(user_id: str) -> User:
    return User(
        id=user_id,
        username=user_id,
        email=f"{user_id}@example.test",
        password_hash="unused",
        role="user",
        tenant_id="tenant-a",
    )


def _device(row_id: str, public_id: str, owner: User) -> Device:
    return Device(
        id=row_id,
        name=row_id,
        device_id=public_id,
        os="Linux",
        tenant_id="tenant-a",
        is_bound=True,
        bound_user_id=owner.id,
    )


@pytest.fixture
def wan_relay_api(monkeypatch: pytest.MonkeyPatch):
    for name, value in {
        "jwt_secret": SecretStr(JWT_SECRET),
        "jwt_issuer": "https://auth.rdesk.test",
        "jwt_audience": "rdesk-api",
        "device_jwt_audience": "rdesk-device",
        "device_jwt_expire_minutes": 30,
        "jwt_max_lifetime_minutes": 60,
    }.items():
        monkeypatch.setitem(settings.__dict__, name, value)

    anchor = datetime.now(UTC).replace(microsecond=0)
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine, expire_on_commit=False)
    async_session = AsyncSessionShim(session)
    cipher = AesGcmRelaySecretCipher(bytes.fromhex("41" * 32))

    controller_user = _user("controller-user")
    target_user = _user("target-user")
    alternate_user = _user("alternate-user")
    controller = _device("controller-row", "controller-1", controller_user)
    target = _device("target-row", "target-1", target_user)
    target_sibling = _device("target-sibling-row", "target-sibling-1", target_user)
    unrelated = _device("unrelated-row", "unrelated-1", alternate_user)
    session.add_all(
        [
            controller_user,
            target_user,
            alternate_user,
            controller,
            target,
            target_sibling,
            unrelated,
        ]
    )
    for index, (node_id, region, domain) in enumerate(
        (("relay-a", "ap-east", "rack-a"), ("relay-b", "eu-west", "rack-b")),
        start=1,
    ):
        enrollment = RelayEnrollment(
            id=f"enrollment-{index}",
            token_digest=f"{index:064x}",
            expires_at=anchor + timedelta(hours=2),
            used_at=anchor,
            enrolled_node_id=node_id,
            created_at=anchor,
        )
        encrypted_secret = cipher.encrypt(
            hashlib.sha256(f"fixture-secret-{node_id}".encode()).digest(),
            associated_data=node_id.encode(),
        )
        relay = RelayNode(
            node_id=node_id,
            region=region,
            failure_domain=domain,
            physical_host_id=f"host-{node_id}",
            state="available",
            endpoints=[
                f"turn:{node_id}.example.test:3478?transport=udp",
                f"turn:{node_id}.example.test:3478?transport=tcp",
            ],
            certificate_fingerprint="sha256:" + f"{index:064x}",
            encrypted_turn_secret=encrypted_secret,
            max_allocations=4,
            active_allocations=0,
            max_egress_bps=1_000_000,
            current_egress_bps=0,
            heartbeat_sequence=3,
            healthy_heartbeat_streak=3,
            lease_expires_at=anchor + timedelta(minutes=10),
            created_at=anchor,
            updated_at=anchor,
        )
        registration = RelayNodeRegistration(
            node_id=node_id,
            enrollment_id=enrollment.id,
            region=region,
            failure_domain=domain,
            physical_host_id=relay.physical_host_id,
            topology_approved_at=anchor,
            endpoints=relay.endpoints,
            max_allocations=relay.max_allocations,
            max_egress_bps=relay.max_egress_bps,
            csr_pem=b"fixture",
            signing_public_key=bytes([index]) * 32,
            encrypted_turn_secret=encrypted_secret,
            status="approved",
            certificate_pem=b"fixture",
            certificate_expires_at=anchor + timedelta(hours=1),
            created_at=anchor,
            approved_at=anchor,
        )
        session.add_all([enrollment, relay, registration])
    session.commit()

    policy = SessionGrantPolicy(
        grant_ttl_seconds=600,
        policy_ttl_seconds=300,
        revision=29,
        allowed_regions=("ap-east", "eu-west"),
        preferred_regions=("ap-east", "eu-west"),
        accepted_transports=("udp", "tcp"),
    )
    credential_issuer = RecordingCredentialIssuer(
        NodeTurnCredentialService(
            cipher=cipher,
            ttl_seconds=600,
            now=lambda: int(datetime.now(UTC).timestamp()),
        )
    )
    service = RelayAccessService(
        session=async_session,
        repository=RelayRepository(
            async_session,
            enrollment_token_pepper=bytes.fromhex("42" * 32),
            secret_cipher=cipher,
            max_reservations_per_session=2,
        ),
        signer=Ed25519RelayDirectorySigner(
            key_id="wan-test-key",
            private_key_seed=bytes.fromhex("43" * 32),
        ),
        credential_issuer=credential_issuer,
        current_policy=policy,
        directory_ttl_seconds=120,
        now=lambda: datetime.now(UTC),
    )

    async def override_db():
        yield async_session

    app = FastAPI()
    app.add_middleware(SensitiveResponseCacheMiddleware)
    app.include_router(api_router)
    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_relay_access_service] = lambda: service
    client = TestClient(app)
    devices = {
        item.device_id: item for item in (controller, target, target_sibling, unrelated)
    }
    tokens = {
        public_id: create_device_access_token(device)
        for public_id, device in devices.items()
    }
    try:
        yield WanRelayAPI(
            client=client,
            session=session,
            service=service,
            devices=devices,
            credential_calls=credential_issuer.calls,
            tokens=tokens,
        )
    finally:
        client.close()
        session.close()
        engine.dispose()


def _headers(api: WanRelayAPI, public_id: str) -> dict[str, str]:
    return {"X-Rdesk-Device-Authorization": f"Bearer {api.tokens[public_id]}"}


def _auth_snapshot(device: Device) -> SimpleNamespace:
    return SimpleNamespace(
        row_id=device.id,
        device_id=device.device_id,
        auth_version=device.auth_version,
        bound_user_id=device.bound_user_id,
        tenant_id=device.tenant_id,
        is_bound=device.is_bound,
        auth_revoked_at=device.auth_revoked_at,
    )


def _create(api: WanRelayAPI, *, session_id: str = "wan-session-1"):
    return api.client.post(
        "/api/v1/device-sessions",
        headers=_headers(api, "controller-1"),
        json={
            "session_id": session_id,
            "idempotency_key": [7] * 16,
            "target_device_id": "target-1",
            "access_mode": "attended",
            "requested_scopes": ["input.keyboard", "screen.view"],
            "requested_profile": {
                "width": 1920,
                "height": 1080,
                "fps": 60,
                "bitrate_mbps": 20,
                "codec": "h264",
                "codec_profile": "high",
                "bit_depth": 8,
                "chroma_subsampling": "4:2:0",
                "pixel_format": "nv12",
                "hdr_enabled": False,
                "color_mode": "sdr",
                "color_pipeline": "bt709",
            },
            "route_policy": "relay_only",
        },
    )


def _approve(
    api: WanRelayAPI,
    *,
    session_id: str = "wan-session-1",
    caller: str = "target-1",
):
    return api.client.post(
        f"/api/v1/device-sessions/{session_id}/approve",
        headers=_headers(api, caller),
        json={
            "approved_scopes": ["screen.view"],
            "approved_profile": {
                "width": 1280,
                "height": 720,
                "fps": 30,
                "bitrate_mbps": 8,
                "codec": "h264",
                "codec_profile": "high",
                "bit_depth": 8,
                "chroma_subsampling": "4:2:0",
                "pixel_format": "nv12",
                "hdr_enabled": False,
                "color_mode": "sdr",
                "color_pipeline": "bt709",
            },
        },
    )


def _access(
    api: WanRelayAPI,
    *,
    caller: str,
    generation: int = 0,
    refresh: bool = False,
):
    return api.client.post(
        "/api/v1/relays/access",
        headers=_headers(api, caller),
        json={
            "session_id": "wan-session-1",
            "policy_revision": 29,
            "intended_peer_id": "target-1",
            "generation": generation,
            "refresh": refresh,
        },
    )


def _safe_access_projection(body: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in body.items() if key not in {"credentials"}}


def _manual_urls_digest(urls: list[str]) -> str:
    digest = hashlib.sha256(b"MRD_RELAY_URLS_V1\x00")
    for url in sorted(urls, key=lambda value: value.encode("utf-8")):
        encoded = url.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def test_only_exact_target_can_atomically_approve_generation_zero(
    wan_relay_api: WanRelayAPI,
) -> None:
    api = wan_relay_api
    assert _create(api).status_code == 200

    sibling = _approve(api, caller="target-sibling-1")
    unrelated = _approve(api, caller="unrelated-1")
    controller = _approve(api, caller="controller-1")
    assert sibling.status_code == unrelated.status_code == 404
    assert controller.status_code == 403
    row = api.session.get(SessionRequest, "wan-session-1")
    assert row is not None and row.status == "requested"
    assert api.session.scalar(select(func.count()).select_from(RelayReservation)) == 0
    assert (
        api.session.scalar(select(func.count()).select_from(RelayAccessGeneration)) == 0
    )

    approved = _approve(api)
    assert approved.status_code == 200
    body = approved.json()
    assert body["status"] == "approved"
    assert body["approved_scopes"] == ["screen.view"]
    assert body["approved_profile"]["width"] == 1280
    assert body["policy_revision"] == 29
    assert body["active_relay_generation"] == 0

    row = api.session.get(SessionRequest, "wan-session-1")
    generation = api.session.get(RelayAccessGeneration, ("wan-session-1", 0))
    assert row is not None and generation is not None
    assert row.status == "approved"
    assert row.active_relay_generation == 0
    assert len(generation.reservation_ids) == 2
    reservations = list(
        api.session.scalars(
            select(RelayReservation)
            .where(RelayReservation.session_id == "wan-session-1")
            .order_by(RelayReservation.node_id)
        )
    )
    assert {item.id for item in reservations} == set(generation.reservation_ids)
    relay_rows = {
        relay.node_id: relay
        for relay in api.session.scalars(
            select(RelayNode).where(
                RelayNode.node_id.in_([item.node_id for item in reservations])
            )
        )
    }
    assert len({relay_rows[item.node_id].failure_domain for item in reservations}) == 2
    assert (
        len({relay_rows[item.node_id].physical_host_id for item in reservations}) == 2
    )
    persisted = json.dumps(generation.signed_directory, sort_keys=True).lower()
    assert all(
        forbidden not in persisted
        for forbidden in ("credential", "username", "password", "userinfo")
    )


def test_duplicate_approval_reuses_one_generation_and_one_reservation_set(
    wan_relay_api: WanRelayAPI,
) -> None:
    api = wan_relay_api
    assert _create(api).status_code == 200
    first = _approve(api)
    second = _approve(api)
    assert first.status_code == second.status_code == 200
    for response_field in (
        "session_id",
        "request",
        "request_commitment",
        "status",
        "approved_scopes",
        "approved_profile",
        "policy_revision",
        "active_relay_generation",
    ):
        assert first.json()[response_field] == second.json()[response_field]
    assert (
        api.session.scalar(select(func.count()).select_from(RelayAccessGeneration)) == 1
    )
    assert api.session.scalar(select(func.count()).select_from(RelayReservation)) == 2


def test_approval_is_closed_narrowed_and_conflicting_retry_is_rejected(
    wan_relay_api: WanRelayAPI,
) -> None:
    api = wan_relay_api
    assert _create(api).status_code == 200
    headers = _headers(api, "target-1")
    extra_policy = api.client.post(
        "/api/v1/device-sessions/wan-session-1/approve",
        headers=headers,
        json={
            "approved_scopes": ["screen.view"],
            "approved_profile": None,
            "policy_revision": 29,
        },
    )
    expanded_scope = api.client.post(
        "/api/v1/device-sessions/wan-session-1/approve",
        headers=headers,
        json={"approved_scopes": ["input.pointer"], "approved_profile": None},
    )
    expanded_profile = api.client.post(
        "/api/v1/device-sessions/wan-session-1/approve",
        headers=headers,
        json={
            "approved_scopes": ["screen.view"],
            "approved_profile": {
                "width": 1921,
                "height": 1080,
                "fps": 60,
                "bitrate_mbps": 20,
                "codec": "h264",
                "codec_profile": "high",
                "bit_depth": 8,
                "chroma_subsampling": "4:2:0",
                "pixel_format": "nv12",
                "hdr_enabled": False,
                "color_mode": "sdr",
                "color_pipeline": "bt709",
            },
        },
    )
    assert extra_policy.status_code == 400
    assert expanded_scope.status_code == expanded_profile.status_code == 403
    row = api.session.get(SessionRequest, "wan-session-1")
    assert row is not None and row.status == "requested"
    assert row.approved_scopes is None and row.active_relay_generation is None
    assert api.session.scalar(select(func.count()).select_from(RelayReservation)) == 0

    assert _approve(api).status_code == 200
    conflicting = api.client.post(
        "/api/v1/device-sessions/wan-session-1/approve",
        headers=headers,
        json={"approved_scopes": ["input.keyboard"], "approved_profile": None},
    )
    assert conflicting.status_code == 409
    assert (
        api.session.scalar(select(func.count()).select_from(RelayAccessGeneration)) == 1
    )


def test_same_owner_distinct_devices_keep_device_exact_authority(
    wan_relay_api: WanRelayAPI,
) -> None:
    api = wan_relay_api
    controller = api.devices["controller-1"]
    target = api.devices["target-1"]
    target.bound_user_id = controller.bound_user_id
    api.session.commit()
    api.tokens["target-1"] = create_device_access_token(target)

    assert _create(api).status_code == 200
    assert _approve(api).status_code == 200
    assert _access(api, caller="controller-1").status_code == 200
    assert _access(api, caller="target-1").status_code == 200
    assert {caller for caller, _ in api.credential_calls} == {
        "controller-1",
        "target-1",
    }


@pytest.mark.anyio
async def test_auth_version_rotation_between_auth_and_approval_lock_fails_closed(
    wan_relay_api: WanRelayAPI,
) -> None:
    api = wan_relay_api
    assert _create(api).status_code == 200
    target = api.session.get(Device, "target-row")
    assert target is not None
    authenticated = _auth_snapshot(target)
    target.auth_version += 1
    api.session.commit()

    with pytest.raises(DeviceSessionError) as denied:
        await DeviceSessionService(
            api.service._session, now=lambda: datetime.now(UTC)
        ).approve(
            session_id="wan-session-1",
            current_device=target,
            auth_snapshot=authenticated,
            payload=DeviceSessionApprovalIn(
                approved_scopes=["screen.view"],
                approved_profile=None,
            ),
            relay_access=api.service,
        )
    assert denied.value.code == "wan_session_not_found"


@pytest.mark.anyio
async def test_auth_version_rotation_between_auth_and_access_lock_fails_closed(
    wan_relay_api: WanRelayAPI,
) -> None:
    api = wan_relay_api
    assert _create(api).status_code == 200
    assert _approve(api).status_code == 200
    controller = api.session.get(Device, "controller-row")
    assert controller is not None
    authenticated = _auth_snapshot(controller)
    controller.auth_version += 1
    api.session.commit()

    with pytest.raises(RelayAccessError) as denied:
        await api.service.issue_authenticated_access(
            current_device=controller,
            auth_snapshot=authenticated,
            session_id="wan-session-1",
            policy_revision=29,
            intended_peer_id="target-1",
            generation=0,
            refresh=False,
        )
    assert denied.value.code == "relay_access_denied"


def test_both_devices_fetch_identical_public_generation_but_scoped_credentials(
    wan_relay_api: WanRelayAPI,
) -> None:
    api = wan_relay_api
    assert _create(api).status_code == 200
    assert _approve(api).status_code == 200

    target = _access(api, caller="target-1")
    controller = _access(api, caller="controller-1")
    assert target.status_code == controller.status_code == 200
    target_body = target.json()
    controller_body = controller.json()
    assert set(target_body) == set(controller_body) == {
        "generation",
        "directory_id",
        "relay_url_digest",
        "directory",
        "credentials",
    }
    assert target_body["generation"] == controller_body["generation"] == 0
    assert target_body["directory_id"] == controller_body["directory_id"]
    assert target_body["relay_url_digest"] == controller_body["relay_url_digest"]
    assert _safe_access_projection(target_body) == _safe_access_projection(
        controller_body
    )
    assert api.credential_calls == [
        ("target-1", "relay-a"),
        ("target-1", "relay-b"),
        ("controller-1", "relay-a"),
        ("controller-1", "relay-b"),
    ]

    intruder = _access(api, caller="unrelated-1")
    mismatch = _access(api, caller="controller-1", generation=1)
    assert intruder.status_code == mismatch.status_code == 403
    assert intruder.json()["detail"] == mismatch.json()["detail"]

    sibling = _access(api, caller="target-sibling-1")
    downgraded = api.client.post(
        "/api/v1/relays/access",
        headers=_headers(api, "target-sibling-1"),
        json={
            "session_id": "wan-session-1",
            "policy_revision": 29,
            "intended_peer_id": "target-1",
        },
    )
    assert sibling.status_code == downgraded.status_code == 403


def test_generation_signs_the_endpoint_snapshot_locked_by_capacity_admission(
    wan_relay_api: WanRelayAPI,
) -> None:
    api = wan_relay_api
    assert _create(api).status_code == 200
    reserve = api.service._repository.reserve_capacity
    locked_url = "turn:relay-a-locked.example.test:3478?transport=udp"

    async def heartbeat_before_capacity_lock(**kwargs: object):
        node = api.session.get(RelayNode, "relay-a")
        assert node is not None
        node.endpoints = [locked_url]
        api.session.flush()
        return await reserve(**kwargs)

    api.service._repository.reserve_capacity = heartbeat_before_capacity_lock  # type: ignore[method-assign]
    approved = _approve(api)
    assert approved.status_code == 200
    persisted = api.session.get(RelayAccessGeneration, ("wan-session-1", 0))
    assert persisted is not None
    primary = next(
        candidate
        for candidate in persisted.signed_directory["payload"]["candidates"]
        if candidate["node_id"] == persisted.primary_node_id
    )
    assert primary["endpoints"] == [
        {
            "transport": "udp",
            "host": "relay-a-locked.example.test",
            "port": 3478,
        }
    ]
    assert _access(api, caller="controller-1").status_code == 200


def test_selected_cross_domain_backup_precedes_bounded_fallbacks(
    wan_relay_api: WanRelayAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = wan_relay_api
    assert _create(api).status_code == 200
    select_nodes = relay_directory_module.select_relay_nodes

    def put_valid_backup_ninth(*args: object, **kwargs: object):
        decision = select_nodes(*args, **kwargs)
        assert len(decision.selected) == 2
        primary, backup = decision.selected
        decoys = tuple(
            replace(primary, node_id=f"missing-relay-{index}")
            for index in range(1, 8)
        )
        return replace(decision, eligible=(primary, *decoys, backup))

    monkeypatch.setattr(
        relay_directory_module,
        "select_relay_nodes",
        put_valid_backup_ninth,
    )
    assert _approve(api).status_code == 200
    persisted = api.session.get(RelayAccessGeneration, ("wan-session-1", 0))
    assert persisted is not None
    assert len(persisted.reservation_ids) == 2


def test_access_locks_all_nodes_before_all_registrations(
    wan_relay_api: WanRelayAPI,
) -> None:
    api = wan_relay_api
    assert _create(api).status_code == 200
    assert _approve(api).status_code == 200
    shim = api.service._session
    shim.lock_trace.clear()

    assert _access(api, caller="controller-1").status_code == 200
    assert ("RelayNode", "RelayNodeRegistration") not in shim.lock_trace
    assert shim.lock_trace.index(("RelayNode",)) < shim.lock_trace.index(
        ("RelayNodeRegistration",)
    )


def test_primary_url_digest_matches_rust_framing_and_ipv6_rendering(
    wan_relay_api: WanRelayAPI,
) -> None:
    api = wan_relay_api
    assert _create(api).status_code == 200
    assert _approve(api).status_code == 200
    persisted = api.session.get(RelayAccessGeneration, ("wan-session-1", 0))
    assert persisted is not None
    directory = persisted.signed_directory["payload"]
    primary = next(
        candidate
        for candidate in directory["candidates"]
        if candidate["node_id"] == persisted.primary_node_id
    )
    urls = [
        _canonical_endpoint_url(RelayDirectoryEndpointOut.model_validate(endpoint))
        for endpoint in primary["endpoints"]
    ]
    assert persisted.relay_url_digest == _manual_urls_digest(urls)
    assert persisted.relay_url_digest == relay_url_digest(urls)
    assert all("@" not in url for url in urls)
    ipv6 = RelayDirectoryEndpointOut(transport="udp", host="::1", port=3478)
    ipv6_url = "turn:[::1]:3478?transport=udp"
    assert _canonical_endpoint_url(ipv6) == ipv6_url
    assert relay_url_digest([ipv6_url]) == _manual_urls_digest([ipv6_url])

    response = _access(api, caller="controller-1")
    assert response.status_code == 200
    public_credentials = [
        (item["node_id"], item["urls"], item["expires_at_unix_seconds"])
        for item in response.json()["credentials"]
    ]
    assert (
        next(item[1] for item in public_credentials if item[0] == primary["node_id"])
        == urls
    )


class FailingSigner:
    def sign(self, payload: object) -> object:
        raise RuntimeError("sensitive signer diagnostics")


def test_signing_failure_rolls_back_approval_and_all_partial_capacity(
    wan_relay_api: WanRelayAPI,
) -> None:
    api = wan_relay_api
    assert _create(api).status_code == 200
    release_calls: list[tuple[str, int]] = []
    release = api.service._repository.release_uncommitted_generation

    async def record_release(**kwargs: object):
        reservation_ids = kwargs["reservation_ids"]
        assert isinstance(reservation_ids, list)
        release_calls.append((str(kwargs["session_id"]), len(reservation_ids)))
        return await release(**kwargs)

    api.service._repository.release_uncommitted_generation = record_release  # type: ignore[method-assign]
    api.service._signer = FailingSigner()  # type: ignore[assignment]

    response = _approve(api)
    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "relay_signing_unavailable",
        "message": "relay access unavailable",
    }
    row = api.session.get(SessionRequest, "wan-session-1")
    assert row is not None and row.status == "requested"
    assert release_calls == [("wan-session-1", 2)]
    assert api.session.scalar(select(func.count()).select_from(RelayReservation)) == 0
    assert (
        api.session.scalar(select(func.count()).select_from(RelayAccessGeneration)) == 0
    )


@pytest.mark.parametrize("failure", ["capacity", "partial-repository"])
def test_selection_or_reservation_failure_releases_uncommitted_capacity(
    wan_relay_api: WanRelayAPI,
    failure: str,
) -> None:
    api = wan_relay_api
    assert _create(api).status_code == 200
    release_calls: list[tuple[str, object]] = []
    if failure == "capacity":
        for node in api.session.scalars(select(RelayNode)):
            node.active_allocations = node.max_allocations
        api.session.commit()
    else:
        reserve = api.service._repository.reserve_capacity
        release = api.service._repository.release_uncommitted_generation

        async def record_release(**kwargs: object):
            release_calls.append(
                (str(kwargs["directory_generation"]), kwargs["reservation_ids"])
            )
            return await release(**kwargs)

        async def fail_after_partial_reservation(**kwargs: object):
            await reserve(**kwargs)
            raise RelayRepositoryError(
                "CAPACITY_UNAVAILABLE", "internal reservation canary"
            )

        api.service._repository.reserve_capacity = fail_after_partial_reservation  # type: ignore[method-assign]
        api.service._repository.release_uncommitted_generation = record_release  # type: ignore[method-assign]

    response = _approve(api)
    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "relay_capacity_unavailable",
        "message": "relay capacity unavailable",
    }
    api.session.expire_all()
    row = api.session.get(SessionRequest, "wan-session-1")
    assert row is not None and row.status == "requested"
    assert row.policy_revision is None and row.active_relay_generation is None
    assert api.session.scalar(select(func.count()).select_from(RelayReservation)) == 0
    assert (
        api.session.scalar(select(func.count()).select_from(RelayAccessGeneration)) == 0
    )
    if failure == "partial-repository":
        assert len(release_calls) == 1
        assert release_calls[0][1] is None


class FailingCredentialIssuer:
    def issue(self, **_: object) -> object:
        raise RuntimeError("credential issuer internal canary")


def test_credential_failure_occurs_after_committed_generation_and_is_redacted(
    wan_relay_api: WanRelayAPI,
) -> None:
    api = wan_relay_api
    assert _create(api).status_code == 200
    assert _approve(api).status_code == 200
    persisted = api.session.get(RelayAccessGeneration, ("wan-session-1", 0))
    assert persisted is not None
    public_before = json.loads(json.dumps(persisted.signed_directory))
    reservation_count = api.session.scalar(
        select(func.count()).select_from(RelayReservation)
    )
    api.service._credential_issuer = FailingCredentialIssuer()  # type: ignore[assignment]

    response = _access(api, caller="controller-1")
    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "relay_credential_unavailable",
        "message": "relay access unavailable",
    }
    api.session.expire_all()
    after = api.session.get(RelayAccessGeneration, ("wan-session-1", 0))
    row = api.session.get(SessionRequest, "wan-session-1")
    assert after is not None and row is not None
    assert after.signed_directory == public_before
    assert row.status == "approved" and row.active_relay_generation == 0
    assert (
        api.session.scalar(select(func.count()).select_from(RelayReservation))
        == reservation_count
    )


@pytest.mark.parametrize("mutation", ["signature", "reservation", "endpoint"])
def test_persisted_generation_or_capacity_drift_fails_closed_before_credentials(
    wan_relay_api: WanRelayAPI,
    mutation: str,
) -> None:
    api = wan_relay_api
    assert _create(api).status_code == 200
    assert _approve(api).status_code == 200
    persisted = api.session.get(RelayAccessGeneration, ("wan-session-1", 0))
    assert persisted is not None
    if mutation == "signature":
        public = json.loads(json.dumps(persisted.signed_directory))
        public["signature_b64"] = "A" * 88
        persisted.signed_directory = public
        persisted.signature_b64 = "A" * 88
    elif mutation == "reservation":
        reservation = api.session.get(RelayReservation, persisted.reservation_ids[0])
        assert reservation is not None
        reservation.superseded_at = datetime.now(UTC)
    else:
        node = api.session.get(RelayNode, persisted.primary_node_id)
        assert node is not None
        node.endpoints = ["turn:changed.example.test:3478?transport=udp"]
    api.session.commit()

    response = _access(api, caller="controller-1")
    assert response.status_code == 403
    assert api.credential_calls == []


def test_expiry_revocation_and_generation_mismatch_fail_closed(
    wan_relay_api: WanRelayAPI,
) -> None:
    api = wan_relay_api
    assert _create(api).status_code == 200
    assert _approve(api).status_code == 200
    row = api.session.get(SessionRequest, "wan-session-1")
    assert row is not None
    row.policy_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    api.session.commit()
    expired = _access(api, caller="controller-1")
    assert expired.status_code == 403

    row.policy_expires_at = datetime.now(UTC) + timedelta(minutes=5)
    api.session.commit()
    revoked = api.client.post(
        "/api/v1/device-sessions/wan-session-1/revoke",
        headers=_headers(api, "target-1"),
        json={},
    )
    assert revoked.status_code == 200
    denied = _access(api, caller="controller-1")
    assert denied.status_code == 403


def test_refresh_serializes_next_generation_without_mutating_old_directory(
    wan_relay_api: WanRelayAPI,
) -> None:
    api = wan_relay_api
    assert _create(api).status_code == 200
    assert _approve(api).status_code == 200
    old = api.session.get(RelayAccessGeneration, ("wan-session-1", 0))
    assert old is not None
    old_public = json.loads(json.dumps(old.signed_directory))

    refreshed = _access(
        api,
        caller="controller-1",
        generation=0,
        refresh=True,
    )
    assert refreshed.status_code == 200
    assert set(refreshed.json()) == {
        "generation",
        "directory_id",
        "relay_url_digest",
        "directory",
        "credentials",
    }
    assert refreshed.json()["generation"] == 1
    assert refreshed.json()["directory_id"] == refreshed.json()["directory"]["payload"]["directory_id"]
    api.session.expire_all()
    old_after = api.session.get(RelayAccessGeneration, ("wan-session-1", 0))
    current = api.session.get(RelayAccessGeneration, ("wan-session-1", 1))
    row = api.session.get(SessionRequest, "wan-session-1")
    assert old_after is not None and current is not None and row is not None
    assert old_after.signed_directory == old_public
    assert row.active_relay_generation == 1

    stale = _access(api, caller="target-1", generation=0)
    active = _access(api, caller="target-1", generation=1)
    assert stale.status_code == 403
    assert active.status_code == 200


def test_failed_refresh_preserves_active_pointer_and_old_public_generation(
    wan_relay_api: WanRelayAPI,
) -> None:
    api = wan_relay_api
    assert _create(api).status_code == 200
    assert _approve(api).status_code == 200
    old = api.session.get(RelayAccessGeneration, ("wan-session-1", 0))
    assert old is not None
    public_before = json.loads(json.dumps(old.signed_directory))
    reservations_before = {
        item.id: (item.directory_generation, item.superseded_at)
        for item in api.session.scalars(
            select(RelayReservation).where(
                RelayReservation.session_id == "wan-session-1"
            )
        )
    }
    api.service._signer = FailingSigner()  # type: ignore[assignment]

    response = _access(
        api,
        caller="controller-1",
        generation=0,
        refresh=True,
    )
    assert response.status_code == 503
    api.session.expire_all()
    row = api.session.get(SessionRequest, "wan-session-1")
    old_after = api.session.get(RelayAccessGeneration, ("wan-session-1", 0))
    assert row is not None and old_after is not None
    assert row.active_relay_generation == 0
    assert old_after.signed_directory == public_before
    assert api.session.get(RelayAccessGeneration, ("wan-session-1", 1)) is None
    reservations_after = {
        item.id: (item.directory_generation, item.superseded_at)
        for item in api.session.scalars(
            select(RelayReservation).where(
                RelayReservation.session_id == "wan-session-1"
            )
        )
    }
    assert reservations_after == reservations_before


@pytest.mark.anyio
async def test_release_all_never_deletes_committed_generation_capacity(
    wan_relay_api: WanRelayAPI,
) -> None:
    api = wan_relay_api
    assert _create(api).status_code == 200
    assert _approve(api).status_code == 200
    persisted = api.session.get(RelayAccessGeneration, ("wan-session-1", 0))
    assert persisted is not None
    released = await api.service._repository.release_uncommitted_generation(
        session_id="wan-session-1",
        directory_generation=persisted.directory_id,
        reservation_ids=list(persisted.reservation_ids),
    )
    released_all = await api.service._repository.release_uncommitted_generation(
        session_id="wan-session-1",
        directory_generation=persisted.directory_id,
        reservation_ids=None,
    )
    assert released == released_all == 0
    assert api.session.scalar(select(func.count()).select_from(RelayReservation)) == 2


@pytest.mark.anyio
async def test_legacy_access_cannot_be_downgraded_or_written_as_wan_generation() -> (
    None
):
    engine, session, service = relay_service_fixture()
    current_device = SimpleNamespace(
        id="legacy-caller-device",
        device_id="legacy-caller-public",
        is_bound=True,
        bound_user_id="user-42",
        auth_version=1,
        tenant_id="tenant-a",
        auth_revoked_at=None,
    )
    auth_snapshot = _auth_snapshot(current_device)  # type: ignore[arg-type]
    try:
        first = await service.issue_authenticated_access(
            current_device=current_device,
            auth_snapshot=auth_snapshot,
            session_id="session-7",
            policy_revision=17,
            intended_peer_id="device-7",
            generation=None,
            refresh=False,
        )
        second = await service.issue_authenticated_access(
            current_device=current_device,
            auth_snapshot=auth_snapshot,
            session_id="session-7",
            policy_revision=17,
            intended_peer_id="device-7",
            generation=None,
            refresh=False,
        )
        assert (
            first.directory.payload.directory_id
            != second.directory.payload.directory_id
        )
        assert (
            session.scalar(select(func.count()).select_from(RelayAccessGeneration)) == 0
        )
        assert RelayAccessResult.__dataclass_fields__["credentials"].repr is False
        assert NodeTurnCredential.__dataclass_fields__["username"].repr is False
        assert NodeTurnCredential.__dataclass_fields__["credential"].repr is False
    finally:
        session.close()
        engine.dispose()
