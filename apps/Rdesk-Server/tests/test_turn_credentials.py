import base64
import hashlib
import hmac
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.turn import (
    get_turn_credential_service,
    require_legacy_turn_credentials_enabled,
    router,
)
from app.core.security import get_current_user
from app.core.response_security import SensitiveResponseCacheMiddleware
from app.services.turn_credentials import (
    NodeTurnCredentialService,
    TurnCredentialExpired,
    TurnCredentialService,
)


NOW = 1_800_000_000
SECRET = "test-turn-secret"


def service() -> TurnCredentialService:
    return TurnCredentialService(
        auth_secret=SECRET,
        urls=[
            "turn:relay.example.test:3478?transport=udp",
            "turns:relay.example.test:5349?transport=tcp",
        ],
        ttl_seconds=600,
        now=lambda: NOW,
    )


def app(*, authenticated: bool, legacy_enabled: bool = False) -> FastAPI:
    test_app = FastAPI()
    test_app.add_middleware(SensitiveResponseCacheMiddleware)
    test_app.include_router(router, prefix="/api/v1")
    test_app.dependency_overrides[get_turn_credential_service] = service
    if legacy_enabled:
        test_app.dependency_overrides[require_legacy_turn_credentials_enabled] = lambda: None
    if authenticated:
        test_app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
            id="user-42"
        )
    return test_app


def test_sensitive_cache_middleware_does_not_disable_ordinary_api_caching():
    test_app = app(authenticated=False)

    @test_app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    response = TestClient(test_app).get("/healthz")
    assert response.status_code == 200
    assert "cache-control" not in response.headers
    assert "pragma" not in response.headers


def test_legacy_caller_deadline_route_is_disabled_by_default_and_deprecated():
    test_app = app(authenticated=True)
    response = TestClient(test_app).post(
        "/api/v1/turn/credentials",
        json={
            "session_id": "session-7",
            "credential_deadline_unix_seconds": NOW + 300,
        },
    )
    assert response.status_code == 404
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"
    operation = test_app.openapi()["paths"]["/api/v1/turn/credentials"]["post"]
    assert operation["deprecated"] is True


def test_explicit_development_flag_preserves_bounded_legacy_credentials():
    client = TestClient(app(authenticated=True, legacy_enabled=True))
    response = client.post(
        "/api/v1/turn/credentials",
        json={
            "session_id": "session-7",
            "credential_deadline_unix_seconds": NOW + 300,
        },
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["pragma"] == "no-cache"
    payload = response.json()
    assert payload["expires_at_unix_seconds"] == NOW + 300
    assert payload["username"] == f"{NOW + 300}:user-42:session-7"


class RecordingCipher:
    def __init__(self, secrets_by_node: dict[str, bytes]) -> None:
        self.secrets_by_node = secrets_by_node
        self.decrypt_calls: list[tuple[bytes, bytes]] = []

    def decrypt(self, ciphertext: bytes, *, associated_data: bytes) -> bytes:
        self.decrypt_calls.append((ciphertext, associated_data))
        return self.secrets_by_node[associated_data.decode()]

    def decrypt_mutable(
        self, ciphertext: bytes, *, associated_data: bytes
    ) -> bytearray:
        return bytearray(self.decrypt(ciphertext, associated_data=associated_data))

    def encrypt(self, plaintext: bytes, *, associated_data: bytes) -> bytes:
        return b"active:" + associated_data + b":" + plaintext

    def needs_reencrypt(self, ciphertext: bytes) -> bool:
        return False


class MutableRecordingCipher:
    def __init__(self) -> None:
        self.buffer: bytearray | None = None

    def decrypt_mutable(
        self, ciphertext: bytes, *, associated_data: bytes
    ) -> bytearray:
        assert ciphertext == b"ciphertext-a"
        assert associated_data == b"relay-a"
        self.buffer = bytearray(hashlib.sha256(b"relay-a-unique-secret").digest())
        return self.buffer

    def encrypt(self, plaintext: bytes, *, associated_data: bytes) -> bytes:
        return b"active-envelope"

    def needs_reencrypt(self, ciphertext: bytes) -> bool:
        return False


def test_node_credential_matches_coturn_canonical_secret_string() -> None:
    canonical_secret = base64.urlsafe_b64encode(
        hashlib.sha256(b"coturn-wire-secret").digest()
    ).rstrip(b"=")
    cipher = RecordingCipher({"relay-a": canonical_secret})
    issued = NodeTurnCredentialService(
        cipher=cipher, ttl_seconds=600, now=lambda: NOW
    ).issue(
        user_id="user-42",
        session_id="session-7",
        node_id="relay-a",
        urls=["turn:relay-a.example.test:3478?transport=udp"],
        encrypted_secret=b"active-envelope",
        grant_deadline_unix_seconds=NOW + 300,
        directory_deadline_unix_seconds=NOW + 300,
        policy_deadline_unix_seconds=NOW + 300,
        node_deadline_unix_seconds=NOW + 300,
    )
    expected = base64.b64encode(
        hmac.new(
            canonical_secret, issued.username.encode("utf-8"), hashlib.sha1
        ).digest()
    ).decode("ascii")
    assert hmac.compare_digest(issued.credential, expected)
    assert issued.reencrypted_secret is None


def test_node_credential_upgrades_legacy_raw_secret_to_wire_string() -> None:
    legacy_raw = hashlib.sha256(b"legacy-raw-secret").digest()
    canonical_secret = base64.urlsafe_b64encode(legacy_raw).rstrip(b"=")
    cipher = RecordingCipher({"relay-a": legacy_raw})
    issued = NodeTurnCredentialService(
        cipher=cipher, ttl_seconds=600, now=lambda: NOW
    ).issue(
        user_id="user-42",
        session_id="session-7",
        node_id="relay-a",
        urls=["turn:relay-a.example.test:3478?transport=udp"],
        encrypted_secret=b"active-but-legacy-envelope",
        grant_deadline_unix_seconds=NOW + 300,
        directory_deadline_unix_seconds=NOW + 300,
        policy_deadline_unix_seconds=NOW + 300,
        node_deadline_unix_seconds=NOW + 300,
    )
    expected = base64.b64encode(
        hmac.new(
            canonical_secret, issued.username.encode("utf-8"), hashlib.sha1
        ).digest()
    ).decode("ascii")
    assert hmac.compare_digest(issued.credential, expected)
    assert issued.reencrypted_secret == b"active:relay-a:" + canonical_secret


def test_node_credential_uses_and_clears_the_cipher_mutable_buffer() -> None:
    cipher = MutableRecordingCipher()
    issuer = NodeTurnCredentialService(
        cipher=cipher, ttl_seconds=600, now=lambda: NOW
    )
    credential = issuer.issue(
        user_id="user-42",
        session_id="session-7",
        node_id="relay-a",
        urls=["turn:relay-a.example.test:3478?transport=udp"],
        encrypted_secret=b"ciphertext-a",
        grant_deadline_unix_seconds=NOW + 300,
        directory_deadline_unix_seconds=NOW + 300,
        policy_deadline_unix_seconds=NOW + 300,
        node_deadline_unix_seconds=NOW + 300,
    )
    assert credential.username == f"{NOW + 300}:user-42:session-7:relay-a"
    assert cipher.buffer is not None
    assert cipher.buffer == bytearray(len(cipher.buffer))


@pytest.mark.parametrize(
    ("deadlines", "expected"),
    [
        ((NOW + 900, NOW + 800, NOW + 700, NOW + 650), NOW + 600),
        ((NOW + 500, NOW + 800, NOW + 700, NOW + 650), NOW + 500),
        ((NOW + 900, NOW + 400, NOW + 700, NOW + 650), NOW + 400),
        ((NOW + 900, NOW + 800, NOW + 300, NOW + 650), NOW + 300),
        ((NOW + 900, NOW + 800, NOW + 700, NOW + 200), NOW + 200),
    ],
)
def test_node_credential_ttl_is_exact_minimum_of_all_server_deadlines(
    deadlines: tuple[int, int, int, int], expected: int
):
    relay_a_secret = base64.urlsafe_b64encode(
        hashlib.sha256(b"relay-a-unique-secret").digest()
    ).rstrip(b"=")
    cipher = RecordingCipher({"relay-a": relay_a_secret})
    issuer = NodeTurnCredentialService(
        cipher=cipher, ttl_seconds=600, now=lambda: NOW
    )
    grant, directory, policy, certificate = deadlines
    credential = issuer.issue(
        user_id="user-42",
        session_id="session-7",
        node_id="relay-a",
        urls=["turn:relay-a.example.test:3478?transport=udp"],
        encrypted_secret=b"ciphertext-a",
        grant_deadline_unix_seconds=grant,
        directory_deadline_unix_seconds=directory,
        policy_deadline_unix_seconds=policy,
        node_deadline_unix_seconds=certificate,
    )
    assert credential.expires_at_unix_seconds == expected
    assert credential.username == f"{expected}:user-42:session-7:relay-a"
    expected_hmac = base64.b64encode(
        hmac.new(relay_a_secret, credential.username.encode(), hashlib.sha1).digest()
    ).decode()
    assert hmac.compare_digest(credential.credential, expected_hmac)
    assert cipher.decrypt_calls == [(b"ciphertext-a", b"relay-a")]
    assert "relay-a-unique-secret" not in repr(credential)
    assert credential.credential not in repr(credential)


def test_node_credentials_are_secret_isolated_and_expire_at_exact_now():
    relay_a_secret = base64.urlsafe_b64encode(
        hashlib.sha256(b"relay-a-unique-secret").digest()
    ).rstrip(b"=")
    relay_b_secret = base64.urlsafe_b64encode(
        hashlib.sha256(b"relay-b-unique-secret").digest()
    ).rstrip(b"=")
    cipher = RecordingCipher({
        "relay-a": relay_a_secret,
        "relay-b": relay_b_secret,
    })
    issuer = NodeTurnCredentialService(cipher=cipher, ttl_seconds=600, now=lambda: NOW)
    common = dict(
        user_id="user-42", session_id="session-7",
        grant_deadline_unix_seconds=NOW + 300,
        directory_deadline_unix_seconds=NOW + 300,
        policy_deadline_unix_seconds=NOW + 300,
        node_deadline_unix_seconds=NOW + 300,
    )
    a = issuer.issue(
        **common,
        node_id="relay-a",
        urls=["turn:relay-a.example.test:3478?transport=udp"],
        encrypted_secret=b"ciphertext-a",
    )
    b = issuer.issue(
        **common,
        node_id="relay-b",
        urls=["turn:relay-b.example.test:3478?transport=udp"],
        encrypted_secret=b"ciphertext-b",
    )
    assert not NodeTurnCredentialService.verify_with_secret(
        a.username, a.credential, relay_b_secret, now=NOW
    )
    assert NodeTurnCredentialService.verify_with_secret(
        b.username, b.credential, relay_b_secret, now=NOW
    )
    assert not NodeTurnCredentialService.verify_with_secret(
        b.username, b.credential, relay_b_secret, now=NOW + 300
    )
    with pytest.raises(TurnCredentialExpired):
        issuer.issue(
            **{**common, "grant_deadline_unix_seconds": NOW},
            node_id="relay-a",
            urls=["turn:relay-a.example.test:3478?transport=udp"],
            encrypted_secret=b"ciphertext-a",
        )


def test_node_credential_returns_active_envelope_for_old_read_key() -> None:
    class RotatingCipher(RecordingCipher):
        def needs_reencrypt(self, ciphertext: bytes) -> bool:
            return ciphertext == b"old-envelope"

    secret = base64.urlsafe_b64encode(
        hashlib.sha256(b"rotation-secret").digest()
    ).rstrip(b"=")
    cipher = RotatingCipher({"relay-a": secret})
    issued = NodeTurnCredentialService(
        cipher=cipher, ttl_seconds=60, now=lambda: NOW
    ).issue(
        user_id="user-42",
        session_id="session-7",
        node_id="relay-a",
        urls=["turn:relay-a.example.test:3478?transport=udp"],
        encrypted_secret=b"old-envelope",
        grant_deadline_unix_seconds=NOW + 30,
        directory_deadline_unix_seconds=NOW + 30,
        policy_deadline_unix_seconds=NOW + 30,
        node_deadline_unix_seconds=NOW + 30,
    )
    assert issued.reencrypted_secret == b"active:relay-a:" + secret
    assert secret.hex() not in repr(issued)


def test_legacy_service_rejects_invalid_scope_and_caps_ttl():
    issuer = service()
    credential = issuer.issue(
        user_id="user-42",
        session_id="session-7",
        credential_deadline_unix_seconds=NOW + 3_600,
    )
    assert credential.expires_at_unix_seconds == NOW + 600
    assert issuer.verify(credential.username, credential.credential, NOW + 599)
    assert not issuer.verify(credential.username, credential.credential, NOW + 600)
    with pytest.raises(ValueError, match="session_id"):
        issuer.issue(
            user_id="user-42",
            session_id="bad:scope",
            credential_deadline_unix_seconds=NOW + 300,
        )
