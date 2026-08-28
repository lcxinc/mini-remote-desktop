from __future__ import annotations

import base64
import binascii
import re
import struct
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field


DIRECTORY_CONTEXT = b"MRD_RELAY_DIRECTORY_V1"
MAX_CANDIDATES = 8
MAX_ENDPOINTS = 4
MAX_STRING_BYTES = 256
MAX_CANONICAL_BYTES = 16 * 1024
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TRANSPORT_CODE = {"udp": 1, "tcp": 2, "tls": 3}


class RelayDirectoryEndpointOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transport: Literal["udp", "tcp", "tls"]
    host: str
    port: int = Field(ge=1, le=65_535)


class RelayReservationOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reservation_id: str
    expires_at_ms: int = Field(ge=0, le=2**64 - 1)


class RelayDirectoryCandidateOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_id: str
    region: str
    failure_domain: str
    endpoints: list[RelayDirectoryEndpointOut] = Field(min_length=1, max_length=4)
    capabilities: int = Field(ge=0, le=2**32 - 1)
    load_class: int = Field(ge=0, le=3)
    selection_reason: str
    reservation: RelayReservationOut


class RelayDirectoryPayloadOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format_version: int = Field(ge=0, le=2**16 - 1)
    policy_revision: int = Field(ge=0, le=2**64 - 1)
    directory_id: str
    issued_at_ms: int = Field(ge=0, le=2**64 - 1)
    expires_at_ms: int = Field(ge=0, le=2**64 - 1)
    session_id: str
    intended_peer_digest: str
    candidates: list[RelayDirectoryCandidateOut] = Field(min_length=1, max_length=8)


class SignedRelayDirectoryOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload: RelayDirectoryPayloadOut
    signing_key_id: str
    signature_b64: str = Field(repr=False)


def canonical_directory_bytes(payload: RelayDirectoryPayloadOut) -> bytes:
    if payload.format_version != 1:
        raise ValueError("unsupported directory format version")
    if payload.policy_revision == 0:
        raise ValueError("invalid directory policy revision")
    if payload.issued_at_ms >= payload.expires_at_ms:
        raise ValueError("invalid directory validity window")
    if not 1 <= len(payload.candidates) <= MAX_CANDIDATES:
        raise ValueError("invalid directory candidate count")

    node_ids = [candidate.node_id.encode("utf-8") for candidate in payload.candidates]
    if node_ids != sorted(node_ids) or len(node_ids) != len(set(node_ids)):
        raise ValueError("directory candidates are not canonical")
    reservation_ids = [candidate.reservation.reservation_id for candidate in payload.candidates]
    if len(reservation_ids) != len(set(reservation_ids)):
        raise ValueError("directory reservations are not unique")

    encoded = bytearray(DIRECTORY_CONTEXT)
    encoded.extend(struct.pack(">HQ", payload.format_version, payload.policy_revision))
    _push_string(encoded, payload.directory_id)
    encoded.extend(struct.pack(">QQ", payload.issued_at_ms, payload.expires_at_ms))
    _push_string(encoded, payload.session_id)
    _push_string(encoded, payload.intended_peer_digest)
    encoded.extend(struct.pack(">I", len(payload.candidates)))

    for candidate in payload.candidates:
        _push_string(encoded, candidate.node_id)
        _push_string(encoded, candidate.region)
        _push_string(encoded, candidate.failure_domain)
        if not 1 <= len(candidate.endpoints) <= MAX_ENDPOINTS:
            raise ValueError("invalid directory endpoint count")
        endpoint_keys = [
            (_TRANSPORT_CODE[endpoint.transport], endpoint.host.encode("utf-8"), endpoint.port)
            for endpoint in candidate.endpoints
        ]
        if endpoint_keys != sorted(endpoint_keys) or len(endpoint_keys) != len(set(endpoint_keys)):
            raise ValueError("directory endpoints are not canonical")
        encoded.extend(struct.pack(">I", len(candidate.endpoints)))
        for endpoint in candidate.endpoints:
            encoded.append(_TRANSPORT_CODE[endpoint.transport])
            _push_string(encoded, endpoint.host)
            encoded.extend(struct.pack(">H", endpoint.port))
        encoded.extend(struct.pack(">IB", candidate.capabilities, candidate.load_class))
        _push_string(encoded, candidate.selection_reason)
        _push_string(encoded, candidate.reservation.reservation_id)
        reservation_expiry = candidate.reservation.expires_at_ms
        if not payload.issued_at_ms < reservation_expiry <= payload.expires_at_ms:
            raise ValueError("invalid directory reservation expiry")
        encoded.extend(struct.pack(">Q", reservation_expiry))

    if len(encoded) > MAX_CANONICAL_BYTES:
        raise ValueError("directory canonical representation is too large")
    return bytes(encoded)


class Ed25519RelayDirectorySigner:
    def __init__(self, *, key_id: str, private_key_seed: bytes) -> None:
        if _KEY_ID.fullmatch(key_id) is None:
            raise ValueError("directory signing key id is invalid")
        if not isinstance(private_key_seed, bytes) or len(private_key_seed) != 32:
            raise ValueError("directory signing key seed must contain exactly 32 bytes")
        self._key_id = key_id
        self._private_key = Ed25519PrivateKey.from_private_bytes(private_key_seed)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(key_id={self._key_id!r}, private_key=<redacted>)"

    def sign(self, payload: RelayDirectoryPayloadOut) -> SignedRelayDirectoryOut:
        signature = self._private_key.sign(canonical_directory_bytes(payload))
        return SignedRelayDirectoryOut(
            payload=payload,
            signing_key_id=self._key_id,
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )


def verify_signed_directory(
    directory: SignedRelayDirectoryOut, *, public_key: bytes
) -> bool:
    try:
        if len(public_key) != 32:
            return False
        signature = base64.b64decode(directory.signature_b64, validate=True)
        if (
            len(signature) != 64
            or base64.b64encode(signature).decode("ascii")
            != directory.signature_b64
        ):
            return False
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, canonical_directory_bytes(directory.payload)
        )
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False


def _push_string(encoded: bytearray, value: str) -> None:
    if not isinstance(value, str):
        raise ValueError("directory string field is invalid")
    raw = value.encode("utf-8")
    if not 1 <= len(raw) <= MAX_STRING_BYTES:
        raise ValueError("directory string field is invalid")
    encoded.extend(struct.pack(">I", len(raw)))
    encoded.extend(raw)
