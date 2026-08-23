from __future__ import annotations

import base64
import binascii
from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    StringConstraints,
    field_validator,
    model_validator,
)


def _canonical_base64url_32(value: str) -> str:
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (ValueError, binascii.Error):
        raise ValueError("value must be canonical base64url") from None
    if (
        len(decoded) != 32
        or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value
    ):
        raise ValueError("value must be canonical base64url")
    return value


RelayId = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    ),
]
CredentialSafeRelayId = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    ),
]
Region = Annotated[
    str,
    StringConstraints(
        min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]{0,63}$"
    ),
]
Endpoint = Annotated[str, StringConstraints(min_length=1, max_length=512)]
RotationId = Annotated[
    str,
    StringConstraints(
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$",
    ),
]
BootId = Annotated[
    str, StringConstraints(min_length=22, max_length=22, pattern=r"^[A-Za-z0-9_-]{22}$")
]
RequestNonce = Annotated[
    str,
    StringConstraints(min_length=43, max_length=43, pattern=r"^[A-Za-z0-9_-]{43}$"),
    AfterValidator(_canonical_base64url_32),
]


class EnrollmentTokenRequest(BaseModel):
    ttl_seconds: int = Field(ge=60, le=3600)


class EnrollmentTokenResponse(BaseModel):
    token: str = Field(min_length=40, max_length=512, repr=False)
    expires_at: datetime


class RelayEnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: SecretStr = Field(repr=False)
    node_id: CredentialSafeRelayId
    region: Region
    failure_domain: RelayId
    endpoints: list[Endpoint] = Field(min_length=1, max_length=4)
    max_allocations: int = Field(ge=1, le=2**31 - 1)
    max_egress_bps: int = Field(ge=1, le=2**63 - 1)
    csr_pem: str = Field(min_length=100, max_length=16_384, repr=False)
    turn_rest_secret: SecretStr = Field(repr=False)

    @field_validator("turn_rest_secret")
    @classmethod
    def validate_turn_rest_secret(cls, value: SecretStr) -> SecretStr:
        encoded = value.get_secret_value()
        if (
            len(encoded) != 43
            or not encoded.isascii()
            or any(
                character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
                for character in encoded
            )
        ):
            raise ValueError("TURN REST secret must be canonical base64url")
        return value


class RelayEnrollmentResponse(BaseModel):
    enrollment_id: str
    node_id: RelayId
    status: str
    receipt: str = Field(min_length=40, max_length=512, repr=False)


class RelayEnrollmentPickupResponse(BaseModel):
    enrollment_id: str
    node_id: RelayId
    status: str
    certificate_pem: str | None = Field(default=None, repr=False)
    ca_certificate_pem: str | None = Field(default=None, repr=False)
    expires_at: datetime | None = None


class RelayApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    failure_domain: CredentialSafeRelayId
    physical_host_id: CredentialSafeRelayId


class RelayRenewalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    renewal_id: RelayId
    csr_pem: str = Field(min_length=100, max_length=16_384, repr=False)


class RelayRenewalResponse(BaseModel):
    renewal_id: RelayId
    node_id: RelayId
    certificate_pem: str = Field(repr=False)
    ca_certificate_pem: str = Field(repr=False)
    fingerprint: str
    expires_at: datetime


class RelayApprovalResponse(BaseModel):
    node_id: RelayId
    status: str


class RelayHeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_epoch: int = Field(strict=True, ge=1, le=2**63 - 1)
    boot_id: BootId
    nonce: RequestNonce
    process_health: Literal["healthy", "degraded", "failed"]
    listener_health: Literal["healthy", "degraded", "failed"]
    probe_health: Literal["healthy", "failed", "non_evidence"]
    active_allocations: int = Field(strict=True, ge=0, le=2**31 - 1)
    current_ingress_bps: int = Field(strict=True, ge=0, le=2**63 - 1)
    current_egress_bps: int = Field(strict=True, ge=0, le=2**63 - 1)
    max_allocations: int = Field(strict=True, ge=1, le=2**31 - 1)
    max_egress_bps: int = Field(strict=True, ge=1, le=2**63 - 1)
    packet_loss_bps: int = Field(strict=True, ge=0, le=10_000)
    cpu_usage_bps: int = Field(strict=True, ge=0, le=10_000)
    memory_usage_bps: int = Field(strict=True, ge=0, le=10_000)
    measured_rtt_ms: int | None = Field(
        default=None, strict=True, ge=0, le=2**32 - 1
    )
    recent_failure_bps: int = Field(default=0, strict=True, ge=0, le=10_000)
    endpoints: list[Endpoint] = Field(min_length=1, max_length=4)
    applied_secret_version: int = Field(strict=True, ge=1, le=2**63 - 1)


class RelayDesiredState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    draining: bool
    secret_version: int = Field(strict=True, ge=1, le=2**63 - 1)
    not_before: datetime | None
    old_credential_deadline: datetime | None
    rotation_challenge: RequestNonce | None = None

    @model_validator(mode="after")
    def validate_rotation_fields(self) -> "RelayDesiredState":
        has_rotation_window = self.not_before is not None
        if (
            has_rotation_window != (self.old_credential_deadline is not None)
            or has_rotation_window != (self.rotation_challenge is not None)
            or (
                self.not_before is not None
                and self.old_credential_deadline is not None
                and self.old_credential_deadline < self.not_before
            )
        ):
            raise ValueError("desired rotation fields must be present together")
        return self


class RelayHeartbeatResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_id: RelayId
    identity_epoch: int = Field(strict=True, ge=1, le=2**63 - 1)
    state: Literal["available", "degraded", "draining", "unavailable", "revoked"]
    sequence: int = Field(strict=True, ge=1, le=2**63 - 1)
    desired: RelayDesiredState
    lease_expires_at: datetime


class RelaySecretRotationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential_ttl_seconds: int = Field(strict=True, ge=60, le=3600)


class RelaySecretRotationDirective(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_id: RelayId
    identity_epoch: int = Field(strict=True, ge=1, le=2**63 - 1)
    secret_version: int = Field(strict=True, ge=2, le=2**63 - 1)
    draining: Literal[True]
    not_before: datetime
    old_credential_deadline: datetime
    rotation_challenge: RequestNonce


class RelaySecretUploadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_epoch: int = Field(strict=True, ge=1, le=2**63 - 1)
    rotation_id: RotationId
    secret_version: int = Field(strict=True, ge=2, le=2**63 - 1)
    turn_rest_secret: SecretStr = Field(repr=False)

    _validate_secret = field_validator("turn_rest_secret")(
        RelayEnrollmentRequest.validate_turn_rest_secret.__func__
    )


class RelaySecretUploadResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_id: RelayId
    identity_epoch: int
    rotation_id: RotationId
    secret_version: int
    status: Literal["uploaded"]


class RelaySecretCommitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_epoch: int = Field(strict=True, ge=1, le=2**63 - 1)
    rotation_id: RotationId
    secret_version: int = Field(strict=True, ge=2, le=2**63 - 1)
    rotation_challenge: RequestNonce
    probe_evidence_sha256: str = Field(
        min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"
    )
    proof_mac: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")


class RelaySecretCommitResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_id: RelayId
    identity_epoch: int
    rotation_id: RotationId
    active_secret_version: int
    status: Literal["committed"]


class RelayNodeResponse(BaseModel):
    node_id: RelayId
    region: Region
    failure_domain: RelayId
    physical_host_id: RelayId | None = None
    state: str
    endpoints: list[str]
    max_allocations: int
    active_allocations: int
    max_egress_bps: int
    current_egress_bps: int
    lease_expires_at: datetime | None
    revoked_at: datetime | None


class RelayRevocationResponse(BaseModel):
    node_id: RelayId
    state: Literal["revoked"]


class RelayErrorDetail(BaseModel):
    code: str
    message: str


class RelayErrorResponse(BaseModel):
    detail: RelayErrorDetail
