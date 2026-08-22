from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, SecretStr, StringConstraints


RelayId = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    ),
]
Region = Annotated[
    str,
    StringConstraints(
        min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]{0,63}$"
    ),
]
Endpoint = Annotated[str, StringConstraints(min_length=1, max_length=512)]


class EnrollmentTokenRequest(BaseModel):
    ttl_seconds: int = Field(ge=60, le=3600)


class EnrollmentTokenResponse(BaseModel):
    token: str = Field(min_length=40, max_length=512, repr=False)
    expires_at: datetime


class RelayEnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: SecretStr = Field(repr=False)
    node_id: RelayId
    region: Region
    failure_domain: RelayId
    endpoints: list[Endpoint] = Field(min_length=1, max_length=4)
    max_allocations: int = Field(ge=1, le=2**31 - 1)
    max_egress_bps: int = Field(ge=1, le=2**63 - 1)
    csr_pem: str = Field(min_length=100, max_length=16_384, repr=False)


class RelayEnrollmentResponse(BaseModel):
    node_id: RelayId
    status: str


class RelayApprovalResponse(BaseModel):
    node_id: RelayId
    certificate_pem: str
    ca_certificate_pem: str
    fingerprint: str
    expires_at: datetime


class RelayHeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    active_allocations: int = Field(strict=True, ge=0, le=2**31 - 1)
    current_egress_bps: int = Field(strict=True, ge=0, le=2**63 - 1)
    endpoints: list[Endpoint] = Field(min_length=1, max_length=4)


class RelayHeartbeatResponse(BaseModel):
    node_id: RelayId
    state: str
    sequence: int
    lease_expires_at: datetime


class RelayNodeResponse(BaseModel):
    node_id: RelayId
    region: Region
    failure_domain: RelayId
    state: str
    endpoints: list[str]
    max_allocations: int
    active_allocations: int
    max_egress_bps: int
    current_egress_bps: int
    lease_expires_at: datetime | None
    revoked_at: datetime | None
