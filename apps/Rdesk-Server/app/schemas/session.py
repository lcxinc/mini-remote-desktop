from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SessionRequestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_device_id: str = Field(
        min_length=1,
        max_length=36,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,35}$",
    )


class SessionRequestOut(BaseModel):
    request_id: str
    signaling_url: str
    room: str
    status: str


class SessionApprovalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SessionApprovalOut(BaseModel):
    request_id: str
    status: str
    grant_expires_at: datetime
    policy_revision: int
    policy_expires_at: datetime
    intended_peer_id: str


class SessionTransitionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SessionTransitionOut(BaseModel):
    request_id: str
    status: str


WanPermissionScopeV3 = Literal[
    "audio.listen",
    "audio.talk",
    "clipboard.read",
    "clipboard.write",
    "display.multi_view",
    "display.switch",
    "file.read",
    "file.write",
    "input.keyboard",
    "input.pointer",
    "power.restart",
    "power.shutdown",
    "privacy.blank_screen",
    "privacy.block_local_input",
    "screen.view",
    "secure_desktop.control",
    "secure_desktop.view",
    "terminal.open",
]
NormalizedWanToken = Annotated[
    str,
    Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9._:+-]{1,64}$",
    ),
]
DeviceSessionId = Annotated[
    str,
    Field(
        min_length=1,
        max_length=36,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,35}$",
    ),
]
PublicDeviceId = Annotated[
    str,
    Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
    ),
]


class WanMediaProfileV3(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    width: int = Field(ge=1, le=16_384)
    height: int = Field(ge=1, le=16_384)
    fps: int = Field(ge=1, le=240)
    bitrate_mbps: int = Field(ge=1, le=1_000)
    codec: Annotated[
        str,
        Field(
            min_length=1,
            max_length=32,
            pattern=r"^[a-z0-9._:+-]{1,32}$",
        ),
    ]
    codec_profile: NormalizedWanToken | None = None
    bit_depth: Literal[8, 10] | None = None
    chroma_subsampling: NormalizedWanToken | None = None
    pixel_format: NormalizedWanToken | None = None
    hdr_enabled: bool | None = None
    color_mode: NormalizedWanToken | None = None
    color_pipeline: NormalizedWanToken | None = None


class _WanRequestBase(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    session_id: DeviceSessionId
    idempotency_key: list[int] = Field(min_length=16, max_length=16)

    @field_validator("idempotency_key")
    @classmethod
    def validate_idempotency_key(cls, value: list[int]) -> list[int]:
        if any(isinstance(item, bool) or not 0 <= item <= 255 for item in value):
            raise ValueError("idempotency key is invalid")
        if value == [0] * 16:
            raise ValueError("idempotency key is invalid")
        return value

    @field_validator("requested_scopes", check_fields=False)
    @classmethod
    def validate_requested_scopes(
        cls, value: list[WanPermissionScopeV3]
    ) -> list[WanPermissionScopeV3]:
        if not 1 <= len(value) <= 32 or any(
            left >= right for left, right in zip(value, value[1:])
        ):
            raise ValueError("requested scopes are not normalized")
        return value


class DeviceSessionCreateIn(_WanRequestBase):
    target_device_id: PublicDeviceId
    access_mode: Literal["attended"]
    requested_scopes: list[WanPermissionScopeV3] = Field(min_length=1, max_length=32)
    requested_profile: WanMediaProfileV3 | None = None
    route_policy: Literal["relay_only"]


class DeviceSessionCanonicalRequest(_WanRequestBase):
    controller_device_id: PublicDeviceId
    target_device_id: PublicDeviceId
    access_mode: Literal["attended"]
    requested_scopes: list[WanPermissionScopeV3] = Field(min_length=1, max_length=32)
    requested_profile: WanMediaProfileV3 | None = None
    route_policy: Literal["relay_only"]


class DeviceSessionOut(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    session_id: DeviceSessionId
    request: DeviceSessionCanonicalRequest
    request_commitment: Annotated[
        str, Field(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64)
    ]
    status: Literal["requested", "approved", "rejected", "expired", "closed", "revoked"]
    approved_scopes: list[WanPermissionScopeV3] | None = None
    approved_profile: WanMediaProfileV3 | None = None
    policy_revision: int | None = None
    policy_expires_at: datetime | None = None
    grant_expires_at: datetime | None = None
    active_relay_generation: int | None = Field(default=None, ge=0)


class DeviceSessionTransitionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
