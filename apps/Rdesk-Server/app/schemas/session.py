from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


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
