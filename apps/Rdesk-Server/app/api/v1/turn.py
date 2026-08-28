from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from pydantic import SecretStr

from app.core.config import settings
from app.core.security import get_current_user
from app.models.user import User
from app.services.turn_credentials import (
    TurnCredentialConfigurationError,
    TurnCredentialExpired,
    TurnCredentialService,
)


router = APIRouter(prefix="/turn", tags=["turn"])


def require_legacy_turn_credentials_enabled() -> None:
    if not settings.legacy_turn_credentials_enabled:
        raise HTTPException(status_code=404, detail="Not found")


class TurnCredentialRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    credential_deadline_unix_seconds: int = Field(gt=0)


class TurnCredentialResponse(BaseModel):
    urls: list[str]
    username: str
    credential: str
    expires_at_unix_seconds: int
    ttl_seconds: int
    transport_policy: str


def get_turn_credential_service() -> TurnCredentialService:
    configured_secret = settings.turn_auth_secret
    auth_secret = (
        configured_secret.get_secret_value()
        if isinstance(configured_secret, SecretStr)
        else configured_secret
    )
    return TurnCredentialService(
        auth_secret=auth_secret,
        urls=[item.strip() for item in settings.turn_urls.split(",") if item.strip()],
        ttl_seconds=settings.turn_credential_ttl_seconds,
    )

@router.post(
    "/credentials",
    response_model=TurnCredentialResponse,
    deprecated=True,
    dependencies=[Depends(require_legacy_turn_credentials_enabled)],
)
async def create_turn_credentials(
    payload: TurnCredentialRequest,
    current_user: User = Depends(get_current_user),
    issuer: TurnCredentialService = Depends(get_turn_credential_service),
) -> TurnCredentialResponse:
    try:
        credential = issuer.issue(
            user_id=current_user.id,
            session_id=payload.session_id,
            credential_deadline_unix_seconds=payload.credential_deadline_unix_seconds,
        )
    except TurnCredentialExpired as error:
        raise HTTPException(status_code=410, detail=str(error)) from error
    except TurnCredentialConfigurationError as error:
        raise HTTPException(status_code=503, detail="TURN is not configured") from error
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return TurnCredentialResponse(
        urls=list(credential.urls),
        username=credential.username,
        credential=credential.credential,
        expires_at_unix_seconds=credential.expires_at_unix_seconds,
        ttl_seconds=credential.ttl_seconds,
        transport_policy=credential.transport_policy,
    )
