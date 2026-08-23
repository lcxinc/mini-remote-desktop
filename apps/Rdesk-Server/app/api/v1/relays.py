from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
from typing import Annotated, Callable, Coroutine

from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Request,
    Security,
    status,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from app.core.config import settings
from app.core.security import (
    get_current_user,
    get_verified_relay_node,
    get_verified_relay_renewal_node,
    require_admin,
    trusted_mtls_proxy_scheme,
)
from app.db.session import get_db
from app.models.relay_node import RelayNode
from app.models.user import User
from app.schemas.relay import (
    EnrollmentTokenRequest,
    EnrollmentTokenResponse,
    RelayApprovalResponse,
    RelayApprovalRequest,
    RelayEnrollmentRequest,
    RelayEnrollmentResponse,
    RelayEnrollmentPickupResponse,
    RelayErrorResponse,
    RelayHeartbeatRequest,
    RelayHeartbeatResponse,
    RelayNodeResponse,
    RelayRevocationResponse,
    RelayRenewalRequest,
    RelayRenewalResponse,
)
from app.services.relay_node_auth import RelayAuthError, require_trusted_proxy
from app.services.relay_registry import (
    RelayIdentity,
    RelayRegistry,
    RelayRegistryError,
)
from app.services.relay_directory import RelayAccessError, RelayAccessService
from app.services.relay_repository import AesGcmRelaySecretCipher, RelayRepository
from app.services.relay_signing import (
    Ed25519RelayDirectorySigner,
    SignedRelayDirectoryOut,
)
from app.services.turn_credentials import NodeTurnCredentialService


class RelayAPIRoute(APIRoute):
    """Return stable relay-domain codes instead of raw validator diagnostics."""

    def get_route_handler(self) -> Callable[..., Coroutine[object, object, object]]:
        original = super().get_route_handler()

        async def stable_validation_handler(request: Request):
            try:
                return await original(request)
            except RequestValidationError:
                if request.url.path.endswith("/heartbeat"):
                    code = "relay_metrics_invalid"
                elif request.url.path.endswith("/access"):
                    code = "relay_access_invalid"
                else:
                    code = "relay_enrollment_invalid"
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"detail": {"code": code, "message": "relay request invalid"}},
                )

        return stable_validation_handler


_RELAY_ERROR_RESPONSES = {
    code: {
        "model": RelayErrorResponse,
        "description": "Stable relay-domain error response.",
    }
    for code in (400, 401, 403, 404, 409, 413, 503)
}


router = APIRouter(
    prefix="/relays",
    tags=["relays"],
    route_class=RelayAPIRoute,
    responses=_RELAY_ERROR_RESPONSES,
)

_HEARTBEAT_OPENAPI_PATH = "/api/v1/relays/{node_id}/heartbeat"
_RENEWAL_OPENAPI_PATH = "/api/v1/relays/{node_id}/renew"
_PICKUP_OPENAPI_PATH = "/api/v1/relays/enrollments/{enrollment_id}/pickup"
_HEARTBEAT_AUTH_HEADERS = {
    "X-Rdesk-Client-Cert-Sha256",
    "X-Relay-Node-Id",
    "X-Relay-Signature",
    "X-Relay-Timestamp",
    "X-Relay-Sequence",
}
_RENEWAL_AUTH_HEADERS = _HEARTBEAT_AUTH_HEADERS | {"X-Relay-Renewal-Id"}
_PICKUP_AUTH_HEADERS = {
    "X-Rdesk-Client-TLS",
    "X-Relay-Enrollment-Receipt",
}


def install_relay_openapi(app: FastAPI) -> None:
    """Align relay-only OpenAPI metadata with the stable runtime contract."""

    original_openapi = app.openapi
    if getattr(original_openapi, "__relay_openapi_installed__", False):
        return

    def relay_openapi():
        if app.openapi_schema is not None:
            return app.openapi_schema
        schema = original_openapi()
        for path, path_item in schema.get("paths", {}).items():
            relay_path = path == "/api/v1/relays" or path.startswith(
                "/api/v1/relays/"
            )
            if not relay_path or not isinstance(path_item, dict):
                continue
            for method, operation in path_item.items():
                is_operation = method in {
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                }
                if not is_operation or not isinstance(operation, dict):
                    continue
                responses = operation.get("responses")
                if isinstance(responses, dict):
                    responses.pop("422", None)
                required_headers = {
                    _HEARTBEAT_OPENAPI_PATH: _HEARTBEAT_AUTH_HEADERS,
                    _RENEWAL_OPENAPI_PATH: _RENEWAL_AUTH_HEADERS,
                    _PICKUP_OPENAPI_PATH: _PICKUP_AUTH_HEADERS,
                }.get(path)
                if required_headers is None or method != "post":
                    continue
                parameters = operation.get("parameters")
                if not isinstance(parameters, list):
                    continue
                for parameter in parameters:
                    if (
                        isinstance(parameter, dict)
                        and parameter.get("in") == "header"
                        and parameter.get("name") in required_headers
                    ):
                        parameter["required"] = True
        app.openapi_schema = schema
        return schema

    relay_openapi.__relay_openapi_installed__ = True  # type: ignore[attr-defined]
    app.openapi = relay_openapi  # type: ignore[method-assign]
    app.openapi_schema = None


def _registry(db: AsyncSession) -> RelayRegistry:
    try:
        cipher = _relay_turn_secret_cipher()
    except (ValueError, TypeError, binascii.Error):
        raise RelayRegistryError(
            "relay_access_unavailable", 503, "relay access unavailable"
        ) from None
    return RelayRegistry(
        db,
        enrollment_token_pepper=settings.relay_enrollment_token_pepper,
        turn_secret_cipher=cipher,
    )


def _now() -> datetime:
    return datetime.now(UTC)


def _raise_domain(error: RelayRegistryError | RelayAuthError) -> None:
    raise HTTPException(
        status_code=error.status_code,
        detail={"code": error.code, "message": str(error)},
    ) from None


class RelayAccessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    policy_revision: int = Field(gt=0, le=2**63 - 1)
    intended_peer_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )


class NodeTurnCredentialOut(BaseModel):
    node_id: str
    urls: list[str]
    username: str
    credential: str = Field(repr=False)
    expires_at_unix_seconds: int


class RelayAccessResponse(BaseModel):
    directory: SignedRelayDirectoryOut
    credentials: list[NodeTurnCredentialOut]


def get_relay_access_service(
    db: AsyncSession = Depends(get_db),
) -> RelayAccessService:
    try:
        signing_seed = _decode_secret_b64(
            settings.relay_directory_signing_private_key, expected_length=32
        )
        pepper = bytes.fromhex(
            _secret_value(settings.relay_enrollment_token_pepper)
        )
        if len(pepper) < 32:
            raise ValueError("relay repository pepper unavailable")
        cipher = _relay_turn_secret_cipher()
        repository = RelayRepository(
            db,
            enrollment_token_pepper=pepper,
            secret_cipher=cipher,
            max_reservations_per_session=2,
        )
        signer = Ed25519RelayDirectorySigner(
            key_id=settings.relay_directory_signing_key_id,
            private_key_seed=signing_seed,
        )
        issuer = NodeTurnCredentialService(
            cipher=cipher,
            ttl_seconds=settings.turn_credential_ttl_seconds,
        )
        return RelayAccessService(
            session=db,
            repository=repository,
            signer=signer,
            credential_issuer=issuer,
            directory_ttl_seconds=settings.relay_directory_ttl_seconds,
        )
    except (ValueError, TypeError, binascii.Error):
        raise HTTPException(
            status_code=503,
            detail={
                "code": "relay_signing_unavailable",
                "message": "relay access unavailable",
            },
        ) from None


def _secret_value(value: str | SecretStr) -> str:
    return value.get_secret_value() if isinstance(value, SecretStr) else value


def _decode_secret_b64(value: str | SecretStr, *, expected_length: int) -> bytes:
    decoded = base64.b64decode(_secret_value(value), validate=True)
    if len(decoded) != expected_length:
        raise ValueError("secret has invalid length")
    return decoded


def _relay_turn_secret_cipher() -> AesGcmRelaySecretCipher:
    encryption_key = _decode_secret_b64(
        settings.relay_turn_secret_encryption_key, expected_length=32
    )
    return AesGcmRelaySecretCipher(
        encryption_key, key_id=settings.relay_turn_secret_encryption_key_id
    )


async def _commit(db: AsyncSession) -> None:
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise


def _node_response(node: RelayNode) -> RelayNodeResponse:
    return RelayNodeResponse(
        node_id=node.node_id,
        region=node.region,
        failure_domain=node.failure_domain,
        physical_host_id=node.physical_host_id,
        state=node.state,
        endpoints=list(node.endpoints),
        max_allocations=node.max_allocations,
        active_allocations=node.active_allocations,
        max_egress_bps=node.max_egress_bps,
        current_egress_bps=node.current_egress_bps,
        lease_expires_at=node.lease_expires_at,
        revoked_at=node.revoked_at,
    )


@router.post(
    "/enrollment-tokens",
    response_model=EnrollmentTokenResponse,
    status_code=status.HTTP_201_CREATED,
)
async def issue_enrollment_token(
    payload: EnrollmentTokenRequest,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> EnrollmentTokenResponse:
    try:
        token, expires_at = await _registry(db).issue_enrollment_token(
            ttl_seconds=payload.ttl_seconds, actor_id=admin.id, now=_now()
        )
        await _commit(db)
    except RelayRegistryError as error:
        _raise_domain(error)
    return EnrollmentTokenResponse(token=token, expires_at=expires_at)


@router.post(
    "/enroll",
    response_model=RelayEnrollmentResponse,
    status_code=status.HTTP_202_ACCEPTED,
    description=(
        "Submit a CSR through the configured trusted TLS proxy. "
        "`X-Rdesk-Client-TLS` is a proxy-only verified-transport marker; the "
        "backend trusts it only when the direct peer is allowlisted and clients "
        "must not set it themselves."
    ),
    # A tuple intentionally replaces FastAPI's generated security list during
    # its deep merge (JSON still renders an array).  A list would be appended
    # and incorrectly document the alternatives as OR.
    openapi_extra={"security": ({"TrustedMTLSProxy": []},)},
)
async def enroll_relay_node(
    request: Request,
    payload: RelayEnrollmentRequest,
    _proxy_tls_header: Annotated[
        str | None,
        Header(
            alias="X-Rdesk-Client-TLS",
            description="Proxy-only TLS verification marker from the trusted direct peer.",
        ),
    ] = None,
    _trusted_proxy_marker: Annotated[
        str | None, Security(trusted_mtls_proxy_scheme)
    ] = None,
    db: AsyncSession = Depends(get_db),
) -> RelayEnrollmentResponse:
    try:
        require_trusted_proxy(request, settings.trusted_mtls_proxy)
        requested = await _registry(db).request_enrollment(
            token=payload.token.get_secret_value(),
            node_id=payload.node_id,
            region=payload.region,
            failure_domain=payload.failure_domain,
            endpoints=payload.endpoints,
            max_allocations=payload.max_allocations,
            max_egress_bps=payload.max_egress_bps,
            csr_pem=payload.csr_pem,
            turn_rest_secret=payload.turn_rest_secret,
            receipt_ttl_seconds=settings.relay_enrollment_receipt_ttl_seconds,
            now=_now(),
        )
        await _commit(db)
    except (RelayRegistryError, RelayAuthError) as error:
        _raise_domain(error)
    return RelayEnrollmentResponse(
        enrollment_id=requested.registration.enrollment_id,
        node_id=requested.registration.node_id,
        status="pending",
        receipt=requested.receipt,
    )


@router.post(
    "/enrollments/{enrollment_id}/pickup",
    response_model=RelayEnrollmentPickupResponse,
    description=(
        "Poll an enrollment through the trusted TLS proxy using the one-time "
        "enrollment receipt. The receipt is never stored or logged in raw form."
    ),
    openapi_extra={"security": ({"TrustedMTLSProxy": []},)},
)
async def pickup_relay_certificate(
    enrollment_id: str,
    request: Request,
    _proxy_tls_header: Annotated[
        str | None, Header(alias="X-Rdesk-Client-TLS")
    ] = None,
    _receipt_header: Annotated[
        str | None,
        Header(alias="X-Relay-Enrollment-Receipt", min_length=20, max_length=512),
    ] = None,
    db: AsyncSession = Depends(get_db),
) -> RelayEnrollmentPickupResponse:
    try:
        require_trusted_proxy(request, settings.trusted_mtls_proxy)
        receipts = request.headers.getlist("x-relay-enrollment-receipt")
        if (
            len(receipts) != 1
            or not receipts[0].isascii()
            or not 20 <= len(receipts[0]) <= 512
        ):
            raise RelayRegistryError(
                "relay_enrollment_invalid", 401, "relay enrollment invalid"
            )
        pickup = await _registry(db).pickup_enrollment(
            enrollment_id=enrollment_id,
            receipt=receipts[0],
            ca_certificate_pem=settings.relay_ca_certificate_pem,
            ca_private_key_pem=settings.relay_ca_private_key_pem,
            ca_private_key_password=settings.relay_ca_private_key_password,
            validity_seconds=settings.relay_certificate_validity_seconds,
            now=_now(),
        )
        await _commit(db)
    except (RelayRegistryError, RelayAuthError) as error:
        _raise_domain(error)
    return RelayEnrollmentPickupResponse(**pickup.__dict__)


@router.post("/{node_id}/approve", response_model=RelayApprovalResponse)
async def approve_relay_node(
    node_id: str,
    payload: RelayApprovalRequest,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> RelayApprovalResponse:
    try:
        approved = await _registry(db).approve(
            node_id=node_id,
            actor_id=admin.id,
            failure_domain=payload.failure_domain,
            physical_host_id=payload.physical_host_id,
            now=_now(),
        )
        await _commit(db)
    except (RelayRegistryError, RelayAuthError) as error:
        _raise_domain(error)
    return RelayApprovalResponse(node_id=node_id, status=approved.status)


@router.post(
    "/{node_id}/heartbeat",
    response_model=RelayHeartbeatResponse,
    description=(
        "Accept a heartbeat only when a trusted mTLS proxy fingerprint and the "
        "node's body-bound Ed25519 authentication both verify."
    ),
    openapi_extra={
        "security": ({"TrustedMTLSProxy": [], "RelayEd25519": []},)
    },
)
async def record_relay_heartbeat(
    node_id: str,
    request: Request,
    payload: RelayHeartbeatRequest,
    identity: RelayIdentity = Depends(get_verified_relay_node),
    db: AsyncSession = Depends(get_db),
) -> RelayHeartbeatResponse:
    try:
        node = await _registry(db).record_heartbeat(
            identity=identity,
            sequence=request.state.relay_sequence,
            active_allocations=payload.active_allocations,
            current_egress_bps=payload.current_egress_bps,
            measured_rtt_ms=payload.measured_rtt_ms,
            recent_failure_bps=payload.recent_failure_bps,
            endpoints=payload.endpoints,
            now=_now(),
        )
        await _commit(db)
    except RelayRegistryError as error:
        _raise_domain(error)
    return RelayHeartbeatResponse(
        node_id=node_id,
        state=node.state,
        sequence=node.heartbeat_sequence,
        lease_expires_at=node.lease_expires_at,
    )


@router.post(
    "/{node_id}/renew",
    response_model=RelayRenewalResponse,
    description=(
        "Rotate the node-bound certificate and Ed25519 key using current mTLS "
        "and request authentication plus a bounded idempotency identifier."
    ),
    openapi_extra={"security": ({"TrustedMTLSProxy": [], "RelayEd25519": []},)},
)
async def renew_relay_certificate(
    node_id: str,
    request: Request,
    payload: RelayRenewalRequest,
    identity: RelayIdentity = Depends(get_verified_relay_renewal_node),
    _renewal_header: Annotated[
        str | None, Header(alias="X-Relay-Renewal-Id", min_length=1, max_length=128)
    ] = None,
    db: AsyncSession = Depends(get_db),
) -> RelayRenewalResponse:
    try:
        renewal_ids = request.headers.getlist("x-relay-renewal-id")
        if (
            len(renewal_ids) != 1
            or renewal_ids[0] != payload.renewal_id
            or not renewal_ids[0].isascii()
        ):
            raise RelayRegistryError(
                "relay_signature_invalid", 401, "relay request signature invalid"
            )
        renewed = await _registry(db).renew(
            identity=identity,
            renewal_id=payload.renewal_id,
            csr_pem=payload.csr_pem,
            ca_certificate_pem=settings.relay_ca_certificate_pem,
            ca_private_key_pem=settings.relay_ca_private_key_pem,
            ca_private_key_password=settings.relay_ca_private_key_password,
            validity_seconds=settings.relay_certificate_validity_seconds,
            renew_before_seconds=settings.relay_certificate_renew_before_seconds,
            previous_auth_grace_seconds=settings.relay_previous_auth_grace_seconds,
            renewal_record_retention_seconds=(
                settings.relay_renewal_record_retention_seconds
            ),
            now=_now(),
        )
        await _commit(db)
    except (RelayRegistryError, RelayAuthError) as error:
        _raise_domain(error)
    return RelayRenewalResponse(
        renewal_id=payload.renewal_id,
        node_id=node_id,
        certificate_pem=renewed.certificate.certificate_pem,
        ca_certificate_pem=renewed.certificate.ca_certificate_pem,
        fingerprint=renewed.certificate.fingerprint,
        expires_at=renewed.certificate.expires_at,
    )


@router.get("", response_model=list[RelayNodeResponse])
async def list_relay_nodes(
    _: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> list[RelayNodeResponse]:
    nodes = await _registry(db).list_nodes()
    return [_node_response(node) for node in nodes]


async def _transition(
    *, node_id: str, action: str, admin: User, db: AsyncSession
) -> RelayNodeResponse:
    try:
        node = await _registry(db).transition(
            node_id=node_id, action=action, actor_id=admin.id, now=_now()
        )
        await _commit(db)
    except RelayRegistryError as error:
        _raise_domain(error)
    return _node_response(node)


@router.post("/{node_id}/drain", response_model=RelayNodeResponse)
async def drain_relay_node(
    node_id: str,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> RelayNodeResponse:
    return await _transition(node_id=node_id, action="drain", admin=admin, db=db)


@router.post("/{node_id}/resume", response_model=RelayNodeResponse)
async def resume_relay_node(
    node_id: str,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> RelayNodeResponse:
    return await _transition(node_id=node_id, action="resume", admin=admin, db=db)


@router.post("/{node_id}/revoke", response_model=RelayRevocationResponse)
async def revoke_relay_node(
    node_id: str,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> RelayRevocationResponse:
    try:
        revoked = await _registry(db).revoke(
            node_id=node_id, actor_id=admin.id, now=_now()
        )
        await _commit(db)
    except RelayRegistryError as error:
        _raise_domain(error)
    return RelayRevocationResponse(node_id=revoked.node_id, state="revoked")


@router.post(
    "/access",
    response_model=RelayAccessResponse,
    responses={
        403: {"model": RelayErrorResponse, "description": "Relay access denied."},
        503: {"model": RelayErrorResponse, "description": "Relay access unavailable."},
    },
)
async def issue_relay_access(
    payload: RelayAccessRequest,
    current_user: User = Depends(get_current_user),
    service: RelayAccessService = Depends(get_relay_access_service),
) -> RelayAccessResponse:
    try:
        result = await service.issue_access(
            current_user_id=current_user.id,
            session_id=payload.session_id,
            policy_revision=payload.policy_revision,
            intended_peer_id=payload.intended_peer_id,
        )
    except RelayAccessError as error:
        raise HTTPException(
            status_code=error.status_code,
            detail={"code": error.code, "message": str(error)},
        ) from None
    return RelayAccessResponse(
        directory=result.directory,
        credentials=[
            NodeTurnCredentialOut(
                node_id=item.node_id,
                urls=list(item.urls),
                username=item.username,
                credential=item.credential,
                expires_at_unix_seconds=item.expires_at_unix_seconds,
            )
            for item in result.credentials
        ],
    )
