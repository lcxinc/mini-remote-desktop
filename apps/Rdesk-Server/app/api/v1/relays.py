from __future__ import annotations

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

from app.core.config import settings
from app.core.security import (
    get_verified_relay_node,
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
    RelayEnrollmentRequest,
    RelayEnrollmentResponse,
    RelayErrorResponse,
    RelayHeartbeatRequest,
    RelayHeartbeatResponse,
    RelayNodeResponse,
)
from app.services.relay_node_auth import RelayAuthError, require_trusted_proxy
from app.services.relay_registry import (
    RelayIdentity,
    RelayRegistry,
    RelayRegistryError,
)


class RelayAPIRoute(APIRoute):
    """Return stable relay-domain codes instead of raw validator diagnostics."""

    def get_route_handler(self) -> Callable[..., Coroutine[object, object, object]]:
        original = super().get_route_handler()

        async def stable_validation_handler(request: Request):
            try:
                return await original(request)
            except RequestValidationError:
                code = (
                    "relay_metrics_invalid"
                    if request.url.path.endswith("/heartbeat")
                    else "relay_enrollment_invalid"
                )
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
    for code in (400, 401, 403, 404, 409, 503)
}


router = APIRouter(
    prefix="/relays",
    tags=["relays"],
    route_class=RelayAPIRoute,
    responses=_RELAY_ERROR_RESPONSES,
)

_HEARTBEAT_OPENAPI_PATH = "/api/v1/relays/{node_id}/heartbeat"
_HEARTBEAT_AUTH_HEADERS = {
    "X-Rdesk-Client-Cert-Sha256",
    "X-Relay-Node-Id",
    "X-Relay-Signature",
    "X-Relay-Timestamp",
    "X-Relay-Sequence",
}


def install_relay_openapi(app: FastAPI) -> None:
    """Align relay-only OpenAPI metadata with the stable runtime contract."""

    original_openapi = app.openapi
    if getattr(original_openapi, "__relay_openapi_installed__", False):
        return

    def relay_openapi():
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
                if path != _HEARTBEAT_OPENAPI_PATH or method != "post":
                    continue
                parameters = operation.get("parameters")
                if not isinstance(parameters, list):
                    continue
                for parameter in parameters:
                    if (
                        isinstance(parameter, dict)
                        and parameter.get("in") == "header"
                        and parameter.get("name") in _HEARTBEAT_AUTH_HEADERS
                    ):
                        parameter["required"] = True
        return schema

    relay_openapi.__relay_openapi_installed__ = True  # type: ignore[attr-defined]
    app.openapi = relay_openapi  # type: ignore[method-assign]


def _registry(db: AsyncSession) -> RelayRegistry:
    return RelayRegistry(
        db, enrollment_token_pepper=settings.relay_enrollment_token_pepper
    )


def _now() -> datetime:
    return datetime.now(UTC)


def _raise_domain(error: RelayRegistryError | RelayAuthError) -> None:
    raise HTTPException(
        status_code=error.status_code,
        detail={"code": error.code, "message": str(error)},
    ) from None


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
        registration = await _registry(db).request_enrollment(
            token=payload.token.get_secret_value(),
            node_id=payload.node_id,
            region=payload.region,
            failure_domain=payload.failure_domain,
            endpoints=payload.endpoints,
            max_allocations=payload.max_allocations,
            max_egress_bps=payload.max_egress_bps,
            csr_pem=payload.csr_pem,
            now=_now(),
        )
        await _commit(db)
    except (RelayRegistryError, RelayAuthError) as error:
        _raise_domain(error)
    return RelayEnrollmentResponse(node_id=registration.node_id, status="pending")


@router.post("/{node_id}/approve", response_model=RelayApprovalResponse)
async def approve_relay_node(
    node_id: str,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> RelayApprovalResponse:
    try:
        approved = await _registry(db).approve(
            node_id=node_id,
            actor_id=admin.id,
            ca_certificate_pem=settings.relay_ca_certificate_pem,
            ca_private_key_pem=settings.relay_ca_private_key_pem,
            validity_seconds=settings.relay_certificate_validity_seconds,
            now=_now(),
        )
        await _commit(db)
    except (RelayRegistryError, RelayAuthError) as error:
        _raise_domain(error)
    return RelayApprovalResponse(
        node_id=node_id,
        certificate_pem=approved.certificate.certificate_pem,
        ca_certificate_pem=approved.certificate.ca_certificate_pem,
        fingerprint=approved.certificate.fingerprint,
        expires_at=approved.certificate.expires_at,
    )


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


@router.post("/{node_id}/revoke", response_model=RelayNodeResponse)
async def revoke_relay_node(
    node_id: str,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> RelayNodeResponse:
    return await _transition(node_id=node_id, action="revoke", admin=admin, db=db)
