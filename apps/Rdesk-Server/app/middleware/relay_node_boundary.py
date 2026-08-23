from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Awaitable, Callable
from typing import Any


_MAX_BODY_BYTES = 65_536
_NODE_PATH = re.compile(
    r"^/api/v1/relays/(?:enroll|enrollments/[^/]+/pickup|[^/]+/(?:heartbeat|renew|secret-rotation/(?:upload|commit)))$"
)
_CONTENT_LENGTH = re.compile(rb"^(0|[1-9][0-9]{0,19})$")
_FORWARDED_HEADERS = {
    b"forwarded",
    b"x-forwarded-for",
    b"x-real-ip",
    b"x-client-ip",
}
_SECURITY_HEADERS = {
    b"x-rdesk-client-tls": (403, "relay_proxy_required"),
    b"x-rdesk-client-cert-sha256": (401, "relay_certificate_invalid"),
    b"x-relay-node-id": (401, "relay_signature_invalid"),
    b"x-relay-signature": (401, "relay_signature_invalid"),
    b"x-relay-timestamp": (401, "relay_signature_invalid"),
    b"x-relay-sequence": (401, "relay_signature_invalid"),
    b"x-relay-enrollment-receipt": (401, "relay_enrollment_invalid"),
    b"x-relay-renewal-id": (401, "relay_signature_invalid"),
}
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class RelayNodeBoundaryMiddleware:
    """Enforce the relay-node transport/body boundary before FastAPI parsing.

    Uvicorn must run with proxy header rewriting disabled.  A terminating proxy
    must strip all forwarded/security headers from clients and inject one clean
    copy.  Rejecting forwarding headers also fails closed if another middleware
    has already rewritten the ASGI peer address.
    """

    def __init__(self, app: Any, *, trusted_proxy: str) -> None:
        self.app = app
        self._networks = _networks(trusted_proxy)

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope.get("type") != "http" or not _NODE_PATH.fullmatch(
            str(scope.get("path", ""))
        ):
            await self.app(scope, receive, send)
            return

        headers = list(scope.get("headers") or ())
        names = [name.lower() for name, _ in headers]
        # Forwarding metadata is never part of this private hop.  Test it before
        # the possibly mutable scope peer so ProxyHeadersMiddleware cannot turn
        # an attacker-selected XFF value into a trusted identity.
        if any(
            name in _FORWARDED_HEADERS or name.startswith(b"x-forwarded-")
            for name in names
        ):
            await _error(send, 403, "relay_proxy_required", "trusted mTLS proxy required")
            return
        if not _peer_allowed(scope.get("client"), self._networks):
            await _error(send, 403, "relay_proxy_required", "trusted mTLS proxy required")
            return

        by_name: dict[bytes, list[bytes]] = {}
        for name, value in headers:
            by_name.setdefault(name.lower(), []).append(value)
        tls_values = by_name.get(b"x-rdesk-client-tls", [])
        if len(tls_values) != 1 or tls_values[0].lower() != b"verified":
            await _error(send, 403, "relay_proxy_required", "trusted mTLS proxy required")
            return
        for name, (status_code, code) in _SECURITY_HEADERS.items():
            values = by_name.get(name, [])
            if len(values) > 1 or any(b"," in value for value in values):
                await _error(send, status_code, code, "relay authentication invalid")
                return

        content_lengths = by_name.get(b"content-length", [])
        if len(content_lengths) > 1 or any(b"," in value for value in content_lengths):
            await _error(send, 400, "relay_request_invalid", "relay request invalid")
            return
        transfer_encodings = by_name.get(b"transfer-encoding", [])
        if (
            len(transfer_encodings) > 1
            or any(b"," in value for value in transfer_encodings)
            or (transfer_encodings and transfer_encodings[0].lower() != b"chunked")
            or (content_lengths and transfer_encodings)
        ):
            await _error(send, 400, "relay_request_invalid", "relay request invalid")
            return
        declared: int | None = None
        if content_lengths:
            if _CONTENT_LENGTH.fullmatch(content_lengths[0]) is None:
                await _error(send, 400, "relay_request_invalid", "relay request invalid")
                return
            declared = int(content_lengths[0])
            if declared > _MAX_BODY_BYTES:
                await _error(send, 413, "relay_request_too_large", "relay request too large")
                return

        body = bytearray()
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return
            if message.get("type") != "http.request":
                await _error(send, 400, "relay_request_invalid", "relay request invalid")
                return
            body.extend(message.get("body", b""))
            if len(body) > _MAX_BODY_BYTES:
                await _error(send, 413, "relay_request_too_large", "relay request too large")
                return
            if declared is not None and len(body) > declared:
                await _error(send, 400, "relay_request_invalid", "relay request invalid")
                return
            if not message.get("more_body", False):
                break
        exact_body = bytes(body)
        if declared is not None and len(exact_body) != declared:
            await _error(send, 400, "relay_request_invalid", "relay request invalid")
            return
        scope.setdefault("state", {})["relay_raw_body"] = exact_body
        delivered = False

        async def replay() -> dict[str, Any]:
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": exact_body, "more_body": False}

        await self.app(scope, replay, send)


def _networks(configured: str) -> tuple[Network, ...]:
    result: list[Network] = []
    for raw in configured.split(","):
        try:
            result.append(ipaddress.ip_network(raw.strip(), strict=False))
        except ValueError:
            continue
    return tuple(result)


def _peer_allowed(
    client: object, networks: tuple[Network, ...]
) -> bool:
    if not isinstance(client, (tuple, list)) or not client:
        return False
    try:
        address = ipaddress.ip_address(str(client[0]))
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return bool(networks) and any(
        address.version == network.version and address in network for network in networks
    )


async def _error(
    send: Callable[[dict[str, Any]], Awaitable[None]],
    status_code: int,
    code: str,
    message: str,
) -> None:
    body = json.dumps(
        {"detail": {"code": code, "message": message}}, separators=(",", ":")
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
