from fastapi import Response
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send


_SENSITIVE_PATH_PREFIXES = (
    "/api/v1/auth",
    "/api/v1/devices",
    "/api/v1/relays",
    "/api/v1/turn/credentials",
)


def _is_sensitive_path(path: object) -> bool:
    return isinstance(path, str) and any(
        path == prefix or path.startswith(prefix + "/")
        for prefix in _SENSITIVE_PATH_PREFIXES
    )


class SensitiveResponseCacheMiddleware:
    """Stamp the final ASGI response for credential-bearing API surfaces.

    A FastAPI ``Response`` dependency only changes the framework's temporary
    response object. Validator JSON responses and exception-handler responses
    replace that object, so the policy must be applied at ``http.response.start``.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http" or not _is_sensitive_path(scope.get("path")):
            await self.app(scope, receive, send)
            return

        async def send_no_store(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Cache-Control"] = "no-store, private"
                headers["Pragma"] = "no-cache"
            await send(message)

        await self.app(scope, receive, send_no_store)


async def no_store_sensitive_response(response: Response) -> None:
    """Prevent browsers and intermediaries from retaining credential responses."""

    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
