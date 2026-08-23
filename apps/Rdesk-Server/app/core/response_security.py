from fastapi import Response


async def no_store_sensitive_response(response: Response) -> None:
    """Prevent browsers and intermediaries from retaining credential responses."""

    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
