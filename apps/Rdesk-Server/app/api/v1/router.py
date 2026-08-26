from fastapi import APIRouter

from app.api.v1 import (
    auth,
    device_sessions,
    devices,
    network_groups,
    realtime,
    relays,
    sessions,
    turn,
    users,
)

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth.router)
api_router.include_router(device_sessions.router)
api_router.include_router(devices.router)
api_router.include_router(network_groups.router)
api_router.include_router(realtime.router)
api_router.include_router(relays.router)
api_router.include_router(sessions.router)
api_router.include_router(turn.router)
api_router.include_router(users.router)
