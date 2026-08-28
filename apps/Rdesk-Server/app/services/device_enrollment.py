from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import secrets
import weakref
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Callable

from pydantic import SecretStr
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.models.device import Device, generate_device_id_from_digest
from app.models.device_enrollment import DeviceEnrollment
from app.models.relay_audit_event import RelayAuditEvent


_TOKEN = re.compile(r"^[A-Za-z0-9_-]{43}$", flags=re.ASCII)
_TOKEN_CONTEXT = b"MRD_DEVICE_ENROLLMENT_TOKEN_V1\x00"
_REQUEST_CONTEXT = b"MRD_DEVICE_REGISTRATION_REQUEST_V1\x00"
_SERIAL_CONTEXT = b"MRD_DEVICE_SERIAL_V1\x00"
_SERIAL_LOCK_CONTEXT = b"MRD_DEVICE_SERIAL_LOCK_V1\x00"
_LOCAL_SERIAL_LOCKS: weakref.WeakValueDictionary[
    tuple[int, str], asyncio.Lock
] = weakref.WeakValueDictionary()


class DeviceEnrollmentError(Exception):
    def __init__(self, code: str, status_code: int, message: str) -> None:
        self.code = code
        self.status_code = status_code
        super().__init__(message)


@dataclass(frozen=True)
class IssuedDeviceEnrollment:
    enrollment_id: str
    token: SecretStr
    expires_at: datetime


@dataclass(frozen=True)
class RegisteredDevice:
    device: Device
    recovered: bool


class DeviceEnrollmentService:
    def __init__(
        self,
        session: object,
        *,
        token_pepper: bytes,
        serial_pepper: bytes,
        ttl_seconds: int,
        now: Callable[[], datetime] | None = None,
        token_source: Callable[[int], str] = secrets.token_urlsafe,
    ) -> None:
        if len(token_pepper) < 32:
            raise ValueError("device enrollment token pepper is unavailable")
        if len(serial_pepper) < 32:
            raise ValueError("device serial pepper is unavailable")
        if (
            not isinstance(ttl_seconds, int)
            or isinstance(ttl_seconds, bool)
            or not 30 <= ttl_seconds <= 900
        ):
            raise ValueError("device enrollment TTL is unavailable")
        self._session = session
        self._token_pepper = bytes(token_pepper)
        self._serial_pepper = bytes(serial_pepper)
        self._ttl_seconds = ttl_seconds
        self._now = now or (lambda: datetime.now(UTC))
        self._token_source = token_source

    async def issue(self, *, admin_user_id: str) -> IssuedDeviceEnrollment:
        raw_token = self._token_source(32)
        if not isinstance(raw_token, str) or _TOKEN.fullmatch(raw_token) is None:
            raise DeviceEnrollmentError(
                "device_enrollment_unavailable",
                503,
                "device enrollment unavailable",
            )
        now = _utc(self._now())
        enrollment = DeviceEnrollment(
            token_digest=self._token_digest(raw_token),
            expires_at=now + timedelta(seconds=self._ttl_seconds),
            issued_by_user_id=admin_user_id,
            issued_at=now,
        )
        self._session.add(enrollment)
        await self._session.flush()
        self._session.add(
            RelayAuditEvent(
                action="device_enrollment_issued",
                node_id=None,
                actor_id=admin_user_id,
                details={
                    "enrollment_id": enrollment.id,
                    "expires_at_unix_seconds": int(enrollment.expires_at.timestamp()),
                },
                created_at=now,
            )
        )
        await self._session.flush()
        return IssuedDeviceEnrollment(
            enrollment_id=enrollment.id,
            token=SecretStr(raw_token),
            expires_at=enrollment.expires_at,
        )

    async def register(
        self, *, token: SecretStr, registration: dict[str, object]
    ) -> RegisteredDevice:
        raw_token = token.get_secret_value()
        if _TOKEN.fullmatch(raw_token) is None:
            self._invalid()
        serial = registration.get("motherboard_serial")
        if not isinstance(serial, str) or not 1 <= len(serial) <= 128:
            self._invalid()
        serial_digest = device_serial_digest(serial, self._serial_pepper)
        async with _serial_lock(self._session, serial_digest):
            return await self._register_locked(
                raw_token=raw_token,
                registration=registration,
                serial_digest=serial_digest,
            )

    async def _register_locked(
        self,
        *,
        raw_token: str,
        registration: dict[str, object],
        serial_digest: str,
    ) -> RegisteredDevice:
        now = _utc(self._now())
        request_digest = self._request_digest(registration)
        enrollment = await self._session.scalar(
            select(DeviceEnrollment)
            .where(DeviceEnrollment.token_digest == self._token_digest(raw_token))
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if enrollment is None or _utc(enrollment.expires_at) <= now:
            self._invalid()
        if enrollment.consumed_at is not None:
            if (
                not hmac.compare_digest(
                    enrollment.request_digest or "", request_digest
                )
                or enrollment.registered_device_id is None
            ):
                self._conflict()
            device = await self._session.scalar(
                select(Device)
                .where(Device.id == enrollment.registered_device_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if device is None:
                self._invalid()
            return RegisteredDevice(device=device, recovered=True)

        existing = await self._session.scalar(
            select(Device)
            .where(Device.motherboard_serial_digest == serial_digest)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if existing is not None:
            self._conflict()
        device_id = generate_device_id_from_digest(serial_digest)
        if await self._session.scalar(
            select(Device.id).where(Device.device_id == device_id)
        ):
            device_id = f"{device_id}-{secrets.token_hex(2)}"
        os_version = registration.get("os_version")
        os_type = (
            os_version.split()[0]
            if isinstance(os_version, str) and os_version
            else "Unknown"
        )
        hostname = registration.get("hostname")
        device_name = registration.get("device_name") or hostname
        device = Device(
            name=device_name,
            device_id=device_id,
            os=os_type,
            os_version=os_version,
            hostname=hostname,
            motherboard_serial=None,
            motherboard_serial_digest=serial_digest,
            cpu_info=registration.get("cpu_info"),
            total_memory_mb=registration.get("total_memory_mb"),
            gpu_info=registration.get("gpu_info"),
            is_bound=False,
        )
        begin_nested = getattr(self._session, "begin_nested", None)
        savepoint = await begin_nested() if callable(begin_nested) else None
        try:
            self._session.add(device)
            await self._session.flush()
        except IntegrityError:
            if savepoint is not None:
                await savepoint.rollback()
            self._conflict()
        else:
            if savepoint is not None:
                await savepoint.commit()
        enrollment.consumed_at = now
        enrollment.request_digest = request_digest
        enrollment.registered_device_id = device.id
        self._session.add(
            RelayAuditEvent(
                action="device_enrollment_consumed",
                node_id=None,
                actor_id=None,
                details={
                    "enrollment_id": enrollment.id,
                    "device_id": device.device_id,
                },
                created_at=now,
            )
        )
        await self._session.flush()
        return RegisteredDevice(device=device, recovered=False)

    def _token_digest(self, token: str) -> str:
        return hmac.new(
            self._token_pepper,
            _TOKEN_CONTEXT + token.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def _request_digest(self, registration: dict[str, object]) -> str:
        canonical = json.dumps(
            registration,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(
            self._token_pepper,
            _REQUEST_CONTEXT + canonical,
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _invalid() -> None:
        raise DeviceEnrollmentError(
            "device_enrollment_invalid", 401, "device enrollment invalid"
        )

    @staticmethod
    def _conflict() -> None:
        raise DeviceEnrollmentError(
            "device_enrollment_conflict", 409, "device enrollment conflicts"
        )


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def device_serial_digest(serial: str, pepper: bytes) -> str:
    if (
        not isinstance(serial, str)
        or not 1 <= len(serial) <= 128
        or not isinstance(pepper, bytes)
        or len(pepper) < 32
    ):
        raise ValueError("device serial identity is unavailable")
    return hmac.new(
        pepper,
        _SERIAL_CONTEXT + serial.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


@asynccontextmanager
async def _serial_lock(session: object, serial_digest: str):
    if _session_dialect_name(session) == "postgresql":
        digest = hashlib.sha256(
            _SERIAL_LOCK_CONTEXT + serial_digest.encode("ascii")
        ).digest()
        lock_key = int.from_bytes(digest[:8], "big", signed=True)
        await session.execute(
            text("SELECT pg_advisory_xact_lock(:lock_key)"),
            {"lock_key": lock_key},
        )
        yield
        return
    target = getattr(session, "session", session)
    get_bind = getattr(target, "get_bind", None)
    bind = get_bind() if callable(get_bind) else target
    key = (id(bind), serial_digest)
    lock = _LOCAL_SERIAL_LOCKS.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _LOCAL_SERIAL_LOCKS[key] = lock
    async with lock:
        yield


def _session_dialect_name(session: object) -> str | None:
    target = getattr(session, "session", session)
    get_bind = getattr(target, "get_bind", None)
    if not callable(get_bind):
        return None
    return str(get_bind().dialect.name)
