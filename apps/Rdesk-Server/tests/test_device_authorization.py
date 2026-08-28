import importlib
import sys
import types
import unittest

from pydantic import ValidationError


class HTTPException(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class APIRouter:
    def __init__(self, **_kwargs):
        pass

    def _route(self, *_args, **_kwargs):
        return lambda function: function

    get = post = patch = _route


def Depends(dependency=None):
    return dependency


def Query(default=None):
    return default


class Column:
    def __eq__(self, other):
        return ("eq", other)

    def ilike(self, value):
        return ("ilike", value)

    def is_(self, value):
        return ("is", value)


class Select:
    @classmethod
    def __class_getitem__(cls, _item):
        return cls


class Statement:
    def __init__(self):
        self.filters = []

    def where(self, *expressions):
        self.filters.extend(expressions)
        return self

    def options(self, _option):
        return self

    def with_for_update(self):
        return self

    def execution_options(self, **_options):
        return self


class User:
    id = Column()

    def __init__(
        self,
        user_id: str,
        role: str = "user",
        username: str = "user",
        tenant_id: str | None = None,
    ):
        self.id = user_id
        self.role = role
        self.username = username
        self.tenant_id = tenant_id or f"tenant-{user_id}"


class Device:
    id = Column()
    name = Column()
    device_id = Column()
    motherboard_serial = Column()
    bound_user_id = Column()
    status = Column()
    tenant_id = Column()
    is_bound = Column()

    def __init__(
        self,
        device_id: str,
        bound_user_id: str | None,
        *,
        database_id: str | None = None,
    ):
        self.id = database_id or f"db-{device_id}"
        self.name = f"device-{device_id}"
        self.device_id = device_id
        self.os = "Linux"
        self.icon = "Monitor"
        self.status = None
        self.location = ""
        self.ip = ""
        self.group = "default"
        self.favorite = False
        self.bound_user_id = bound_user_id
        self.is_bound = bound_user_id is not None
        self.tenant_id = (
            f"tenant-{bound_user_id}" if bound_user_id is not None else "tenant-unbound"
        )
        self.bound_at = None


STUBBED_MODULE_NAMES = (
    "fastapi",
    "sqlalchemy",
    "sqlalchemy.ext",
    "sqlalchemy.ext.asyncio",
    "sqlalchemy.orm",
    "app.core.response_security",
    "app.core.security",
    "app.db.session",
    "app.models.device",
    "app.models.user",
    "app.services.device_enrollment",
)
MISSING_MODULE = object()


def _install_dependency_stubs() -> None:
    fastapi = types.ModuleType("fastapi")
    fastapi.APIRouter = APIRouter
    fastapi.Depends = Depends
    fastapi.HTTPException = HTTPException
    fastapi.Query = Query
    fastapi.status = types.SimpleNamespace(
        HTTP_401_UNAUTHORIZED=401,
        HTTP_403_FORBIDDEN=403,
        HTTP_409_CONFLICT=409,
        HTTP_503_SERVICE_UNAVAILABLE=503,
    )

    sqlalchemy = types.ModuleType("sqlalchemy")
    sqlalchemy.Select = Select
    sqlalchemy.select = lambda _model: Statement()
    sqlalchemy_ext = types.ModuleType("sqlalchemy.ext")
    sqlalchemy_asyncio = types.ModuleType("sqlalchemy.ext.asyncio")
    sqlalchemy_asyncio.AsyncSession = object
    sqlalchemy_orm = types.ModuleType("sqlalchemy.orm")
    sqlalchemy_orm.selectinload = lambda value: value

    security = types.ModuleType("app.core.security")
    security.create_access_token = lambda *_args: "token"
    security.create_device_access_token = lambda *_args: "device-token"
    security.get_device_enrollment_token_optional = object()
    security.get_current_device = object()
    security.get_current_device_optional = object()
    security.get_current_user = object()
    security.get_current_user_optional = object()
    security.require_admin = object()
    response_security = types.ModuleType("app.core.response_security")
    response_security.no_store_sensitive_response = object()
    session = types.ModuleType("app.db.session")
    session.get_db = object()
    device_model = types.ModuleType("app.models.device")
    device_model.Device = Device
    device_model.generate_device_id_from_serial = lambda _serial: "123456789012"
    user_model = types.ModuleType("app.models.user")
    user_model.User = User
    enrollment = types.ModuleType("app.services.device_enrollment")

    class DeviceEnrollmentError(Exception):
        pass

    class DeviceEnrollmentService:
        def __init__(self, **_kwargs):
            pass

    enrollment.DeviceEnrollmentError = DeviceEnrollmentError
    enrollment.DeviceEnrollmentService = DeviceEnrollmentService
    enrollment.device_serial_digest = lambda serial, **_kwargs: serial

    sys.modules.update(
        {
            "fastapi": fastapi,
            "sqlalchemy": sqlalchemy,
            "sqlalchemy.ext": sqlalchemy_ext,
            "sqlalchemy.ext.asyncio": sqlalchemy_asyncio,
            "sqlalchemy.orm": sqlalchemy_orm,
            "app.core.response_security": response_security,
            "app.core.security": security,
            "app.db.session": session,
            "app.models.device": device_model,
            "app.models.user": user_model,
            "app.services.device_enrollment": enrollment,
        }
    )


schemas = importlib.import_module("app.schemas.device")


def _load_devices_with_stubs():
    target_name = "app.api.v1.devices"
    module_names = (*STUBBED_MODULE_NAMES, target_name)
    previous_modules = {
        name: sys.modules.get(name, MISSING_MODULE) for name in module_names
    }
    api_package = importlib.import_module("app.api.v1")
    previous_package_attribute = getattr(api_package, "devices", MISSING_MODULE)

    try:
        _install_dependency_stubs()
        sys.modules.pop(target_name, None)
        return importlib.import_module(target_name)
    finally:
        for name, previous_module in previous_modules.items():
            if previous_module is MISSING_MODULE:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous_module

        if previous_package_attribute is MISSING_MODULE:
            try:
                delattr(api_package, "devices")
            except AttributeError:
                pass
        else:
            api_package.devices = previous_package_attribute


devices = _load_devices_with_stubs()


class ScalarRows:
    def __init__(self, rows):
        self.rows = rows

    def all(self):
        return list(self.rows)


class FakeSession:
    def __init__(self, *, scalar_results=(), rows=()):
        self.scalar_results = iter(scalar_results)
        self.rows = rows
        self.commit_count = 0

    async def scalar(self, _statement):
        return next(self.scalar_results)

    async def scalars(self, _statement):
        return ScalarRows(self.rows)

    async def commit(self):
        self.commit_count += 1

    async def flush(self):
        return None

    async def rollback(self):
        return None


class DeviceAuthorizationTests(unittest.IsolatedAsyncioTestCase):
    async def test_spoofed_payload_user_id_is_rejected(self):
        unbound = Device("device-1", None)
        with self.assertRaises(ValidationError):
            schemas.DeviceBindRequest(device_id=unbound.device_id, user_id="victim")
        self.assertIsNone(unbound.bound_user_id)

    async def test_auto_bind_cannot_migrate_another_users_device(self):
        attacker = User("attacker")
        victim_device = Device("device-2", "victim")
        session = FakeSession(scalar_results=[victim_device])
        payload = schemas.DeviceAutoBindRequest(device_id=victim_device.device_id)

        with self.assertRaises(HTTPException) as raised:
            await devices.auto_bind_device(payload, attacker, victim_device, session)

        self.assertEqual(raised.exception.status_code, 409)
        self.assertEqual(victim_device.bound_user_id, "victim")
        self.assertEqual(session.commit_count, 0)

    async def test_list_filters_devices_to_authenticated_owner(self):
        owner = User("owner")
        own_device = Device("device-3", "owner")
        victim_device = Device("device-4", "victim")
        session = FakeSession(rows=[own_device, victim_device])

        result = await devices.list_devices(None, None, owner, session)

        self.assertEqual([item.device_id for item in result], [own_device.device_id])

    async def test_read_hides_another_users_device(self):
        attacker = User("attacker")
        victim_device = Device("device-5", "victim")
        session = FakeSession(scalar_results=[victim_device])

        with self.assertRaises(HTTPException) as raised:
            await devices.get_device(victim_device.id, attacker, session)

        self.assertEqual(raised.exception.status_code, 404)

    async def test_owner_can_bind_without_payload_user_id(self):
        owner = User("owner")
        unbound = Device("device-6", None)
        session = FakeSession(scalar_results=[unbound])
        payload = schemas.DeviceBindRequest(device_id=unbound.device_id)

        result = await devices.bind_device(payload, owner, unbound, session)

        self.assertEqual(result["user_id"], owner.id)
        self.assertEqual(unbound.bound_user_id, owner.id)
        self.assertEqual(session.commit_count, 1)

    async def test_admin_can_audit_all_devices(self):
        admin = User("admin", role="admin")
        rows = [Device("device-7", "a"), Device("device-8", "b")]
        session = FakeSession(rows=rows)

        result = await devices.list_devices(None, None, admin, session)

        self.assertEqual([item.device_id for item in result], ["device-7", "device-8"])


if __name__ == "__main__":
    unittest.main()
