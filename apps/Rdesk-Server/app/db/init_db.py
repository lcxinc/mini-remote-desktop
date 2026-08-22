import re

from pydantic import SecretStr
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, settings
from app.core.security import hash_password
from app.models.device import Device, DeviceStatus
from app.models.user import User


async def seed_initial_data(
    session: AsyncSession, *, configuration: Settings = settings
) -> None:
    """Run an explicit, opt-in development bootstrap without default credentials."""

    if not configuration.bootstrap_admin_enabled:
        return

    username = configuration.bootstrap_admin_username.strip()
    email = configuration.bootstrap_admin_email.strip().lower()
    configured_password = configuration.bootstrap_admin_password
    password = (
        configured_password.get_secret_value()
        if isinstance(configured_password, SecretStr)
        else configured_password
    )
    if not _valid_bootstrap_admin(username, email, password):
        return

    admin_exists = await session.scalar(
        select(User).where(or_(User.username == username, User.email == email))
    )
    if admin_exists:
        return

    admin = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role="admin",
    )
    session.add(admin)

    devices = [
        Device(
            name="办公室电脑",
            device_id="821456789",
            os="Windows 11 Pro",
            icon="Monitor",
            location="北京",
            ip="192.168.1.101",
            group="工作",
            favorite=True,
            status=DeviceStatus(status="online", ping=18, cpu=34, ram=68, disk=45, last_seen="在线"),
        ),
        Device(
            name="家用 MacBook",
            device_id="334902115",
            os="macOS Sonoma 14.2",
            icon="Laptop",
            location="上海",
            ip="192.168.0.5",
            group="个人",
            favorite=True,
            status=DeviceStatus(status="online", ping=35, cpu=12, ram=42, disk=61, last_seen="在线"),
        ),
        Device(
            name="Linux 服务器",
            device_id="567234891",
            os="Ubuntu 22.04 LTS",
            icon="Server",
            location="深圳",
            ip="10.0.0.15",
            group="服务器",
            favorite=False,
            status=DeviceStatus(status="offline", ping=None, cpu=None, ram=None, disk=None, last_seen="2小时前"),
        ),
    ]
    session.add_all(devices)
    await session.commit()


def _valid_bootstrap_admin(username: str, email: str, password: object) -> bool:
    if (
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}", username) is None
        or len(email) > 255
        or "@" not in email
        or "." not in email.rsplit("@", 1)[-1]
        or not isinstance(password, str)
        or len(password) < 20
        or len(set(password)) < 12
    ):
        return False
    character_classes = (
        any(character.islower() for character in password),
        any(character.isupper() for character in password),
        any(character.isdigit() for character in password),
        any(not character.isalnum() for character in password),
    )
    return all(character_classes) and username.lower() not in password.lower()
