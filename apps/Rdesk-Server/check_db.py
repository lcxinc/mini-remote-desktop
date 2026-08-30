"""Read-only database connectivity diagnostic.

Schema migrations and administrator provisioning are explicit deployment actions.
This utility deliberately performs neither operation.
"""

import asyncio

from sqlalchemy import func, select

from app.db.session import AsyncSessionLocal, engine
from app.models.user import User


async def check_database() -> None:
    """Verify connectivity and report a non-sensitive aggregate."""

    async with engine.connect() as connection:
        await connection.execute(select(1))

    async with AsyncSessionLocal() as session:
        user_count = await session.scalar(select(func.count(User.id)))

    print(f"Database reachable; user_count={user_count or 0}")


if __name__ == "__main__":
    asyncio.run(check_database())
