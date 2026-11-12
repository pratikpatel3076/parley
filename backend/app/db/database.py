from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

# Never echo SQL: bound parameters can contain auth material and ciphertext.
# SQLite needs a wait budget so a concurrent single-use rotation loses cleanly
# on the conditional UPDATE instead of failing with "database is locked".
_connect_args = (
    {"timeout": 5}
    if settings.DATABASE_URL.startswith("sqlite")
    else {}
)
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    connect_args=_connect_args,
)
SessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Declarative base for the Parley ORM models."""


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Create tables for the empty development database.

    This is a scaffold convenience. Add reviewed migrations before the first
    schema change; do not grow this into a migration strategy.
    """
    # Importing the package registers the model classes on Base.metadata.
    import app.models  # noqa: F401

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
