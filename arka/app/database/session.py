from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from arka.app.core.config import get_settings


def get_async_engine():
    settings = get_settings()
    return create_async_engine(settings.database_url, echo=False, pool_pre_ping=True)


def get_session_factory(engine=None):
    if engine is None:
        engine = get_async_engine()
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency for database sessions."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
