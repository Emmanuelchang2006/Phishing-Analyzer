from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Optional

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# Module-level singletons — initialized in lifespan, None until then
_engine: Optional[AsyncEngine] = None
_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def get_engine() -> Optional[AsyncEngine]:
    return _engine


async def init_db() -> bool:
    """
    Initialize the async database engine and create all tables.

    Returns True if the connection succeeded, False if Postgres is unreachable
    (scan service will skip persistence in that case).

    Called once from app lifespan on startup.
    """
    global _engine, _session_factory

    settings = get_settings()

    try:
        _engine = create_async_engine(
            settings.database_url,
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            pool_pre_ping=True,       # Verify connections before use (handles stale connections)
            echo=settings.is_development,  # Log SQL in dev only
        )

        _session_factory = async_sessionmaker(
            bind=_engine,
            class_=AsyncSession,
            expire_on_commit=False,   # Don't invalidate objects after commit (safer for async)
        )

        # Import models so Base.metadata knows about them before create_all
        from app.db.models import scan  # noqa: F401
        from app.db.base import Base

        # create_all is safe to call even if tables already exist
        async with _engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        logger.info("database_connected", url=_mask_url(settings.database_url))
        return True

    except Exception as exc:
        logger.warning(
            "database_unavailable",
            error=str(exc),
            detail="Scans will run without persistence until Postgres is available",
        )
        _engine = None
        _session_factory = None
        return False


async def close_db() -> None:
    """Dispose of the engine connection pool on shutdown."""
    global _engine
    if _engine:
        await _engine.dispose()
        logger.info("database_disconnected")
        _engine = None


async def get_db_session() -> AsyncGenerator[AsyncSession | None, None]:
    """
    FastAPI dependency that yields an AsyncSession per request.

    Yields None if the database is not initialized, so callers must check
    before using the session.

    Usage:
        @router.post("/scan")
        async def scan(db: AsyncSession | None = Depends(get_db_session)):
            ...
    """
    if _session_factory is None:
        yield None
        return

    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def _mask_url(url: str) -> str:
    """Mask the password in a database URL for safe logging."""
    import re
    return re.sub(r":([^:@]+)@", ":***@", url)
