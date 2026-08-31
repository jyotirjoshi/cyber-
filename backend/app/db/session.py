"""Async engine, session factory and the request-scoped session dependency.

The engine is created lazily and cached per process.  ``expire_on_commit=False`` is
set deliberately: with it on, every attribute access after a commit triggers a lazy
refresh, which under asyncio raises ``MissingGreenlet`` -- the exact failure mode the
``lazy="raise_on_sql"`` convention exists to make visible.  Objects returned from a
service therefore stay usable after the transaction closes.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.core.config import Settings, get_settings

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def create_engine(settings: Settings) -> AsyncEngine:
    """Build the async engine.

    ``NullPool`` is used for tests so each test gets a clean connection and no
    pooled connection outlives an event loop -- reusing a connection across loops is
    a classic source of "attached to a different loop" errors.
    """
    kwargs: dict[str, Any] = {
        "echo": settings.db.echo,
        "pool_pre_ping": True,
        "future": True,
    }
    if settings.db.use_null_pool:
        kwargs["poolclass"] = NullPool
    else:
        kwargs["pool_size"] = settings.db.pool_size
        kwargs["max_overflow"] = settings.db.max_overflow
        kwargs["pool_recycle"] = settings.db.pool_recycle_seconds
        kwargs["pool_timeout"] = settings.db.pool_timeout_seconds
    return create_async_engine(settings.db.async_dsn, **kwargs)


def get_engine(settings: Settings | None = None) -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_engine(settings or get_settings())
    return _engine


def get_sessionmaker(settings: Settings | None = None) -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(
            bind=get_engine(settings),
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
    return _sessionmaker


@asynccontextmanager
async def session_scope(settings: Settings | None = None) -> AsyncIterator[AsyncSession]:
    """Transactional scope for background work (worker, CLI, tests).

    Commits on clean exit, rolls back on any exception. Used by the worker, which has
    no request lifecycle to hang a session off.
    """
    factory = get_sessionmaker(settings)
    session = factory()
    try:
        yield session
        await session.commit()
    except BaseException:
        await session.rollback()
        raise
    finally:
        await session.close()


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency.

    Does *not* commit: routes commit explicitly at the point they mean to, so a
    handler that raises after a partial write cannot have half of it persisted by the
    dependency teardown.
    """
    factory = get_sessionmaker()
    session = factory()
    try:
        yield session
    except BaseException:
        await session.rollback()
        raise
    finally:
        await session.close()


async def dispose_engine() -> None:
    """Close pooled connections. Called on application shutdown and between tests."""
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None


__all__ = [
    "create_engine",
    "dispose_engine",
    "get_db",
    "get_engine",
    "get_sessionmaker",
    "session_scope",
]
