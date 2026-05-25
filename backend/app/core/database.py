"""
SQLAlchemy 2.0 async database engine, session factory, and base class.

All ORM models import Base from here.  FastAPI routes use get_db() as a
dependency.  Alembic migrations use get_sync_engine() via run_sync().
"""
from collections.abc import AsyncGenerator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import declarative_base

from app.core.config import settings

# ---------------------------------------------------------------------------
# Async engine — used by the FastAPI application and Celery workers
# ---------------------------------------------------------------------------
engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,   # drop stale connections before checkout
    echo=False,
)

AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    engine,
    expire_on_commit=False,  # keep attributes accessible after commit
)

# ---------------------------------------------------------------------------
# Declarative base — all ORM models inherit from this
# ---------------------------------------------------------------------------
Base = declarative_base()


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an AsyncSession, committing on success and rolling back on error.

    Usage::

        @router.get("/example")
        async def example(db: AsyncSession = Depends(get_db)) -> ...:
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ---------------------------------------------------------------------------
# Synchronous engine — Alembic only (never used in application code)
# ---------------------------------------------------------------------------
def get_sync_engine() -> Engine:
    """Return a psycopg2-backed synchronous engine for Alembic run_sync().

    Alembic's async env.py calls ``connection.run_sync(do_migrations)`` which
    requires a synchronous execution context.  The URL scheme is rewritten
    from ``+asyncpg`` to ``+psycopg2`` at call time so there is a single
    source of truth (DATABASE_URL in .env).
    """
    sync_url = settings.DATABASE_URL.replace("+asyncpg", "+psycopg2")
    return create_engine(sync_url)
