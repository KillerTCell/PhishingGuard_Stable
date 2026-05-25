"""Alembic async migration environment for PhishGuard.

Uses asyncpg via SQLAlchemy async engine so migration runs share the same
driver stack as the application.  sqlalchemy.url is intentionally left
blank in alembic.ini — this file injects settings.DATABASE_URL directly.

Import order matters: all 11 models must be imported before
``target_metadata`` is assigned so autogenerate detects every table.
"""
from __future__ import annotations

import asyncio
import sys
import os
from logging.config import fileConfig
from typing import TYPE_CHECKING

from sqlalchemy import pool, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# ---------------------------------------------------------------------------
# Ensure the backend/ directory is on sys.path so `app.*` imports resolve
# regardless of the working directory from which alembic is invoked.
# ---------------------------------------------------------------------------
_backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

# ---------------------------------------------------------------------------
# Application imports — settings first, then Base, then all 11 models.
# Models must be imported (even if unused) so Base.metadata is populated
# before target_metadata is read by autogenerate.
# ---------------------------------------------------------------------------
from app.core.config import settings  # noqa: E402
from app.core.database import Base  # noqa: E402

# Import all 11 models — required for autogenerate table detection
import app.models  # noqa: E402, F401  (side-effect import — populates Base.metadata)

# ---------------------------------------------------------------------------
# Alembic Config object — provides access to alembic.ini values
# ---------------------------------------------------------------------------
config = context.config

# Configure logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# All ORM table definitions visible to autogenerate
target_metadata = Base.metadata


# ---------------------------------------------------------------------------
# Migration helpers
# ---------------------------------------------------------------------------

def do_run_migrations(connection: Connection) -> None:
    """Execute pending migrations synchronously inside an async connection."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,              # detect column type changes
        compare_server_default=False,   # server defaults differ by dialect
        render_as_batch=False,          # PostgreSQL supports transactional DDL
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Create an async engine from settings and run migrations online.

    The asyncpg engine is disposed after migrations complete so the
    connection pool does not outlive the alembic process.
    """
    # Build configuration dict — inject DATABASE_URL from Pydantic Settings
    cfg: dict[str, str] = {
        "sqlalchemy.url": settings.DATABASE_URL,
    }

    connectable = async_engine_from_config(
        cfg,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,  # no pooling — single migration run
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


# ---------------------------------------------------------------------------
# Offline mode (generates SQL script without a live DB connection)
# ---------------------------------------------------------------------------

def run_migrations_offline() -> None:
    """Emit SQL to stdout; no DB connection required.

    Useful for generating migration scripts to review before applying.
    Run with: ``alembic upgrade head --sql``
    """
    context.configure(
        url=settings.DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_async_migrations())
