"""PhishGuard test fixtures — Section 8 (tests/conftest.py), Section 9 Phase 1H.

Architecture note: the plan specifies aiosqlite in-memory DB but the ORM models
use PostgreSQL-specific types (UUID with gen_random_uuid() server default, JSONB,
INET) that are incompatible with SQLite.  We use the existing PostgreSQL instance
with transaction-scoped rollback for test isolation instead.  All other spec
requirements (fakeredis, factory-boy, CELERY_TASK_ALWAYS_EAGER) are unchanged.

Test isolation strategy:
  - Each test function runs inside an outer database transaction that is always
    rolled back at teardown, so no test data persists between tests.
  - session.commit() within route handlers is intercepted by SQLAlchemy's
    join_transaction_mode="create_savepoint" and becomes a SAVEPOINT, keeping
    all writes visible within the test but never touching the outer transaction.
  - Redis uses a fresh fakeredis.aioredis.FakeRedis() per test.

nest_asyncio: Celery tasks call asyncio.run() internally (for NLP pipeline and
quarantine_service).  With task_always_eager=True, tasks run synchronously inside
the pytest-asyncio event loop, causing "This event loop is already running".
nest_asyncio.apply() patches asyncio to allow nested event loop execution.
"""
from __future__ import annotations

# nest_asyncio allows Celery tasks to call asyncio.run() from within the
# pytest-asyncio running event loop (task_always_eager=True scenario).
# Must be applied early, before any async fixtures run.
import nest_asyncio
nest_asyncio.apply()

import uuid
from datetime import datetime, timezone
from textwrap import dedent
from typing import AsyncGenerator

import fakeredis.aioredis
import factory
import pytest
import pytest_asyncio
from faker import Faker
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings
from app.core.security import create_access_token, hash_password
from app.models.email import Email
from app.models.organisation import Organisation
from app.models.user import User

# ---------------------------------------------------------------------------
# Module-level engine — NullPool so each test gets a fresh physical connection
# that is never shared across event loops (each test function gets its own loop
# under asyncio_mode=auto, so pooled connections from the previous loop would
# otherwise raise "Event loop is closed" errors).
# ---------------------------------------------------------------------------

_async_engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    poolclass=NullPool,
)

# Import the FastAPI app singleton AFTER creating the engine so that the
# app's lifespan startup banner doesn't run twice during test collection.
from app.main import app as _app  # noqa: E402

# ---------------------------------------------------------------------------
# event_loop — session-scoped (spec requirement; handled by asyncio_mode=auto)
# ---------------------------------------------------------------------------
# With pytest-asyncio 0.23+ and asyncio_mode=auto, the event loop is managed
# automatically.  An explicit session-scoped event_loop is no longer required
# and has been removed to avoid the DeprecationWarning introduced in 0.21+.

# ---------------------------------------------------------------------------
# Faker singleton
# ---------------------------------------------------------------------------

_faker = Faker()

# ---------------------------------------------------------------------------
# Factory classes (factory-boy, factory.Factory — no sync ORM persistence)
# ---------------------------------------------------------------------------
# All factories produce plain Python model instances.
# Callers are responsible for db.add(obj) + await db.flush().


class OrgFactory(factory.Factory):
    """Organisation model factory with faker-generated fields."""

    class Meta:
        model = Organisation

    id = factory.LazyFunction(uuid.uuid4)
    name = factory.Faker("company")
    forwarding_address_slug = factory.LazyFunction(
        lambda: f"test-{uuid.uuid4().hex[:4]}"
    )
    suspicious_threshold = 30
    phishing_threshold = 80
    auto_quarantine_high_risk = True
    prepend_subject_warning = True
    connector_status = "unconfigured"
    data_retention_days = 90


class UserFactory(factory.Factory):
    """User model factory with faker-generated fields.

    Always sets a Python-side UUID so tests never depend on gen_random_uuid().
    Default password is 'test-password-123' (bcrypt-hashed at build time).
    """

    class Meta:
        model = User

    id = factory.LazyFunction(uuid.uuid4)
    org_id = factory.LazyFunction(uuid.uuid4)   # override in tests
    full_name = factory.Faker("name")
    email = factory.LazyFunction(lambda: f"user_{uuid.uuid4().hex[:8]}@test.example")
    password_hash = factory.LazyFunction(lambda: hash_password("test-password-123"))
    role = "analyst"
    is_active = True


class EmailFactory(factory.Factory):
    """Email model factory for ingested email records."""

    class Meta:
        model = Email

    id = factory.LazyFunction(uuid.uuid4)
    org_id = factory.LazyFunction(uuid.uuid4)   # override in tests
    sender = factory.Faker("email")
    subject = factory.Faker("sentence", nb_words=6)
    body_text = factory.Faker("paragraph")
    links = factory.LazyFunction(list)
    attachment_metadata = factory.LazyFunction(list)
    received_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))
    status = "pending"
    ingestion_source = "upload"
    added_to_training = False


# ---------------------------------------------------------------------------
# Database session fixture — function-scoped with rollback isolation
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async DB session; roll back ALL writes after each test.

    join_transaction_mode="create_savepoint" intercepts session.commit()
    calls made inside route handlers and turns them into SAVEPOINTs.  The
    outer connection transaction is always rolled back in teardown.
    """
    conn = await _async_engine.connect()
    trans = await conn.begin()
    session = AsyncSession(
        conn,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )
    try:
        yield session
    finally:
        await session.close()
        await trans.rollback()
        await conn.close()


# ---------------------------------------------------------------------------
# Redis mock fixture — function-scoped, fresh per test
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def redis_mock() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    """Fresh in-memory FakeRedis instance per test (no cross-test state)."""
    r = fakeredis.aioredis.FakeRedis()
    yield r
    await r.aclose()


# ---------------------------------------------------------------------------
# HTTP client fixture — dependency-overridden for test isolation
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def async_client(
    db_session: AsyncSession,
    redis_mock: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator[AsyncClient, None]:
    """httpx AsyncClient wired to the FastAPI app with test dependency overrides.

    get_db  → yields the transaction-scoped test session
    get_redis → returns the per-test FakeRedis instance
    """
    from app.dependencies import get_db, get_redis

    async def _override_db() -> AsyncGenerator[AsyncSession, None]:
        try:
            yield db_session
            await db_session.commit()   # becomes SAVEPOINT via join_transaction_mode
        except HTTPException:
            # HTTPException is intentional HTTP flow (401, 403, 422, 429 …).
            # Do NOT rollback — that would undo fixture data written to the same
            # db_session via join_transaction_mode="create_savepoint", causing
            # subsequent requests in the same test to lose the test fixtures.
            raise
        except Exception:
            await db_session.rollback()
            raise

    async def _override_redis() -> fakeredis.aioredis.FakeRedis:
        return redis_mock

    _app.dependency_overrides[get_db] = _override_db
    _app.dependency_overrides[get_redis] = _override_redis

    async with AsyncClient(
        transport=ASGITransport(app=_app),
        # Use https:// so httpx sends Secure cookies (refresh_token has Secure=True).
        # ASGITransport is in-process — the scheme does not affect actual transport.
        base_url="https://testserver",
    ) as client:
        yield client

    _app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Domain object fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def org(db_session: AsyncSession) -> Organisation:
    """Persisted Organisation for use in auth/email tests."""
    o = OrgFactory()
    db_session.add(o)
    await db_session.flush()
    await db_session.refresh(o)
    return o


@pytest_asyncio.fixture
async def admin_user(db_session: AsyncSession, org: Organisation) -> User:
    """Persisted admin User belonging to ``org``."""
    u = UserFactory(
        org_id=org.id,
        email="admin@testorg.example",
        role="admin",
        password_hash=hash_password("test-password-123"),
    )
    db_session.add(u)
    await db_session.flush()
    await db_session.refresh(u)
    return u


@pytest_asyncio.fixture
async def analyst_user(db_session: AsyncSession, org: Organisation) -> User:
    """Persisted analyst User belonging to ``org``."""
    u = UserFactory(
        org_id=org.id,
        email="analyst@testorg.example",
        role="analyst",
        password_hash=hash_password("test-password-123"),
    )
    db_session.add(u)
    await db_session.flush()
    await db_session.refresh(u)
    return u


@pytest.fixture
def admin_token(admin_user: User) -> str:
    """Short-lived JWT access token for the admin user."""
    return create_access_token(
        user_id=str(admin_user.id),
        org_id=str(admin_user.org_id),
        role=admin_user.role,
    )


@pytest.fixture
def analyst_token(analyst_user: User) -> str:
    """Short-lived JWT access token for the analyst user."""
    return create_access_token(
        user_id=str(analyst_user.id),
        org_id=str(analyst_user.org_id),
        role=analyst_user.role,
    )


# ---------------------------------------------------------------------------
# Email fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_eml() -> bytes:
    """Realistic phishing email in RFC-2822 .eml format."""
    return dedent("""\
        From: "IT Support" <it-support@phish-evil.example>
        To: victim@company.example
        Subject: URGENT: Your account will be suspended in 24 hours
        Date: Mon, 25 May 2026 10:00:00 +0000
        MIME-Version: 1.0
        Content-Type: text/html; charset=utf-8
        Message-ID: <phish-test-001@phish-evil.example>

        <html><body>
        <p>Dear user,</p>
        <p>Your account has been flagged. Click
        <a href="http://phishing-site.evil.example/steal-creds">here</a>
        immediately to avoid suspension.</p>
        <p>IT Security Team</p>
        </body></html>
    """).encode()


# ---------------------------------------------------------------------------
# Celery eager-execution override
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _celery_eager() -> None:
    """Run Celery tasks synchronously in-process during tests (Section 9 F-06)."""
    from app.tasks.celery_app import celery_app

    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagates = True
    yield
    celery_app.conf.task_always_eager = False
    celery_app.conf.task_eager_propagates = False
