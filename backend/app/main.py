"""PhishGuard FastAPI application factory.

Usage:
    uvicorn app.main:app --reload          (development)
    gunicorn app.main:app -k uvicorn.workers.UvicornWorker  (production)

create_app() is defined separately from the ``app`` singleton so that the
test suite can call it with overridden dependencies without importing a
live settings object at module level.
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from app.core.config import settings

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Rate limiter (slowapi) — backed by Redis, shared across workers
# ---------------------------------------------------------------------------

limiter = Limiter(
    key_func=get_remote_address,   # overridden per-route for user_id limits
    storage_uri=settings.REDIS_URL,
    default_limits=["200 per minute"],  # global safety net
)


# ---------------------------------------------------------------------------
# SSE lifespan — Redis pub/sub warm-up
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context.

    Startup:
        - Log startup banner with version/config info.
        - Import SSE router here so the Redis pub/sub client is guaranteed
          to be initialised before the first request arrives.

    Shutdown:
        - Close shared Redis pool used by dependencies.get_redis().
    """
    logger.info(
        "phishguard_startup",
        model_version=settings.MODEL_VERSION,
        forwarding_domain=settings.FORWARDING_DOMAIN,
    )
    yield
    # Close the shared Redis pool on shutdown
    from app.dependencies import _get_redis_pool

    pool = _get_redis_pool()
    await pool.aclose()
    logger.info("phishguard_shutdown")


# ---------------------------------------------------------------------------
# CSP middleware (S-05 fix)
# ---------------------------------------------------------------------------


class CSPMiddleware:
    """Add Content-Security-Policy header to every HTML response.

    S-05 fix: /digest/action returns an HTML confirmation page.  Without a
    CSP header, a tampered link could attempt XSS via injected markup.

    Applied to *all* responses with Content-Type: text/html so the header is
    also present on FastAPI's built-in error pages and the OpenAPI docs page.
    """

    def __init__(self, app: FastAPI) -> None:
        """Store the inner ASGI application."""
        self.app = app

    async def __call__(self, scope: dict, receive, send) -> None:  # type: ignore[type-arg]
        """ASGI middleware entry point."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_csp(message: dict) -> None:  # type: ignore[type-arg]
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                content_type = headers.get(b"content-type", b"").decode()
                if content_type.startswith("text/html"):
                    # Mutate headers — build new list
                    new_headers = list(message["headers"])
                    new_headers.append(
                        (
                            b"content-security-policy",
                            b"default-src 'self'",
                        )
                    )
                    message = {**message, "headers": new_headers}
            await send(message)

        await self.app(scope, receive, send_with_csp)


# ---------------------------------------------------------------------------
# Structlog request middleware
# ---------------------------------------------------------------------------


async def _structlog_request_middleware(request: Request, call_next) -> Response:  # type: ignore[type-arg]
    """Inject request_id and path into every structlog log record.

    Binds a UUID ``request_id`` so all log lines for one HTTP request can be
    correlated in log aggregators.  Does NOT log the request body (privacy).
    """
    request_id = str(uuid.uuid4())
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(
        request_id=request_id,
        method=request.method,
        path=request.url.path,
    )
    response: Response = await call_next(request)
    structlog.contextvars.unbind_contextvars("request_id", "method", "path")
    response.headers["X-Request-Id"] = request_id
    return response


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    """Construct and return the PhishGuard FastAPI application.

    Registers all 14 routers under ``/api/v1``, adds middleware in the
    correct order (outermost first), and attaches the slowapi rate-limit
    handler.

    Router prefixes match Section 4 endpoint paths exactly:
        /api/v1/auth          routers/auth.py       Section 4.1
        /api/v1/emails        routers/emails.py     Section 4.2
        /api/v1/analysis      routers/analysis.py   Section 4.3
        /api/v1/dashboard     routers/analysis.py   Section 4.3 (GET /insights)
        /api/v1/quarantine    routers/quarantine.py Section 4.4
        /api/v1/analysis      routers/assistant.py  Section 4.5 (/assistant)
        /api/v1/forwarding    routers/forwarding.py Section 4.6
        /api/v1/feedback      routers/feedback.py   Section 4.7
        /api/v1/digest        routers/digest.py     Section 4.7 (/action)
        /api/v1/settings      routers/settings.py   Section 4.8
        /api/v1/users         routers/users.py      Section 4.9
        /api/v1/events        routers/events.py     Section 4.10
        /api/v1/notifications routers/notifications.py Section 4.11
        /api/v1/audit-log     routers/audit.py      Section 4.12
        /api/v1/health        routers/health.py     Section 4.13
    """
    app = FastAPI(
        title="PhishGuard API",
        description="Advanced Phishing Detection System — REST API",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # ── Attach rate limiter state ──────────────────────────────────────────
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

    # ── CORS ──────────────────────────────────────────────────────────────
    cors_origins: list[str] = [
        o.strip()
        for o in settings.CORS_ORIGINS.split(",")
        if o.strip()
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,   # required for HttpOnly cookie refresh token
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── slowapi middleware ─────────────────────────────────────────────────
    app.add_middleware(SlowAPIMiddleware)

    # ── structlog request context ──────────────────────────────────────────
    app.middleware("http")(_structlog_request_middleware)

    # ── CSP on HTML responses (S-05) ──────────────────────────────────────
    app.add_middleware(CSPMiddleware)  # type: ignore[arg-type]

    # ── Routers ───────────────────────────────────────────────────────────
    # Import deferred to here so that test overrides applied before
    # create_app() can replace router-level dependencies.
    _V1 = "/api/v1"

    from app.routers.auth import router as auth_router
    from app.routers.emails import router as emails_router
    from app.routers.analysis import router as analysis_router
    from app.routers.assistant import router as assistant_router
    from app.routers.quarantine import router as quarantine_router
    from app.routers.digest import router as digest_router
    from app.routers.feedback import router as feedback_router
    from app.routers.settings import router as settings_router
    from app.routers.forwarding import router as forwarding_router
    from app.routers.users import router as users_router
    from app.routers.events import router as events_router
    from app.routers.notifications import router as notifications_router
    from app.routers.audit import router as audit_router
    from app.routers.health import router as health_router

    app.include_router(auth_router,          prefix=_V1)
    app.include_router(emails_router,        prefix=_V1)
    app.include_router(analysis_router,      prefix=_V1)
    app.include_router(assistant_router,     prefix=_V1)
    app.include_router(quarantine_router,    prefix=_V1)
    app.include_router(digest_router,        prefix=_V1)
    app.include_router(feedback_router,      prefix=_V1)
    app.include_router(settings_router,      prefix=_V1)
    app.include_router(forwarding_router,    prefix=_V1)
    app.include_router(users_router,         prefix=_V1)
    app.include_router(events_router,        prefix=_V1)
    app.include_router(notifications_router, prefix=_V1)
    app.include_router(audit_router,         prefix=_V1)
    app.include_router(health_router,        prefix=_V1)

    return app


# ---------------------------------------------------------------------------
# Module-level singleton — used by uvicorn / gunicorn
# ---------------------------------------------------------------------------

app = create_app()
