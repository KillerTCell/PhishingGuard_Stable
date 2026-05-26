"""FastAPI dependency injection functions for PhishGuard.

All route handlers should import their dependencies from here rather than
directly from ``app.core.*`` so that test overrides stay in one place.

Dependency graph (Depends hierarchy):
    get_db()               → AsyncSession    (from app.core.database)
    get_redis()            → Redis           (singleton pool)
    get_current_user()     → CurrentUser     (JWT → DB → active check)
    require_admin()        → CurrentUser     (get_current_user + role check)
    get_org_thresholds()   → OrgThresholds   (Redis cache → DB fallback)
    validate_digest_token()→ DigestTokenInfo (HMAC verify + replay guard)

Section 7.2 — Route Protection Matrix:
    Public routes            → no dependency
    Any authenticated user   → get_current_user()
    Admin-only routes        → require_admin()
    Digest action link       → validate_digest_token()
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import AsyncGenerator, Optional

import redis.asyncio as aioredis
from fastapi import Cookie, Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.security import (
    decode_access_token,
    is_jti_blacklisted,
    verify_digest_token,
)
from app.models.digest_log import DigestLog
from app.models.organisation import Organisation
from app.models.user import User

# ---------------------------------------------------------------------------
# Shared bearer scheme — auto-populates OpenAPI "Authorize" button
# ---------------------------------------------------------------------------

_bearer_scheme = HTTPBearer(auto_error=False)

# ---------------------------------------------------------------------------
# Redis connection pool (one pool, reused across requests)
# ---------------------------------------------------------------------------

_redis_pool: Optional[aioredis.Redis] = None


def _get_redis_pool() -> aioredis.Redis:
    """Return the process-level Redis connection pool (lazy init)."""
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            max_connections=20,
        )
    return _redis_pool


# ---------------------------------------------------------------------------
# get_db — async database session
# ---------------------------------------------------------------------------


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async DB session; commit on success, rollback on error.

    Re-exported here so routers only need to import from ``app.dependencies``.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ---------------------------------------------------------------------------
# get_redis — async Redis client
# ---------------------------------------------------------------------------


async def get_redis() -> aioredis.Redis:
    """Return the shared async Redis client.

    FastAPI calls this as a dependency; callers receive the pool directly
    (no context manager needed — the pool manages its own connections).
    """
    return _get_redis_pool()


# ---------------------------------------------------------------------------
# CurrentUser — returned by get_current_user()
# ---------------------------------------------------------------------------


@dataclass
class CurrentUser:
    """Validated, active user extracted from the JWT access token.

    Carries everything routers need for multi-tenant filtering (org_id),
    RBAC checks (role), and audit logging (id, full_name).
    """

    id: uuid.UUID
    org_id: uuid.UUID
    role: str               # 'admin' | 'analyst'
    full_name: str
    email: str
    is_active: bool


# ---------------------------------------------------------------------------
# get_current_user — Bearer token → DB user → active check
# ---------------------------------------------------------------------------


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    token_param: Optional[str] = Query(default=None, alias="token"),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> CurrentUser:
    """Resolve the authenticated user from a JWT access token.

    Accepts the token in two places:
      1. ``Authorization: Bearer <token>`` header  (all standard routes)
      2. ``?token=<token>`` query param            (SSE only — EventSource cannot
         set custom headers per the browser SSE spec)

    Raises:
        401 UNAUTHORIZED  — missing / malformed / expired token
        403 FORBIDDEN     — account deactivated (is_active=False)

    Section 7.2: inactive user rejection → 403 per UC-01 edge flow.
    """
    raw_token: Optional[str] = None
    if credentials is not None:
        raw_token = credentials.credentials
    elif token_param is not None:
        raw_token = token_param

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(raw_token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id_str: Optional[str] = payload.get("sub")
    jti: Optional[str] = payload.get("jti")

    if not user_id_str or not jti:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token claims",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Access tokens are short-lived (8h) and are not blacklisted on logout —
    # only the refresh token JTI is blacklisted.  But if somehow the access
    # token's jti ends up in the blacklist (future-proofing), reject it.
    if await is_jti_blacklisted(redis, jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = uuid.UUID(user_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token subject",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user: Optional[User] = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    return CurrentUser(
        id=user.id,
        org_id=user.org_id,
        role=user.role,
        full_name=user.full_name,
        email=user.email,
        is_active=user.is_active,
    )


# ---------------------------------------------------------------------------
# require_admin — admin-only route guard
# ---------------------------------------------------------------------------


async def require_admin(
    current_user: CurrentUser = Depends(get_current_user),
) -> CurrentUser:
    """Reject non-admin users with 403.

    Section 7.2: admin-only routes — PATCH /settings, DELETE /emails/{id},
    POST /auth/invite, POST /quarantine/{id}/send-digest, GET /users*, etc.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )
    return current_user


# ---------------------------------------------------------------------------
# OrgThresholds — returned by get_org_thresholds()
# ---------------------------------------------------------------------------


@dataclass
class OrgThresholds:
    """Cached org detection thresholds.

    Sourced from Redis (TTL 300 s) then DB fallback.
    Used by classify_email task and the stats endpoint.
    """

    suspicious: int
    phishing: int


_THRESHOLD_CACHE_TTL = 300  # seconds (Section 5.1: Redis SETEX 300)


async def get_org_thresholds(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> OrgThresholds:
    """Return this org's detection thresholds (Redis cache → DB fallback).

    Cache key: ``org:{org_id}:thresholds``   TTL: 300 s
    On cache miss: SELECT from organisations and repopulate cache.
    """
    cache_key = f"org:{current_user.org_id}:thresholds"
    cached = await redis.get(cache_key)
    if cached:
        data = json.loads(cached)
        return OrgThresholds(
            suspicious=data["suspicious_threshold"],
            phishing=data["phishing_threshold"],
        )

    result = await db.execute(
        select(
            Organisation.suspicious_threshold,
            Organisation.phishing_threshold,
        ).where(Organisation.id == current_user.org_id)
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organisation not found",
        )

    thresholds = OrgThresholds(
        suspicious=row.suspicious_threshold,
        phishing=row.phishing_threshold,
    )
    await redis.setex(
        cache_key,
        _THRESHOLD_CACHE_TTL,
        json.dumps(
            {
                "suspicious_threshold": thresholds.suspicious,
                "phishing_threshold": thresholds.phishing,
            }
        ),
    )
    return thresholds


# ---------------------------------------------------------------------------
# DigestTokenInfo — returned by validate_digest_token()
# ---------------------------------------------------------------------------


@dataclass
class DigestTokenInfo:
    """Validated, not-yet-consumed digest action token info.

    Passed to GET /digest/action handler so it can apply the outcome
    without re-querying the DigestLog row.
    """

    digest_log: DigestLog
    action: str  # 'confirm' | 'release'


async def validate_digest_token(
    token: str = Query(...),
    action: str = Query(...),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> DigestTokenInfo:
    """Validate a HMAC-signed digest action token from a digest email link.

    Steps (Section 4.4, Section 7.1):
      1. Parse ``email_id`` and ``jti`` from the DigestLog record whose
         ``signed_token_jti`` matches ``jti`` in the token.
      2. Verify HMAC-SHA256 signature.
      3. Check token age ≤ 72 hours (DigestLog.created_at + timedelta).
      4. Check ``action_taken`` is NULL — 410 on replay.
      5. Check ``action`` param is 'confirm' or 'release'.

    Raises:
        400  — HMAC verification failed (tampered token)
        410  — replayed or expired token
        422  — invalid action param value
    """
    if action not in ("confirm", "release"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="action must be 'confirm' or 'release'",
        )

    # The token is formatted as "{email_id}:{jti}:{hmac_hex}"
    # so we can parse the jti to look up the DigestLog row.
    try:
        parts = token.split(":")
        if len(parts) != 3:
            raise ValueError("wrong part count")
        email_id_str, jti, hmac_hex = parts
        email_id = uuid.UUID(email_id_str)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed digest token",
        )

    # HMAC verify — compare_digest used internally (timing-safe)
    if not verify_digest_token(token=hmac_hex, email_id=str(email_id), jti=jti):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid digest token signature",
        )

    # Fetch the DigestLog row
    result = await db.execute(
        select(DigestLog).where(DigestLog.signed_token_jti == jti)
    )
    digest_log: Optional[DigestLog] = result.scalar_one_or_none()

    if digest_log is None:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Digest token not found or already expired",
        )

    # Replay guard — action_taken is non-NULL if already used
    if digest_log.action_taken is not None:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Digest action already taken (replayed token)",
        )

    # Expiry check — token_expires_at stores the 72-hour deadline from sent_at
    from datetime import datetime, timezone

    token_expires_at = digest_log.token_expires_at
    if token_expires_at.tzinfo is None:
        token_expires_at = token_expires_at.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > token_expires_at:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Digest token has expired (>72 hours)",
        )

    return DigestTokenInfo(digest_log=digest_log, action=action)
