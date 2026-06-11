"""Section 4.1 — FR-01, UC-01: Authentication endpoints.

POST /auth/register        — new org or invite path
POST /auth/login           — bcrypt verify, per-IP Redis rate-limit
GET  /auth/me              — current user profile + forwarding address
POST /auth/refresh         — rotate refresh cookie, issue new access token
POST /auth/logout          — blacklist refresh JTI, clear cookie (204)
POST /auth/forgot-password — send HMAC reset link; always 202 (anti-enum)
POST /auth/reset-password  — consume signed token, set new password
POST /auth/invite          — admin: INSERT InviteToken, send Resend email
POST /auth/accept-invite   — public: validate token, create user, issue tokens

Security controls (Section 7):
  - Access tokens in memory only (NFR-2); never in localStorage
  - Refresh tokens: HttpOnly Secure SameSite=Strict cookie, path=/api/v1/auth
  - bcrypt rounds=12 for all password hashes (NFR-2)
  - Per-IP Redis rate limit: 5 attempts / 15 min (S-06 fix)
  - Audit trail: login_success | login_failed | login_blocked_inactive |
    login_blocked | user_invited via audit_service.write_audit_log
"""
from __future__ import annotations

import asyncio
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import redis.asyncio as aioredis
import resend as _resend
import structlog
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import (
    blacklist_jti,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    hash_password,
    is_jti_blacklisted,
    verify_password,
)
from app.dependencies import CurrentUser, get_current_user, get_db, get_redis, require_admin
from app.models.invite_token import InviteToken
from app.models.organisation import Organisation
from app.models.password_reset_token import PasswordResetToken
from app.models.user import User
from app.schemas.auth import (
    AcceptInviteRequest,
    AcceptInviteResponse,
    ForgotPasswordRequest,
    InviteRequest,
    InviteResponse,
    LoginRequest,
    LoginResponse,
    MeResponse,
    RefreshResponse,
    RegisterRequest,
    RegisterResponse,
    ResetPasswordRequest,
    UserRole,
)
from app.services import audit_service, forwarding_service, org_service

log = structlog.get_logger(__name__)
router = APIRouter(tags=["auth"])

_REFRESH_COOKIE = "refresh_token"
_REFRESH_TTL_DAYS = 7
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW_SECONDS = 900   # 15 minutes
_RESET_TOKEN_TTL_HOURS = 1
_INVITE_TTL_HOURS = 48


# ---------------------------------------------------------------------------
# Cookie helpers
# ---------------------------------------------------------------------------


def _set_refresh_cookie(response: Response, token: str) -> None:
    """Set the refresh token as HttpOnly SameSite=Lax cookie (NFR-2).

    Path is scoped to ``/api/v1/auth`` so the cookie is only transmitted to
    auth endpoints and never sent with API data requests.

    SameSite=Lax (not Strict) is required for local development where the
    frontend is served over http://localhost:3000 and the backend is at
    https://localhost — Chrome 86+ schemeful same-site treats these as
    cross-site, and SameSite=Strict would prevent the cookie from being sent
    on the POST /auth/refresh call, breaking session restore on page refresh.
    SameSite=Lax is safe for production: it still blocks CSRF on cross-site
    POST requests originating from third-party pages.

    The Secure flag is False in development (ENVIRONMENT=development) so the
    cookie is accessible when the frontend is served over plain HTTP.  In
    production (ENVIRONMENT=production) Secure=True is reinstated — Railway
    always serves over HTTPS.

    Args:
        response: FastAPI Response object for the current request.
        token:    Encoded refresh JWT string.
    """
    is_production = settings.ENVIRONMENT == "production"
    response.set_cookie(
        key=_REFRESH_COOKIE,
        value=token,
        httponly=True,
        secure=is_production,
        samesite="lax",
        max_age=_REFRESH_TTL_DAYS * 86_400,
        path="/api/v1/auth",
    )


def _clear_refresh_cookie(response: Response) -> None:
    """Expire the refresh cookie by deleting it.

    Args:
        response: FastAPI Response object for the current request.
    """
    response.delete_cookie(key=_REFRESH_COOKIE, path="/api/v1/auth")


# ---------------------------------------------------------------------------
# Resend transactional email helper
# ---------------------------------------------------------------------------


async def _send_email(to: str, subject: str, html: str) -> None:
    """Send a transactional email via Resend.  Swallows all exceptions.

    Email delivery failure MUST NOT cause the enclosing route to fail.
    Errors are logged at ERROR level so operators can investigate delivery
    issues without impacting user-facing behaviour.

    Args:
        to:      Recipient email address.
        subject: Email subject line.
        html:    HTML email body.
    """
    try:
        _resend.api_key = settings.RESEND_API_KEY
        sender = "PhishGuard <onboarding@resend.dev>"
        params: _resend.Emails.SendParams = {
            "from": sender,
            "to": [to],
            "subject": subject,
            "html": html,
        }
        # 8-second timeout prevents nginx from closing the connection while waiting
        # for Resend to respond (e.g. on first-send domain verification or slow network).
        await asyncio.wait_for(
            asyncio.to_thread(_resend.Emails.send, params),
            timeout=8.0,
        )
        log.info("email_sent", to=to, subject=subject)
    except Exception as exc:
        log.warning(
            "resend_email_failed",
            to=to,
            subject=subject,
            error=str(exc),
            exc_type=type(exc).__name__,
        )


def _frontend_url() -> str:
    """Return the primary frontend origin from CORS_ORIGINS (first entry).

    Used to construct reset / invite links embedded in transactional emails.
    """
    return settings.CORS_ORIGINS.split(",")[0].strip()


# ---------------------------------------------------------------------------
# POST /auth/register
# ---------------------------------------------------------------------------


@router.post(
    "/auth/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new account",
)
async def register(
    body: RegisterRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> RegisterResponse:
    """Register a new user via one of two paths.

    **New-organisation path** (``org_name`` provided):
      - Create a new organisation with a unique forwarding slug
        (:func:`~app.services.org_service.create_organisation`).
      - INSERT the first user with ``role='admin'``.

    **Invite path** (``invite_token`` provided):
      - Validate the token (not used, not expired).
      - INSERT the user into the invited organisation with the role from the token.
      - Mark the invite as consumed (``used_at = now()``).

    A-08 fix: 422 if neither ``org_name`` nor ``invite_token`` is supplied
    (enforced first by ``RegisterRequest.require_org_or_invite``, then
    re-validated here for explicit HTTP error messaging).

    Bcrypt cost factor 12 is applied in :func:`~app.core.security.hash_password`.
    """
    if not body.org_name and not body.invite_token:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide org_name for a new organisation or invite_token to join one.",
        )

    if body.invite_token:
        # ── Invite path ──────────────────────────────────────────────────────
        token_hash = hashlib.sha256(body.invite_token.encode()).hexdigest()
        result = await db.execute(
            select(InviteToken).where(
                InviteToken.token_hash == token_hash,
                InviteToken.used_at.is_(None),
            )
        )
        invite: Optional[InviteToken] = result.scalar_one_or_none()
        if invite is None or invite.expires_at < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invite token is invalid or expired",
            )

        existing = (
            await db.execute(select(User).where(User.email == body.email))
        ).scalar_one_or_none()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered",
            )

        user = User(
            org_id=invite.org_id,
            full_name=body.full_name,
            email=body.email,
            password_hash=hash_password(body.password),
            role=invite.role,
        )
        db.add(user)
        invite.used_at = datetime.now(timezone.utc)
        await db.flush()
        await db.refresh(user)

        org: Organisation = (
            await db.execute(
                select(Organisation).where(Organisation.id == invite.org_id)
            )
        ).scalar_one()
        fwd_address = forwarding_service.build_forwarding_address(
            org.forwarding_address_slug or ""
        )

    else:
        # ── New-organisation path ─────────────────────────────────────────────
        existing = (
            await db.execute(select(User).where(User.email == body.email))
        ).scalar_one_or_none()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered",
            )

        # F-01 fix: always use org_service so the forwarding slug is generated
        # deterministically (slugify + 4-char hex suffix) rather than random bytes.
        org = await org_service.create_organisation(db, body.org_name)  # type: ignore[arg-type]

        user = User(
            org_id=org.id,
            full_name=body.full_name,
            email=body.email,
            password_hash=hash_password(body.password),
            role="admin",
        )
        db.add(user)
        await db.flush()
        await db.refresh(user)

        fwd_address = forwarding_service.build_forwarding_address(
            org.forwarding_address_slug or ""
        )

    access_token = create_access_token(
        user_id=str(user.id),
        org_id=str(user.org_id),
        role=user.role,
    )
    refresh_token = create_refresh_token(user_id=str(user.id))
    _set_refresh_cookie(response, refresh_token)

    await audit_service.write_audit_log(
        db,
        org_id=user.org_id,
        action="login_success",
        user_id=user.id,
        target_type="user",
        target_id=user.id,
        ip_address=request.client.host if request.client else None,
        request_id=request.headers.get("x-request-id"),
    )

    return RegisterResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        role=UserRole(user.role),
        org_id=user.org_id,
        forwarding_address=fwd_address,
    )


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------


@router.post(
    "/auth/login",
    response_model=LoginResponse,
    summary="Authenticate and receive tokens",
)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> LoginResponse:
    """Verify credentials and issue access + refresh tokens.

    Execution order (Section 7, S-06 fix):

    1. SELECT user — 401 if not found (no audit; no org_id available).
    2. Check ``is_active`` — 403 + ``login_blocked_inactive`` audit if false.
    3. Redis INCR ``login_attempts:{ip}`` (EXPIRE 900 on first attempt).
    4. Rate-limit check — 429 + Retry-After:900 + ``login_blocked`` audit
       if count ≥ 5.
    5. ``verify_password()`` — 401 + ``login_failed`` audit [S-06] if wrong.
    6. Success — clear rate counter, issue tokens, set cookie, update
       ``last_active_at``, fetch ``unread_count`` from Redis, audit ``login_success``.
    """
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"login_attempts:{client_ip}"

    # 1. Fetch user — generic 401 if not found (no audit: no org_id yet)
    result = await db.execute(select(User).where(User.email == body.email))
    user: Optional[User] = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # 2. Active check — before rate-limit so inactive accounts always get 403
    if not user.is_active:
        await audit_service.write_audit_log(
            db,
            org_id=user.org_id,
            action="login_blocked_inactive",
            user_id=user.id,
            target_type="user",
            target_id=user.id,
            ip_address=client_ip,
            request_id=request.headers.get("x-request-id"),
        )
        # Security audit must be committed before the error response is sent:
        # the HTTPException causes the get_db() teardown to rollback, which
        # would wash away the flushed row.  Commit here so the audit survives.
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    # 3. Rate-limit: INCR; set EXPIRE only on first attempt (idempotent after)
    attempts = await redis.incr(rate_key)
    if attempts == 1:
        await redis.expire(rate_key, _LOGIN_WINDOW_SECONDS)

    # 4. Reject if rate limit exceeded (>= so the 5th attempt itself is blocked)
    if attempts >= _LOGIN_MAX_ATTEMPTS:
        await audit_service.write_audit_log(
            db,
            org_id=user.org_id,
            action="login_blocked",
            user_id=user.id,
            target_type="user",
            target_id=user.id,
            ip_address=client_ip,
            request_id=request.headers.get("x-request-id"),
            detail={"attempts": attempts, "limit": _LOGIN_MAX_ATTEMPTS},
        )
        await db.commit()  # commit before raising — audit must survive the 429
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again in 15 minutes.",
            headers={"Retry-After": str(_LOGIN_WINDOW_SECONDS)},
        )

    # 5. Password verification (S-06 fix — audit login_failed separately)
    if not verify_password(body.password, user.password_hash):
        await audit_service.write_audit_log(
            db,
            org_id=user.org_id,
            action="login_failed",
            user_id=user.id,
            target_type="user",
            target_id=user.id,
            ip_address=client_ip,
            request_id=request.headers.get("x-request-id"),
        )
        await db.commit()  # commit before raising — audit must survive the 401
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # 6. Success ─────────────────────────────────────────────────────────────
    # Clear rate counter so a future failed attempt starts fresh
    await redis.delete(rate_key)

    # Update last_active_at (debounced on the client side — always write here)
    user.last_active_at = datetime.now(timezone.utc)

    # Fetch org info for response
    org: Organisation = (
        await db.execute(
            select(Organisation).where(Organisation.id == user.org_id)
        )
    ).scalar_one()

    # Unread notification count (Section 5.1)
    unread_raw = await redis.get(f"notif:{user.id}:unread")
    unread_count = int(unread_raw) if unread_raw else 0

    access_token = create_access_token(
        user_id=str(user.id),
        org_id=str(user.org_id),
        role=user.role,
    )
    refresh_token = create_refresh_token(user_id=str(user.id))
    _set_refresh_cookie(response, refresh_token)

    await audit_service.write_audit_log(
        db,
        org_id=user.org_id,
        action="login_success",
        user_id=user.id,
        target_type="user",
        target_id=user.id,
        ip_address=client_ip,
        request_id=request.headers.get("x-request-id"),
    )

    return LoginResponse(
        access_token=access_token,
        role=UserRole(user.role),
        org_id=user.org_id,
        org_name=org.name,
        unread_count=unread_count,
    )


# ---------------------------------------------------------------------------
# GET /auth/me
# ---------------------------------------------------------------------------


@router.get(
    "/auth/me",
    response_model=MeResponse,
    summary="Current user profile",
)
async def me(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> MeResponse:
    """Return the authenticated user's profile.

    Fetches the organisation name and forwarding slug in a single JOIN query.
    Reads the unread notification count from Redis (``notif:{user_id}:unread``).
    No writes; no side effects.
    """
    result = await db.execute(
        select(User, Organisation)
        .join(Organisation, Organisation.id == User.org_id)
        .where(User.id == current_user.id)
    )
    row = result.one()
    user, org = row

    unread_raw = await redis.get(f"notif:{user.id}:unread")
    unread_count = int(unread_raw) if unread_raw else 0

    fwd_address = forwarding_service.build_forwarding_address(
        org.forwarding_address_slug or ""
    )

    return MeResponse(
        id=user.id,
        full_name=user.full_name,
        email=user.email,
        role=user.role,
        org_id=user.org_id,
        org_name=org.name,
        is_active=user.is_active,
        last_active_at=user.last_active_at,
        unread_count=unread_count,
        forwarding_address=fwd_address,
    )


# ---------------------------------------------------------------------------
# POST /auth/refresh
# ---------------------------------------------------------------------------


@router.post(
    "/auth/refresh",
    response_model=RefreshResponse,
    summary="Rotate refresh token and issue new access token",
)
async def refresh_tokens(
    request: Request,
    response: Response,
    refresh_token: Optional[str] = Cookie(default=None, alias=_REFRESH_COOKIE),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> RefreshResponse:
    """Issue a new access token using the HttpOnly refresh cookie.

    Refresh token rotation steps:
      1. Decode and validate the refresh JWT.
      2. Confirm it carries ``type='refresh'``.
      3. Check the JTI is not blacklisted (replay prevention).
      4. Fetch the user (must still exist and be active).
      5. Blacklist the old JTI for its remaining TTL.
      6. Issue a new access token and rotate the refresh cookie.
    """
    from jose import JWTError

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing",
        )

    try:
        payload = decode_access_token(refresh_token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not a refresh token",
        )

    jti: str = payload.get("jti", "")
    if await is_jti_blacklisted(redis, jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    user_id_str: str = payload.get("sub", "")
    user: Optional[User] = (
        await db.execute(select(User).where(User.id == uuid.UUID(user_id_str)))
    ).scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    # Blacklist the old JTI for its remaining natural lifetime
    remaining = int(payload.get("exp", 0)) - int(datetime.now(timezone.utc).timestamp())
    if jti and remaining > 0:
        await blacklist_jti(redis, jti, remaining)

    access_token = create_access_token(
        user_id=str(user.id),
        org_id=str(user.org_id),
        role=user.role,
    )
    new_refresh = create_refresh_token(user_id=str(user.id))
    _set_refresh_cookie(response, new_refresh)

    return RefreshResponse(access_token=access_token)


# ---------------------------------------------------------------------------
# POST /auth/logout
# ---------------------------------------------------------------------------


@router.post(
    "/auth/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Logout and invalidate refresh token",
)
async def logout(
    response: Response,
    refresh_token: Optional[str] = Cookie(default=None, alias=_REFRESH_COOKIE),
    redis: aioredis.Redis = Depends(get_redis),
) -> None:
    """Blacklist the refresh token JTI and clear the cookie.

    Access tokens (8h) expire naturally and are not stored server-side.
    Only the refresh token's JTI needs explicit invalidation (NFR-2).
    Silently succeeds even if the token is absent or already invalid.
    """
    from jose import JWTError

    if refresh_token:
        try:
            payload = decode_access_token(refresh_token)
            jti: str = payload.get("jti", "")
            remaining = int(payload.get("exp", 0)) - int(
                datetime.now(timezone.utc).timestamp()
            )
            if jti and remaining > 0:
                await blacklist_jti(redis, jti, remaining)
        except JWTError:
            pass  # already expired or invalid — clear the cookie regardless

    _clear_refresh_cookie(response)


# ---------------------------------------------------------------------------
# POST /auth/forgot-password
# ---------------------------------------------------------------------------


@router.post(
    "/auth/forgot-password",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Initiate password reset (always 202 — prevents user enumeration)",
)
async def forgot_password(
    body: ForgotPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Send a password reset email if the account exists and is active.

    Always returns 202 regardless of whether the address is registered
    (prevents user enumeration — UC-01 edge flow).

    If the user exists and is active:
      - Generates an opaque token (``secrets.token_urlsafe(48)``).
      - SHA-256 hashes it before storage (``token_hash``).
      - INSERTs a :class:`~app.models.password_reset_token.PasswordResetToken`
        with a 1-hour expiry.
      - Sends a Resend transactional email with the reset link.
    """
    client_ip = request.client.host if request.client else None

    result = await db.execute(select(User).where(User.email == body.email))
    user: Optional[User] = result.scalar_one_or_none()

    if user and user.is_active:
        raw_token = secrets.token_urlsafe(48)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=_RESET_TOKEN_TTL_HOURS)

        reset = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
            ip_requested_from=client_ip,
        )
        db.add(reset)

        reset_link = (
            f"{_frontend_url()}/PhishGuard.html?reset={raw_token}"
        )
        await _send_email(
            to=user.email,
            subject="Reset your PhishGuard password",
            html=f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
</head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#F8FAFC;margin:0;padding:40px 20px;">
  <div style="max-width:560px;margin:0 auto">
    <div style="text-align:center;margin-bottom:32px">
      <h1 style="font-size:24px;font-weight:700;color:#4F46E5;margin:0">PhishGuard</h1>
      <p style="font-size:13px;color:#9CA3AF;margin:6px 0 0">Email Security Platform</p>
    </div>
    <div style="background:#ffffff;border-radius:14px;border:1px solid #E5E7EB;padding:32px;box-shadow:0 1px 3px rgba(0,0,0,0.06)">
      <div style="text-align:center;margin-bottom:20px">
        <div style="width:52px;height:52px;border-radius:50%;background:#EEF2FF;display:inline-flex;align-items:center;justify-content:center;font-size:24px;">🔒</div>
      </div>
      <h2 style="font-size:20px;font-weight:600;color:#111827;margin:0 0 8px;text-align:center">Reset your password</h2>
      <p style="font-size:15px;color:#374151;line-height:1.6;margin:0 0 8px;text-align:center">Hi {user.full_name},</p>
      <p style="font-size:14px;color:#6B7280;line-height:1.6;margin:0 0 28px;text-align:center">We received a request to reset your PhishGuard password. Click the button below to choose a new one. This link expires in <strong>1 hour</strong>.</p>
      <div style="text-align:center;margin-bottom:28px">
        <a href="{reset_link}" style="display:inline-block;background:#4F46E5;color:#ffffff;text-decoration:none;padding:13px 32px;border-radius:8px;font-size:15px;font-weight:600;letter-spacing:0.01em;">Reset my password →</a>
      </div>
      <div style="background:#F9FAFB;border-radius:8px;border:1px solid #E5E7EB;padding:14px 16px;">
        <p style="font-size:12px;color:#6B7280;line-height:1.6;margin:0">🔐 <strong>Didn't request this?</strong> If you didn't ask to reset your password, you can safely ignore this email. Your password will remain unchanged.</p>
      </div>
    </div>
    <div style="text-align:center;margin-top:24px;padding:0 16px">
      <p style="font-size:12px;color:#9CA3AF;line-height:1.6;margin:0">This link expires in 1 hour and can only be used once.</p>
      <p style="font-size:12px;color:#D1D5DB;margin:12px 0 0">— PhishGuard</p>
    </div>
  </div>
</body>
</html>""",
        )
        log.info("password_reset_token_created", user_id=str(user.id))

    return {}


# ---------------------------------------------------------------------------
# POST /auth/reset-password
# ---------------------------------------------------------------------------


@router.post(
    "/auth/reset-password",
    summary="Consume reset token and set new password",
)
async def reset_password(
    body: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Verify the signed reset token and update the user's password.

    Validation rules:
      - Token must exist in ``password_reset_tokens``.
      - ``used_at`` must be NULL (single-use).
      - ``expires_at`` must be in the future (1-hour window).

    On success: update ``password_hash`` and set ``used_at = now()``.
    """
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    result = await db.execute(
        select(PasswordResetToken).where(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.used_at.is_(None),
        )
    )
    reset: Optional[PasswordResetToken] = result.scalar_one_or_none()

    if reset is None or reset.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Reset token is invalid or expired",
        )

    user: User = (
        await db.execute(select(User).where(User.id == reset.user_id))
    ).scalar_one()

    user.password_hash = hash_password(body.new_password)
    reset.used_at = datetime.now(timezone.utc)

    log.info("password_reset_completed", user_id=str(user.id))
    return {}


# ---------------------------------------------------------------------------
# POST /auth/invite  (Admin only)
# ---------------------------------------------------------------------------


@router.post(
    "/auth/invite",
    response_model=InviteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Invite a new team member (admin only)",
)
async def create_invite(
    body: InviteRequest,
    request: Request,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> InviteResponse:
    """Create a single-use invite token and email it to the invitee.

    Token lifetime: 48 hours.  Token is SHA-256 hashed before storage;
    the raw token is embedded in the email link.

    ``Depends(require_admin)`` enforces the admin-only constraint (Section 7.2).
    """
    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(hours=_INVITE_TTL_HOURS)

    invite = InviteToken(
        org_id=current_user.org_id,
        invited_by_user_id=current_user.id,
        email=body.email,
        role=body.role.value,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db.add(invite)
    await db.flush()
    await db.refresh(invite)

    invite_link = f"{_frontend_url()}/PhishGuard.html?invite={raw_token}"
    _role_display = {"admin": "Owner", "analyst": "Contributor"}.get(
        body.role.value, body.role.value.capitalize()
    )
    inviter_name = current_user.full_name
    await _send_email(
        to=body.email,
        subject="You've been invited to join PhishGuard",
        html=f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#F8FAFC;margin:0;padding:40px 20px;">
  <div style="max-width:560px;margin:0 auto">
    <div style="text-align:center;margin-bottom:32px">
      <h1 style="font-size:24px;font-weight:700;color:#4F46E5;margin:0">PhishGuard</h1>
      <p style="font-size:13px;color:#9CA3AF;margin:6px 0 0">Email Security Platform</p>
    </div>
    <div style="background:#ffffff;border-radius:14px;border:1px solid #E5E7EB;padding:32px;box-shadow:0 1px 3px rgba(0,0,0,0.06)">
      <div style="text-align:center;margin-bottom:20px">
        <div style="width:52px;height:52px;border-radius:50%;background:#EEF2FF;display:inline-flex;align-items:center;justify-content:center;font-size:24px;">🛡️</div>
      </div>
      <h2 style="font-size:20px;font-weight:600;color:#111827;margin:0 0 16px;text-align:center">You've been invited to PhishGuard</h2>
      <p style="font-size:14px;color:#6B7280;line-height:1.6;margin:0 0 24px;text-align:center"><strong>{inviter_name}</strong> has invited you to join their PhishGuard workspace as a <strong>{_role_display}</strong>. Click below to set up your account.</p>
      <div style="text-align:center;margin-bottom:28px">
        <a href="{invite_link}" style="display:inline-block;background:#4F46E5;color:#ffffff;text-decoration:none;padding:13px 32px;border-radius:8px;font-size:15px;font-weight:600;">Accept invitation →</a>
      </div>
      <div style="background:#F9FAFB;border-radius:8px;border:1px solid #E5E7EB;padding:14px 16px;">
        <p style="font-size:12px;color:#6B7280;line-height:1.6;margin:0">⏰ This invitation expires in <strong>48 hours</strong>. If you didn't expect this invitation, you can safely ignore this email.</p>
      </div>
    </div>
    <div style="text-align:center;margin-top:24px">
      <p style="font-size:12px;color:#D1D5DB;margin:0">— PhishGuard</p>
    </div>
  </div>
</body>
</html>""",
    )

    await audit_service.write_audit_log(
        db,
        org_id=current_user.org_id,
        action="user_invited",
        user_id=current_user.id,
        target_type="user",
        ip_address=request.client.host if request.client else None,
        request_id=request.headers.get("x-request-id"),
        detail={"invitee_email": body.email, "role": body.role.value},
    )

    log.info(
        "invite_created",
        invitee=body.email,
        role=body.role.value,
        org_id=str(current_user.org_id),
    )
    return InviteResponse(invite_id=invite.id)


# ---------------------------------------------------------------------------
# POST /auth/accept-invite  (Public — signed token)
# ---------------------------------------------------------------------------


@router.post(
    "/auth/accept-invite",
    response_model=AcceptInviteResponse,
    summary="Accept an invite and create an account",
)
async def accept_invite(
    body: AcceptInviteRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> AcceptInviteResponse:
    """Validate the invite token and create the invited user's account.

    Token lifetime: 48 hours.  Single-use: ``used_at`` is set on acceptance.
    Issues access token and rotates the refresh cookie on success.
    Audits ``login_success`` so the event appears in the admin audit log.
    """
    # NOTE FOR RAILWAY DEPLOYMENT:
    # Invite token lookup uses SHA-256 (deterministic), NOT bcrypt.
    # SHA-256 is safe here because invite tokens are long random secrets
    # (secrets.token_urlsafe(48) = 384 bits of entropy) — not user-chosen
    # passwords, so rainbow-table attacks are not a concern.
    #
    # The lookup is: sha256(raw_token) == stored token_hash (WHERE clause).
    # This is correct and intentional — do not change to bcrypt.checkpw()
    # (bcrypt is non-deterministic; a WHERE clause comparison would always fail).
    # Do not change this lookup method.
    token_hash = hashlib.sha256(body.invite_token.encode()).hexdigest()
    result = await db.execute(
        select(InviteToken).where(
            InviteToken.token_hash == token_hash,
            InviteToken.used_at.is_(None),
        )
    )
    invite: Optional[InviteToken] = result.scalar_one_or_none()

    if invite is None or invite.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invite token is invalid or expired",
        )

    # Guard against duplicate accounts in the same org (invite email is pre-set)
    existing: Optional[User] = (
        await db.execute(
            select(User).where(
                User.email == invite.email,
                User.org_id == invite.org_id,
            )
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists in the organisation",
        )

    user = User(
        org_id=invite.org_id,
        full_name=body.full_name,
        email=invite.email,          # use the email from the invite, not body
        password_hash=hash_password(body.password),
        role=invite.role,
    )
    db.add(user)
    invite.used_at = datetime.now(timezone.utc)
    await db.flush()
    await db.refresh(user)

    access_token = create_access_token(
        user_id=str(user.id),
        org_id=str(user.org_id),
        role=user.role,
    )
    refresh_token = create_refresh_token(user_id=str(user.id))
    _set_refresh_cookie(response, refresh_token)

    await audit_service.write_audit_log(
        db,
        org_id=user.org_id,
        action="login_success",
        user_id=user.id,
        target_type="user",
        target_id=user.id,
        ip_address=request.client.host if request.client else None,
        request_id=request.headers.get("x-request-id"),
    )

    return AcceptInviteResponse(
        access_token=access_token,
        role=UserRole(user.role),
        org_id=user.org_id,
    )
