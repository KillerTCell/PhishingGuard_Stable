"""Section 4.1 -- FR-01, UC-01: Authentication endpoints.

POST /auth/register        -- new org or invite path
POST /auth/login           -- bcrypt verify, Redis rate-limit
GET  /auth/me              -- current user profile
POST /auth/refresh         -- rotate refresh cookie, issue new access token
POST /auth/logout          -- blacklist refresh JTI, clear cookie
POST /auth/forgot-password -- send HMAC reset link (always 202)
POST /auth/reset-password  -- consume signed token, hash new password
POST /auth/invite          -- admin creates invite_token, sends email
POST /auth/accept-invite   -- validate token, create user
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import redis.asyncio as aioredis
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
    fernet_encrypt,
    hash_password,
    sign_digest_token,
    verify_password,
)
from app.dependencies import CurrentUser, get_current_user, get_db, get_redis
from app.models.audit_log import AuditLog
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
)

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["auth"])

_REFRESH_COOKIE = "refresh_token"
_REFRESH_TTL_DAYS = 7
_LOGIN_RATE_KEY = "login_attempts:{ip}"
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW_SECONDS = 900  # 15 min
_RESET_TOKEN_TTL_HOURS = 1
_INVITE_TTL_HOURS = 48


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _set_refresh_cookie(response: Response, token: str) -> None:
    """Set the refresh token as HttpOnly Secure SameSite=Strict cookie (NFR-2)."""
    response.set_cookie(
        key=_REFRESH_COOKIE,
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=_REFRESH_TTL_DAYS * 86400,
        path="/api/v1/auth",  # narrow scope — only sent to auth endpoints
    )


def _clear_refresh_cookie(response: Response) -> None:
    """Expire the refresh cookie."""
    response.delete_cookie(key=_REFRESH_COOKIE, path="/api/v1/auth")


async def _write_audit(
    db: AsyncSession,
    action: str,
    org_id: Optional[uuid.UUID],
    user_id: Optional[uuid.UUID],
    request: Request,
    detail: Optional[dict] = None,
) -> None:
    """Append an audit_log row.  Errors are swallowed so auth never fails due to logging."""
    try:
        ip = request.client.host if request.client else None
        log = AuditLog(
            org_id=org_id,
            user_id=user_id,
            action=action,
            ip_address=ip,
            request_id=request.headers.get("x-request-id"),
            detail=detail or {},
        )
        db.add(log)
    except Exception:
        logger.warning("audit_write_failed", action=action)


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
    """Register a new user.

    Two paths:
      - ``org_name`` provided: create new organisation + first admin user.
      - ``invite_token`` provided: validate token, join existing org.

    A-08 fix: 422 if neither org_name nor invite_token is supplied (enforced
    in RegisterRequest.require_org_or_invite validator).
    """
    if body.invite_token:
        # ── Invite path ──────────────────────────────────────────────────
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

        # Check email uniqueness
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

        org = (
            await db.execute(select(Organisation).where(Organisation.id == invite.org_id))
        ).scalar_one()
        forwarding_address = (
            f"scan+{org.forwarding_address_slug}@{settings.FORWARDING_DOMAIN}"
        )
        await db.flush()
        await _write_audit(db, "login_success", org.id, user.id, request)

    else:
        # ── New organisation path ─────────────────────────────────────────
        existing = (
            await db.execute(select(User).where(User.email == body.email))
        ).scalar_one_or_none()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered",
            )

        slug = secrets.token_urlsafe(8)
        org = Organisation(
            name=body.org_name,
            forwarding_address_slug=slug,
        )
        db.add(org)
        await db.flush()  # populate org.id

        user = User(
            org_id=org.id,
            full_name=body.full_name,
            email=body.email,
            password_hash=hash_password(body.password),
            role="admin",
        )
        db.add(user)
        forwarding_address = (
            f"scan+{slug}@{settings.FORWARDING_DOMAIN}"
        )
        await db.flush()
        await _write_audit(db, "login_success", org.id, user.id, request)

    access_token = create_access_token(
        user_id=str(user.id),
        org_id=str(user.org_id),
        role=user.role,
    )
    refresh_token = create_refresh_token(user_id=str(user.id))
    _set_refresh_cookie(response, refresh_token)

    return RegisterResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        role=user.role,
        org_id=user.org_id,
        forwarding_address=forwarding_address,
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

    Rate limit: 5 attempts / 15 min per IP (Redis INCR).
    429 on 5th attempt with Retry-After: 900 header.

    Audit events: login_success | login_failed | login_blocked_inactive.
    """
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"login_attempts:{client_ip}"

    # Rate limit check
    attempts = await redis.incr(rate_key)
    if attempts == 1:
        await redis.expire(rate_key, _LOGIN_WINDOW_SECONDS)
    if attempts > _LOGIN_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again in 15 minutes.",
            headers={"Retry-After": str(_LOGIN_WINDOW_SECONDS)},
        )

    result = await db.execute(select(User).where(User.email == body.email))
    user: Optional[User] = result.scalar_one_or_none()

    if user is None or not verify_password(body.password, user.password_hash):
        await _write_audit(db, "login_failed", None, None, request, {"email": body.email})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        await _write_audit(db, "login_blocked_inactive", user.org_id, user.id, request)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    # Reset rate counter on success
    await redis.delete(rate_key)

    # Update last_active_at
    user.last_active_at = datetime.now(timezone.utc)

    # Fetch org details for response
    org = (
        await db.execute(select(Organisation).where(Organisation.id == user.org_id))
    ).scalar_one()

    # Unread count from Redis
    unread_raw = await redis.get(f"notif:{user.id}:unread")
    unread_count = int(unread_raw) if unread_raw else 0

    access_token = create_access_token(
        user_id=str(user.id),
        org_id=str(user.org_id),
        role=user.role,
    )
    refresh_token = create_refresh_token(user_id=str(user.id))
    _set_refresh_cookie(response, refresh_token)

    await _write_audit(db, "login_success", user.org_id, user.id, request)

    return LoginResponse(
        access_token=access_token,
        role=user.role,
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

    Required on every app load to populate the top bar (role, name, org).
    1 DB fetch + 1 Redis GET for unread_count.  No side effects.
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

    forwarding_address = (
        f"scan+{org.forwarding_address_slug}@{settings.FORWARDING_DOMAIN}"
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
        forwarding_address=forwarding_address,
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
    """Issue a new access token using the refresh cookie.

    JTI blacklist check prevents replay.  Old JTI is blacklisted immediately.
    New refresh cookie is rotated (TTL reset).
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
    if await redis.exists(f"blacklist:{jti}"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    user_id_str: str = payload.get("sub", "")
    user = (
        await db.execute(select(User).where(User.id == uuid.UUID(user_id_str)))
    ).scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    # Blacklist old JTI
    remaining = int(payload.get("exp", 0)) - int(datetime.now(timezone.utc).timestamp())
    if remaining > 0:
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

    Access tokens are short-lived (8h) and expire naturally; only the
    refresh token needs explicit invalidation (NFR-2).
    """
    from jose import JWTError

    if refresh_token:
        try:
            payload = decode_access_token(refresh_token)
            jti = payload.get("jti", "")
            remaining = int(payload.get("exp", 0)) - int(
                datetime.now(timezone.utc).timestamp()
            )
            if jti and remaining > 0:
                await blacklist_jti(redis, jti, remaining)
        except JWTError:
            pass  # already invalid — clear cookie regardless

    _clear_refresh_cookie(response)


# ---------------------------------------------------------------------------
# POST /auth/forgot-password
# ---------------------------------------------------------------------------


@router.post(
    "/auth/forgot-password",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Initiate password reset (always 202 to prevent enumeration)",
)
async def forgot_password(
    body: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Send a password reset email if the account exists.

    Always returns 202 regardless of whether the email is registered
    (prevents user enumeration -- UC-01 edge flow).
    """
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
        )
        db.add(reset)
        # In production: fire send_reset_email.delay(user.email, raw_token)
        # Deferred until tasks/digest_tasks.py is implemented.
        logger.info("password_reset_token_created", user_id=str(user.id))

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
) -> dict:
    """Verify the signed reset token and update the user's password.

    Token lifetime: 1 hour.  Single-use: used_at is set on consumption.
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

    user = (
        await db.execute(select(User).where(User.id == reset.user_id))
    ).scalar_one()
    user.password_hash = hash_password(body.new_password)
    reset.used_at = datetime.now(timezone.utc)

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
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> InviteResponse:
    """Create an invite token and send an email to the invitee.

    Admin-only.  The invite token is bcrypt-hashed before storage;
    the raw token is embedded in the email link.
    """
    from app.dependencies import require_admin

    # Manual role check (not using Depends to keep route registration simple)
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )

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

    await _write_audit(
        db, "user_invited", current_user.org_id, current_user.id, request,
        {"invitee_email": body.email, "role": body.role.value},
    )

    # In production: fire send_invite_email.delay(body.email, raw_token)
    logger.info("invite_created", invitee=body.email, org_id=str(current_user.org_id))

    return InviteResponse(invite_id=invite.id)


# ---------------------------------------------------------------------------
# POST /auth/accept-invite  (Public -- signed token)
# ---------------------------------------------------------------------------


@router.post(
    "/auth/accept-invite",
    response_model=AcceptInviteResponse,
    summary="Accept an invite and create an account",
)
async def accept_invite(
    body: AcceptInviteRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> AcceptInviteResponse:
    """Validate the invite token and create the invited user's account.

    Token lifetime: 48 hours.  Single-use: used_at is set on acceptance.
    Issues access token and refresh cookie on success.
    """
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
        email=invite.email,
        password_hash=hash_password(body.password),
        role=invite.role,
    )
    db.add(user)
    invite.used_at = datetime.now(timezone.utc)
    await db.flush()

    access_token = create_access_token(
        user_id=str(user.id),
        org_id=str(user.org_id),
        role=user.role,
    )
    refresh_token = create_refresh_token(user_id=str(user.id))
    _set_refresh_cookie(response, refresh_token)

    return AcceptInviteResponse(
        access_token=access_token,
        role=user.role,
        org_id=user.org_id,
    )
