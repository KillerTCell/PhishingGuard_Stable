"""Section 4.9 -- UC admin: User Management endpoints.

GET   /users/stats    -- summary counts (UI Figure 17 cards)
GET   /users          -- all org members ordered by created_at DESC
GET   /users/{id}     -- detail + last 10 audit actions
PATCH /users/{id}     -- update role / is_active (cannot self-deactivate)
DELETE /users/{id}    -- soft-deactivate (UPDATE is_active=False)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import CurrentUser, get_db, require_admin
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.users import (
    RecentAuditAction,
    UserDetailResponse,
    UserListItem,
    UserStatsResponse,
    UserUpdateRequest,
)

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["users"])


async def _write_audit(
    db: AsyncSession,
    action: str,
    current_user: CurrentUser,
    request: Request,
    detail: Optional[dict] = None,
) -> None:
    """Append an audit log row for user management actions."""
    log = AuditLog(
        org_id=current_user.org_id,
        user_id=current_user.id,
        action=action,
        ip_address=request.client.host if request.client else None,
        request_id=request.headers.get("x-request-id"),
        detail=detail or {},
    )
    db.add(log)


# ---------------------------------------------------------------------------
# GET /users/stats
# ---------------------------------------------------------------------------


@router.get(
    "/users/stats",
    response_model=UserStatsResponse,
    summary="User count summary (admin only)",
)
async def get_user_stats(
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> UserStatsResponse:
    """Return aggregate counts for the User Management page summary cards."""
    result = await db.execute(
        select(
            func.count().label("total"),
            func.count().filter(User.role == "admin").label("admins"),
            func.count().filter(User.role == "analyst").label("analysts"),
            func.count().filter(User.is_active == True).label("active"),  # noqa: E712
        ).where(User.org_id == current_user.org_id)
    )
    row = result.one()
    return UserStatsResponse(
        total=row.total,
        admins=row.admins,
        analysts=row.analysts,
        active=row.active,
    )


# ---------------------------------------------------------------------------
# GET /users
# ---------------------------------------------------------------------------


@router.get(
    "/users",
    response_model=list[UserListItem],
    summary="List all org users (admin only)",
)
async def list_users(
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> list[UserListItem]:
    """Return all users in the organisation ordered by created_at DESC."""
    rows = (
        await db.execute(
            select(User)
            .where(User.org_id == current_user.org_id)
            .order_by(User.created_at.desc())
        )
    ).scalars().all()

    return [
        UserListItem(
            id=u.id,
            full_name=u.full_name,
            email=u.email,
            role=u.role,
            is_active=u.is_active,
            last_active_at=u.last_active_at,
            created_at=u.created_at,
        )
        for u in rows
    ]


# ---------------------------------------------------------------------------
# GET /users/{id}
# ---------------------------------------------------------------------------


@router.get(
    "/users/{user_id}",
    response_model=UserDetailResponse,
    summary="User detail with recent audit actions (admin only)",
)
async def get_user(
    user_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> UserDetailResponse:
    """Return a user's profile plus their last 10 audit log entries."""
    user = (
        await db.execute(
            select(User).where(
                User.id == user_id,
                User.org_id == current_user.org_id,
            )
        )
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    audit_rows = (
        await db.execute(
            select(AuditLog)
            .where(AuditLog.user_id == user_id, AuditLog.org_id == current_user.org_id)
            .order_by(AuditLog.created_at.desc())
            .limit(10)
        )
    ).scalars().all()

    recent_actions = [
        RecentAuditAction(
            action=row.action,
            created_at=row.created_at,
            detail=row.detail,
        )
        for row in audit_rows
    ]

    return UserDetailResponse(
        id=user.id,
        full_name=user.full_name,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        last_active_at=user.last_active_at,
        created_at=user.created_at,
        recent_audit_actions=recent_actions,
    )


# ---------------------------------------------------------------------------
# PATCH /users/{id}  (Admin only)
# ---------------------------------------------------------------------------


@router.patch(
    "/users/{user_id}",
    response_model=UserListItem,
    summary="Update user role or active status (admin only)",
)
async def update_user(
    user_id: uuid.UUID,
    body: UserUpdateRequest,
    request: Request,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> UserListItem:
    """Update a user's role and/or active status.

    Cannot self-deactivate: 403 if id == current_user.id and is_active=False.
    """
    user = (
        await db.execute(
            select(User).where(
                User.id == user_id,
                User.org_id == current_user.org_id,
            )
        )
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user_id == current_user.id and body.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You cannot deactivate your own account",
        )

    changes: dict = {}
    if body.role is not None:
        changes["role"] = {"from": user.role, "to": body.role.value}
        user.role = body.role.value
    if body.is_active is not None:
        changes["is_active"] = {"from": user.is_active, "to": body.is_active}
        user.is_active = body.is_active

    if changes:
        await _write_audit(
            db, "user_updated", current_user, request,
            {"target_user_id": str(user_id), "changes": changes},
        )

    return UserListItem(
        id=user.id,
        full_name=user.full_name,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        last_active_at=user.last_active_at,
        created_at=user.created_at,
    )


# ---------------------------------------------------------------------------
# DELETE /users/{id}  (Admin only — soft-deactivate)
# ---------------------------------------------------------------------------


@router.delete(
    "/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Soft-deactivate a user (admin only)",
)
async def deactivate_user(
    user_id: uuid.UUID,
    request: Request,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Soft-deactivate (set is_active=False).  Does not hard-delete the record."""
    user = (
        await db.execute(
            select(User).where(
                User.id == user_id,
                User.org_id == current_user.org_id,
            )
        )
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.is_active = False
    await _write_audit(
        db, "user_deactivated", current_user, request,
        {"target_user_id": str(user_id)},
    )
