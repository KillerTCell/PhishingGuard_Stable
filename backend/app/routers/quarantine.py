"""Section 4.4 -- FR-05, UC-03, UC-05: Quarantine review endpoints.

GET  /quarantine                        -- paginated queue (A-06: total_count)
GET  /quarantine/{id}                   -- full detail
GET  /quarantine/{id}/digest-preview    -- HTML digest preview
POST /quarantine/{id}/confirm           -- mark confirmed_phishing
POST /quarantine/{id}/release           -- release to delivered
POST /quarantine/{id}/investigate       -- flag for investigation
POST /quarantine/{id}/send-digest       -- fire digest email (admin only)
"""
from __future__ import annotations

import json
import math
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import redis.asyncio as aioredis
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import sign_digest_token
from app.dependencies import CurrentUser, get_current_user, get_db, get_redis, require_admin
from app.services.notification_service import push_notification
from app.models.analysis_result import AnalysisResult
from app.models.audit_log import AuditLog
from app.models.email import Email
from app.models.email_feature import EmailFeature
from app.models.feedback import Feedback
from app.schemas.emails import AttachmentMetadata, EmailDetail, EmailFeatureDetail, LinkDetail
from app.schemas.common import EmailStatus, FeedbackState, Severity
from app.schemas.quarantine import (
    DigestPreviewResponse,
    QuarantineActionResponse,
    QuarantineListItem,
    QuarantineListResponse,
    SendDigestResponse,
)

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["quarantine"])


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _severity(risk_score: int) -> Severity:
    """Map risk_score (0–100) to a Severity enum value."""
    if risk_score >= 90:
        return Severity.critical
    if risk_score >= 80:
        return Severity.high
    if risk_score >= 30:
        return Severity.medium
    return Severity.low


async def _write_audit(
    db: AsyncSession,
    action: str,
    current_user: CurrentUser,
    request: Request,
    target_id: Optional[uuid.UUID] = None,
    detail: Optional[dict[str, Any]] = None,
) -> None:
    """Append an audit log row for quarantine actions."""
    log = AuditLog(
        org_id=current_user.org_id,
        user_id=current_user.id,
        action=action,
        target_type="email",
        target_id=target_id,   # UUID column — do NOT stringify
        ip_address=request.client.host if request.client else None,
        request_id=request.headers.get("x-request-id"),
        detail=detail or {},
    )
    db.add(log)


async def _publish_sse(redis: aioredis.Redis, org_id: uuid.UUID, event: dict[str, Any]) -> None:
    """PUBLISH to the org pub/sub channel + XADD to the org stream (best-effort).

    Both operations use the same JSON payload.  XADD (maxlen 200) feeds the
    Last-Event-ID replay in events.py (Section 6.2).
    """
    try:
        data = json.dumps(event)
        channel = f"org:{org_id}:events"
        stream_key = f"org:{org_id}:stream"
        await redis.publish(channel, data)
        await redis.xadd(stream_key, {"data": data}, maxlen=200, approximate=True)
    except Exception:
        logger.warning("sse_publish_failed", event_type=event.get("type"))


# ---------------------------------------------------------------------------
# GET /quarantine
# ---------------------------------------------------------------------------


@router.get(
    "/quarantine",
    response_model=QuarantineListResponse,
    summary="Paginated quarantine queue",
)
async def list_quarantine(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    search: Optional[str] = Query(default=None, max_length=200),
    sort_by: str = Query(default="received_at"),
    sort_dir: str = Query(default="desc"),
    feedback_state: Optional[str] = Query(default=None),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> QuarantineListResponse:
    """Return paginated emails in the quarantine queue.

    Status filter: ``quarantined`` + ``confirmed_phishing`` (Section 4.4).
    ``feedback_state`` filter is applied via a correlated subquery on the
    most-recent Feedback row per email.
    A-06 fix: returns ``total_count`` (not ``total``) for the '0 in queue' badge.
    """
    # Correlated subquery: most-recent Feedback.label per Email row.
    latest_feedback_label = (
        select(Feedback.label)
        .where(Feedback.email_id == Email.id)
        .order_by(Feedback.created_at.desc())
        .limit(1)
        .correlate(Email)
        .scalar_subquery()
    )

    base = (
        select(Email, AnalysisResult, latest_feedback_label.label("feedback_label"))
        .outerjoin(AnalysisResult, AnalysisResult.email_id == Email.id)
        .where(
            Email.org_id == current_user.org_id,
            Email.status.in_(("quarantined", "confirmed_phishing")),
        )
    )

    if search:
        like = f"%{search}%"
        base = base.where(Email.sender.ilike(like) | Email.subject.ilike(like))

    # Map UI feedback_state values → Feedback.label values for DB filtering.
    _state_to_label: dict[str, str] = {
        "confirmed_phishing": "phishing",
        "marked_safe": "safe",
        "needs_investigation": "needs_investigation",
    }
    if feedback_state:
        filter_label = _state_to_label.get(feedback_state, feedback_state)
        base = base.where(latest_feedback_label == filter_label)

    total_count: int = (
        await db.execute(select(func.count()).select_from(base.subquery()))
    ).scalar_one()

    sort_col = Email.received_at if sort_by == "received_at" else AnalysisResult.risk_score
    if sort_dir == "desc":
        base = base.order_by(sort_col.desc().nullslast())
    else:
        base = base.order_by(sort_col.asc().nullsfirst())

    rows = (
        await db.execute(base.offset((page - 1) * page_size).limit(page_size))
    ).all()

    # Map Feedback.label → display feedback_state for list items.
    _label_to_state: dict[str, FeedbackState] = {
        "phishing": FeedbackState.confirmed,
        "safe": FeedbackState.released,
        "needs_investigation": FeedbackState.investigating,
    }

    items: list[QuarantineListItem] = []
    for row in rows:
        email_row = row.Email
        ar = row.AnalysisResult
        risk_score = ar.risk_score if ar else 0
        top_features: list[Any] = ar.top_features if ar else []
        top_reason = top_features[0].get("name") if top_features else None
        fb_label: str | None = row.feedback_label
        items.append(
            QuarantineListItem(
                id=email_row.id,
                sender=email_row.sender,
                subject=email_row.subject,
                risk_score=risk_score if ar else None,
                severity=_severity(risk_score) if ar else None,
                top_reason=top_reason,
                status=email_row.status,
                feedback_state=_label_to_state.get(fb_label) if fb_label else None,
                received_at=email_row.received_at,
            )
        )

    pages = max(1, math.ceil(total_count / page_size))
    return QuarantineListResponse(
        items=items, total_count=total_count, page=page, pages=pages
    )


# ---------------------------------------------------------------------------
# GET /quarantine/{id}
# ---------------------------------------------------------------------------


@router.get(
    "/quarantine/{email_id}",
    response_model=EmailDetail,
    summary="Full quarantined email detail",
)
async def get_quarantine_detail(
    email_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EmailDetail:
    """Return full email detail — same schema as GET /emails/{id} plus feedback history."""
    result = await db.execute(
        select(Email, AnalysisResult)
        .outerjoin(AnalysisResult, AnalysisResult.email_id == Email.id)
        .where(
            Email.id == email_id,
            Email.org_id == current_user.org_id,
            Email.status.in_(("quarantined", "confirmed_phishing")),
        )
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Quarantined email not found",
        )

    email, analysis = row

    features = (
        await db.execute(
            select(EmailFeature)
            .where(EmailFeature.email_id == email_id)
            .order_by(EmailFeature.score_contribution.desc())
            .limit(7)
        )
    ).scalars().all()

    top_features = [
        EmailFeatureDetail(
            name=f.feature_name,
            value=float(f.feature_value) if f.feature_value is not None else 0.0,
            score_contribution=f.score_contribution or 0.0,
        )
        for f in features
    ]

    links = [LinkDetail(**lnk) if isinstance(lnk, dict) else lnk for lnk in (email.links or [])]
    attachments = [
        AttachmentMetadata(**att) if isinstance(att, dict) else att
        for att in (email.attachment_metadata or [])
    ]

    return EmailDetail(
        id=email.id,
        sender=email.sender,
        reply_to=email.reply_to,
        recipient_address=email.recipient_address,
        subject=email.subject,
        received_at=email.received_at,
        ingestion_source=email.ingestion_source,
        status=email.status,
        body_text=email.body_text,
        html_sanitised=email.html_sanitised,
        links=links,
        attachment_metadata=attachments,
        spf=email.spf,
        dkim=email.dkim,
        dmarc=email.dmarc,
        risk_score=analysis.risk_score if analysis else None,
        classification=analysis.classification if analysis else None,
        severity=_severity(analysis.risk_score) if analysis else None,
        explanation=analysis.explanation if analysis else None,
        top_features=top_features,
        model_version=analysis.model_version if analysis else None,
        quarantined=True,
        added_to_training=email.added_to_training,
    )


# ---------------------------------------------------------------------------
# GET /quarantine/{id}/digest-preview
# ---------------------------------------------------------------------------


@router.get(
    "/quarantine/{email_id}/digest-preview",
    response_model=DigestPreviewResponse,
    summary="Preview the digest email before sending",
)
async def get_digest_preview(
    email_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> DigestPreviewResponse:
    """Build HTML digest preview without sending.

    Generates a real HMAC-signed token so the preview renders identical to the
    live email (no DigestLog INSERT — preview action links will 410 on click).
    can_send=False if recipient_address is NULL (disables Send button in UI).
    """
    result = await db.execute(
        select(Email, AnalysisResult)
        .outerjoin(AnalysisResult, AnalysisResult.email_id == Email.id)
        .where(Email.id == email_id, Email.org_id == current_user.org_id)
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")

    email, analysis = row

    features = (
        await db.execute(
            select(EmailFeature)
            .where(EmailFeature.email_id == email_id)
            .order_by(EmailFeature.score_contribution.desc())
            .limit(3)
        )
    ).scalars().all()

    top_features = [
        EmailFeatureDetail(
            name=f.feature_name,
            value=float(f.feature_value) if f.feature_value is not None else 0.0,
            score_contribution=f.score_contribution or 0.0,
        )
        for f in features
    ]

    can_send = email.recipient_address is not None

    # Build a real HMAC-signed preview token (no DigestLog INSERT).
    email_id_str = str(email_id)
    jti = secrets.token_urlsafe(32)
    hmac_hex = sign_digest_token(email_id_str, jti)
    signed_token = f"{email_id_str}:{jti}:{hmac_hex}"
    expires_at = datetime.now(timezone.utc) + timedelta(hours=72)

    from app.services import resend_service  # noqa: PLC0415

    html_preview = resend_service.build_digest_html(email, analysis, signed_token, expires_at)

    risk_score = analysis.risk_score if analysis else 0
    explanation = analysis.explanation if analysis else "Analysis pending."

    return DigestPreviewResponse(
        html_preview=html_preview,
        recipient_address=email.recipient_address,
        risk_score=risk_score,
        classification=analysis.classification if analysis else None,
        explanation=explanation,
        top_features=top_features,
        can_send=can_send,
    )


# ---------------------------------------------------------------------------
# POST /quarantine/{id}/confirm
# ---------------------------------------------------------------------------


@router.post(
    "/quarantine/{email_id}/confirm",
    response_model=QuarantineActionResponse,
    summary="Confirm as phishing",
)
async def confirm_phishing(
    email_id: uuid.UUID,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> QuarantineActionResponse:
    """Mark a quarantined email as confirmed phishing.

    Updates email.status, inserts feedback, commits, publishes SSE.  UC-03 step 5.
    """
    email = (
        await db.execute(
            select(Email).where(Email.id == email_id, Email.org_id == current_user.org_id)
        )
    ).scalar_one_or_none()
    if email is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")

    email.status = "confirmed_phishing"
    db.add(
        Feedback(
            email_id=email_id,
            user_id=current_user.id,
            label="phishing",
            source="dashboard",
            created_at=datetime.now(timezone.utc),
        )
    )
    await _write_audit(db, "email_confirmed_phishing", current_user, request, email_id)
    await db.commit()

    await _publish_sse(
        redis,
        current_user.org_id,
        {"type": "scan_complete", "email_id": str(email_id), "status": "confirmed_phishing"},
    )
    await push_notification(
        redis, str(current_user.org_id),
        "email_actioned",
        "Email Confirmed as Phishing",
        f"Email from {email.sender or '(unknown)'} confirmed as phishing and saved for ML training.",
        "danger",
    )
    return QuarantineActionResponse(status=EmailStatus.confirmed_phishing)


# ---------------------------------------------------------------------------
# POST /quarantine/{id}/release
# ---------------------------------------------------------------------------


@router.post(
    "/quarantine/{email_id}/release",
    response_model=QuarantineActionResponse,
    summary="Release quarantined email as safe",
)
async def release_email(
    email_id: uuid.UUID,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> QuarantineActionResponse:
    """Release a quarantined email back to delivered status.  UC-03 step 5."""
    email = (
        await db.execute(
            select(Email).where(Email.id == email_id, Email.org_id == current_user.org_id)
        )
    ).scalar_one_or_none()
    if email is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")

    email.status = "delivered"
    db.add(
        Feedback(
            email_id=email_id,
            user_id=current_user.id,
            label="safe",
            source="dashboard",
            created_at=datetime.now(timezone.utc),
        )
    )
    await _write_audit(db, "email_released", current_user, request, email_id)
    await db.commit()

    await _publish_sse(
        redis,
        current_user.org_id,
        {"type": "scan_complete", "email_id": str(email_id), "status": "delivered"},
    )
    await push_notification(
        redis, str(current_user.org_id),
        "email_actioned",
        "Email Released to Inbox",
        f"Email from {email.sender or '(unknown)'} marked as safe and released.",
        "success",
    )
    return QuarantineActionResponse(status=EmailStatus.delivered)


# ---------------------------------------------------------------------------
# POST /quarantine/{id}/investigate
# ---------------------------------------------------------------------------


@router.post(
    "/quarantine/{email_id}/investigate",
    response_model=QuarantineActionResponse,
    summary="Flag email for further investigation",
)
async def flag_for_investigation(
    email_id: uuid.UUID,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> QuarantineActionResponse:
    """Insert a 'needs_investigation' feedback row.  Email status stays quarantined."""
    email = (
        await db.execute(
            select(Email).where(Email.id == email_id, Email.org_id == current_user.org_id)
        )
    ).scalar_one_or_none()
    if email is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")

    db.add(
        Feedback(
            email_id=email_id,
            user_id=current_user.id,
            label="needs_investigation",
            source="dashboard",
            created_at=datetime.now(timezone.utc),
        )
    )
    await _write_audit(db, "email_flagged_investigation", current_user, request, email_id)
    await db.commit()
    await push_notification(
        redis, str(current_user.org_id),
        "email_actioned",
        "Email Flagged for Investigation",
        f"Email from {email.sender or '(unknown)'} flagged for further review.",
        "warning",
    )
    return QuarantineActionResponse(status=EmailStatus.quarantined)


# ---------------------------------------------------------------------------
# POST /quarantine/{id}/send-digest  (Admin only)
# ---------------------------------------------------------------------------


@router.post(
    "/quarantine/{email_id}/send-digest",
    response_model=SendDigestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue digest email for recipient (admin only)",
)
async def send_digest(
    email_id: uuid.UUID,
    request: Request,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> SendDigestResponse:
    """Validate can_send and fire send_digest Celery task.  UC-05 step 3.

    The DigestLog row is created (and idempotently upserted on retry) by the
    Celery task via INSERT ON CONFLICT.  The router pre-generates the UUID so
    it can be returned to the caller immediately at 202.
    """
    email = (
        await db.execute(
            select(Email).where(Email.id == email_id, Email.org_id == current_user.org_id)
        )
    ).scalar_one_or_none()
    if email is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")

    if not email.recipient_address:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Cannot send digest: recipient address is missing",
        )

    # Pre-generate DigestLog UUID — passed to the task for idempotent upsert.
    log_id = uuid.uuid4()

    await _write_audit(
        db,
        "digest_sent",
        current_user,
        request,
        email_id,
        {"digest_log_id": str(log_id)},
    )
    await db.commit()

    try:
        from app.tasks.digest_tasks import send_digest as send_digest_task  # noqa: PLC0415

        send_digest_task.delay(str(email_id), str(log_id))
    except Exception:
        logger.warning("digest_task_dispatch_failed", email_id=str(email_id))

    return SendDigestResponse(digest_log_id=log_id)
