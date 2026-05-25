"""Section 4.8 -- FR-05, UC-04, UC-06: Settings and Export endpoints.

GET   /settings                 -- read thresholds + flags (analyst+)
PATCH /settings                 -- update (admin only, A-03 cross-validation)
POST  /settings/export          -- queue export job (admin only)
GET   /settings/export/{job_id} -- download file or poll status (admin only)
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as aioredis
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as app_settings
from app.dependencies import CurrentUser, get_current_user, get_db, get_redis, require_admin
from app.models.audit_log import AuditLog
from app.models.email import Email
from app.models.export_job import ExportJob
from app.models.feedback import Feedback
from app.models.organisation import Organisation
from app.schemas.settings import (
    ExportCreateRequest,
    ExportCreateResponse,
    ExportJobStatusResponse,
    ExportScope,
    SettingsResponse,
    SettingsUpdateRequest,
)

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["settings"])

_THRESHOLD_CACHE_KEY = "org:{org_id}:thresholds"
_THRESHOLD_CACHE_TTL = 300


async def _invalidate_threshold_cache(redis: aioredis.Redis, org_id: uuid.UUID) -> None:
    """Remove the org threshold cache entry after a PATCH."""
    await redis.delete(f"org:{org_id}:thresholds")


async def _write_audit(
    db: AsyncSession,
    action: str,
    current_user: CurrentUser,
    request: Request,
    detail: Optional[dict] = None,
) -> None:
    """Append an audit log row for settings changes."""
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
# GET /settings
# ---------------------------------------------------------------------------


@router.get(
    "/settings",
    response_model=SettingsResponse,
    summary="Get org detection thresholds and flags",
)
async def get_settings(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SettingsResponse:
    """Return the organisation's current detection thresholds and feature flags."""
    org = (
        await db.execute(
            select(Organisation).where(Organisation.id == current_user.org_id)
        )
    ).scalar_one()

    return SettingsResponse(
        suspicious_threshold=org.suspicious_threshold,
        phishing_threshold=org.phishing_threshold,
        auto_quarantine_high_risk=org.auto_quarantine_high_risk,
        prepend_subject_warning=org.prepend_subject_warning,
    )


# ---------------------------------------------------------------------------
# PATCH /settings  (Admin only)
# ---------------------------------------------------------------------------


@router.patch(
    "/settings",
    response_model=SettingsResponse,
    summary="Update detection thresholds (admin only)",
)
async def update_settings(
    body: SettingsUpdateRequest,
    request: Request,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
) -> SettingsResponse:
    """Update org detection thresholds and/or feature flags.

    A-03 fix: 422 if suspicious_threshold >= phishing_threshold (cross-validated
    in SettingsUpdateRequest.validate_threshold_order).

    Side effects:
      - UPDATE organisations SET ...
      - Redis DEL org:{org_id}:thresholds (invalidate cache)
      - Publish threshold_changed SSE event
      - Write audit_log('threshold_changed', {before, after})
    """
    org = (
        await db.execute(
            select(Organisation).where(Organisation.id == current_user.org_id)
        )
    ).scalar_one()

    before = {
        "suspicious_threshold": org.suspicious_threshold,
        "phishing_threshold": org.phishing_threshold,
        "auto_quarantine_high_risk": org.auto_quarantine_high_risk,
        "prepend_subject_warning": org.prepend_subject_warning,
    }

    if body.suspicious_threshold is not None:
        org.suspicious_threshold = body.suspicious_threshold
    if body.phishing_threshold is not None:
        org.phishing_threshold = body.phishing_threshold
    if body.auto_quarantine_high_risk is not None:
        org.auto_quarantine_high_risk = body.auto_quarantine_high_risk
    if body.prepend_subject_warning is not None:
        org.prepend_subject_warning = body.prepend_subject_warning

    after = {
        "suspicious_threshold": org.suspicious_threshold,
        "phishing_threshold": org.phishing_threshold,
        "auto_quarantine_high_risk": org.auto_quarantine_high_risk,
        "prepend_subject_warning": org.prepend_subject_warning,
    }

    await _write_audit(
        db, "threshold_changed", current_user, request,
        {"before": before, "after": after},
    )

    # Invalidate Redis threshold cache
    await _invalidate_threshold_cache(redis, current_user.org_id)

    # Publish SSE event (best-effort)
    try:
        await redis.publish(
            f"org:{current_user.org_id}:events",
            json.dumps({"type": "threshold_changed", "data": after}),
        )
    except Exception:
        logger.warning("sse_publish_failed", event="threshold_changed")

    return SettingsResponse(
        suspicious_threshold=org.suspicious_threshold,
        phishing_threshold=org.phishing_threshold,
        auto_quarantine_high_risk=org.auto_quarantine_high_risk,
        prepend_subject_warning=org.prepend_subject_warning,
    )


# ---------------------------------------------------------------------------
# POST /settings/export  (Admin only)
# ---------------------------------------------------------------------------


@router.post(
    "/settings/export",
    response_model=ExportCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue a data export job (admin only)",
)
async def create_export(
    body: ExportCreateRequest,
    request: Request,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ExportCreateResponse:
    """Queue an export job and return estimated scope counts immediately.

    A-04 fix: date_range is an enum ('7d'|'30d'|'all') matching UI dropdown.
    A-05 fix: estimated_scope returned in 202 for the 'Estimated scope' card.

    Scope counts are computed with 4 fast COUNT queries before the job is queued.
    """
    from datetime import timedelta

    org_id = current_user.org_id
    now = datetime.now(timezone.utc)

    # Build date filter
    if body.date_range.value == "7d":
        since = now - timedelta(days=7)
    elif body.date_range.value == "30d":
        since = now - timedelta(days=30)
    else:
        since = None

    # Base email query for this org
    base_q = select(func.count(Email.id)).where(Email.org_id == org_id)
    if since:
        base_q = base_q.where(Email.received_at >= since)

    # Scope count queries
    total_count: int = (await db.execute(base_q)).scalar_one()

    phishing_q = base_q.join(
        Feedback, Feedback.email_id == Email.id
    ).where(Feedback.label == "phishing")
    phishing_count: int = (await db.execute(phishing_q)).scalar_one()

    safe_q = base_q.join(
        Feedback, Feedback.email_id == Email.id
    ).where(Feedback.label == "safe")
    safe_count: int = (await db.execute(safe_q)).scalar_one()

    review_q = base_q.join(
        Feedback, Feedback.email_id == Email.id
    ).where(Feedback.label == "needs_investigation")
    review_count: int = (await db.execute(review_q)).scalar_one()

    scope = ExportScope(
        emails=total_count,
        phishing=phishing_count,
        safe=safe_count,
        review=review_count,
    )

    # INSERT export_jobs
    job = ExportJob(
        org_id=org_id,
        requested_by=current_user.id,
        format=body.format.value,
        date_range=body.date_range.value,
        label_filter=body.label_filter.value,
        status="pending",
        estimated_scope_emails=scope.emails,
        estimated_scope_phishing=scope.phishing,
        estimated_scope_safe=scope.safe,
        estimated_scope_review=scope.review,
    )
    db.add(job)
    await db.flush()

    await _write_audit(
        db, "export_generated", current_user, request,
        {"job_id": str(job.id), "format": body.format.value, "date_range": body.date_range.value},
    )

    # Fire Celery task (best-effort import — tasks module built later)
    try:
        from app.tasks.export_tasks import generate_export

        generate_export.delay(str(job.id))
    except Exception:
        logger.warning("export_task_dispatch_failed", job_id=str(job.id))

    return ExportCreateResponse(job_id=job.id, estimated_scope=scope)


# ---------------------------------------------------------------------------
# GET /settings/export/{job_id}  (Admin only)
# ---------------------------------------------------------------------------


@router.get(
    "/settings/export/{job_id}",
    response_model=None,   # returns FileResponse or ExportJobStatusResponse; not Pydantic-serialisable
    summary="Download export file or poll job status (admin only)",
)
async def get_export(
    job_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Return export file (FileResponse) when ready, or job status while pending.

    A-02 fix: FileResponse served directly from /mnt/exports volume mount.
    No signed URL, no redirect.

    Status codes:
        200  -- if pending/generating: JSON ExportJobStatusResponse
        200  -- if ready: FileResponse (Content-Disposition: attachment)
        200  -- if failed: JSON ExportJobStatusResponse with error_message
    """
    import os

    job = (
        await db.execute(
            select(ExportJob).where(
                ExportJob.id == job_id,
                ExportJob.org_id == current_user.org_id,
            )
        )
    ).scalar_one_or_none()

    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Export job not found")

    if job.status == "ready" and job.file_path:
        file_path = job.file_path
        if not os.path.isfile(file_path):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Export file no longer available",
            )
        filename = os.path.basename(file_path)
        return FileResponse(
            path=file_path,
            filename=filename,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # Pending / generating / failed — return status
    scope: Optional[ExportScope] = None
    if job.estimated_scope_emails is not None:
        scope = ExportScope(
            emails=job.estimated_scope_emails,
            phishing=job.estimated_scope_phishing or 0,
            safe=job.estimated_scope_safe or 0,
            review=job.estimated_scope_review or 0,
        )

    return ExportJobStatusResponse(
        job_id=job.id,
        status=job.status,
        estimated_scope=scope,
        format=job.format,
        created_at=job.created_at,
        error_message=job.error_message if job.status == "failed" else None,
    )
