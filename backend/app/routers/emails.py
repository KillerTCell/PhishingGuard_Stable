"""Section 4.2 -- FR-02, UC-02, UC-03: Email list and detail endpoints.

POST   /emails/upload   -- .eml file upload (≤5 MB)
GET    /emails          -- paginated list with risk_band filter (A-07)
GET    /emails/{id}     -- full detail with NLP features
DELETE /emails/{id}     -- hard delete (admin only, Privacy Act erasure)
"""
from __future__ import annotations

import math
import os
import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

import structlog
from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as app_settings
from app.dependencies import CurrentUser, get_current_user, get_db, require_admin
from app.models.analysis_result import AnalysisResult
from app.models.audit_log import AuditLog
from app.models.email import Email
from app.models.email_feature import EmailFeature
from app.schemas.emails import (
    EmailDetail,
    EmailFeatureDetail,
    EmailListItem,
    EmailListResponse,
    EmailUploadResponse,
    LinkDetail,
    AttachmentMetadata,
)

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["emails"])

_MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB


# ---------------------------------------------------------------------------
# POST /emails/upload
# ---------------------------------------------------------------------------


@router.post(
    "/emails/upload",
    response_model=EmailUploadResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Upload a .eml file for analysis",
)
async def upload_email(
    file: UploadFile = File(...),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EmailUploadResponse:
    """Ingest a .eml file and queue it for the analysis pipeline.

    Validates:
        - Content type must be message/rfc822 or application/octet-stream
        - File size <= 5 MB
        - Parseability (stdlib email.parser)

    Saves raw bytes to /tmp/{uuid}.eml then fires Celery analysis chain.
    UC-02 step 1.
    """
    from email import policy
    from email.parser import BytesParser

    # Type check
    allowed = {"message/rfc822", "application/octet-stream", "text/plain"}
    if file.content_type and file.content_type not in allowed:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Only .eml files are accepted",
        )

    raw = await file.read()

    if len(raw) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="File too large — maximum 5 MB",
        )

    # Basic parseability check
    try:
        BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="File could not be parsed as an email",
        )

    email_id = uuid.uuid4()
    tmp_path = f"/tmp/{email_id}.eml"
    with open(tmp_path, "wb") as f_out:
        f_out.write(raw)

    email_record = Email(
        id=email_id,
        org_id=current_user.org_id,
        ingestion_source="upload",
        status="pending",
        received_at=datetime.now(timezone.utc),
    )
    db.add(email_record)
    await db.flush()

    # Fire analysis chain (best-effort — tasks built later)
    try:
        from app.tasks.analysis_tasks import analysis_chain

        analysis_chain.delay(str(email_id))
    except Exception:
        logger.warning("analysis_chain_dispatch_failed", email_id=str(email_id))

    return EmailUploadResponse(email_id=email_id, status="pending")


# ---------------------------------------------------------------------------
# GET /emails
# ---------------------------------------------------------------------------


@router.get(
    "/emails",
    response_model=EmailListResponse,
    summary="Paginated email list with filters",
)
async def list_emails(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    risk_band: str = Query(default="all"),
    search: Optional[str] = Query(default=None, max_length=200),
    sort_by: Literal["received_at", "risk_score"] = Query(default="received_at"),
    sort_dir: Literal["asc", "desc"] = Query(default="desc"),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EmailListResponse:
    """Return paginated emails for this organisation.

    A-07 fix: risk_band maps to score ranges:
        critical  90-100
        high      80-89
        medium    30-79
        low       0-29
    """
    # Build query with LEFT JOIN to analysis_results for risk_score + classification
    base = (
        select(
            Email,
            AnalysisResult.risk_score,
            AnalysisResult.classification,
            AnalysisResult.severity,
        )
        .outerjoin(AnalysisResult, AnalysisResult.email_id == Email.id)
        .where(Email.org_id == current_user.org_id)
    )

    if status_filter:
        base = base.where(Email.status == status_filter)

    # risk_band filter
    if risk_band == "critical":
        base = base.where(AnalysisResult.risk_score >= 90)
    elif risk_band == "high":
        base = base.where(
            AnalysisResult.risk_score >= 80, AnalysisResult.risk_score < 90
        )
    elif risk_band == "medium":
        base = base.where(
            AnalysisResult.risk_score >= 30, AnalysisResult.risk_score < 80
        )
    elif risk_band == "low":
        base = base.where(AnalysisResult.risk_score < 30)

    if search:
        like = f"%{search}%"
        base = base.where(
            Email.sender.ilike(like) | Email.subject.ilike(like)
        )

    # Count
    total: int = (
        await db.execute(select(func.count()).select_from(base.subquery()))
    ).scalar_one()

    # Sort
    sort_col = (
        Email.received_at
        if sort_by == "received_at"
        else AnalysisResult.risk_score
    )
    if sort_dir == "desc":
        base = base.order_by(sort_col.desc().nullslast())
    else:
        base = base.order_by(sort_col.asc().nullsfirst())

    rows = (
        await db.execute(base.offset((page - 1) * page_size).limit(page_size))
    ).all()

    items = [
        EmailListItem(
            id=row.Email.id,
            sender=row.Email.sender,
            subject=row.Email.subject,
            risk_score=row.risk_score,
            severity=row.severity,
            status=row.Email.status,
            classification=row.classification,
            top_reason=None,  # derived from top_features in a service layer
            received_at=row.Email.received_at,
        )
        for row in rows
    ]

    pages = max(1, math.ceil(total / page_size))
    return EmailListResponse(items=items, total=total, page=page, pages=pages)


# ---------------------------------------------------------------------------
# GET /emails/{id}
# ---------------------------------------------------------------------------


@router.get(
    "/emails/{email_id}",
    response_model=EmailDetail,
    summary="Full email detail with analysis results",
)
async def get_email(
    email_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> EmailDetail:
    """Return full email detail including NLP features and analysis results.

    JOIN across emails + analysis_results + email_features.
    org_id check enforced (multi-tenant isolation).
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

    # Fetch email features
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

    # Deserialise JSONB fields
    links = [
        LinkDetail(**lnk) if isinstance(lnk, dict) else lnk
        for lnk in (email.links or [])
    ]
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
        severity=analysis.severity if analysis else None,
        explanation=analysis.explanation if analysis else None,
        top_features=top_features,
        model_version=analysis.model_version if analysis else None,
        quarantined=email.status == "quarantined",
        added_to_training=email.added_to_training,
    )


# ---------------------------------------------------------------------------
# DELETE /emails/{id}  (Admin only — hard delete)
# ---------------------------------------------------------------------------


@router.delete(
    "/emails/{email_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Hard delete email and all child records (admin only)",
)
async def delete_email(
    email_id: uuid.UUID,
    request: Request,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Permanently delete an email and all child rows (CASCADE).

    Used for Privacy Act erasure requests.  Writes audit_log.
    """
    result = await db.execute(
        select(Email).where(Email.id == email_id, Email.org_id == current_user.org_id)
    )
    email = result.scalar_one_or_none()
    if email is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")

    await db.delete(email)

    log = AuditLog(
        org_id=current_user.org_id,
        user_id=current_user.id,
        action="email_deleted",
        target_type="email",
        target_id=str(email_id),
        ip_address=request.client.host if request.client else None,
        request_id=request.headers.get("x-request-id"),
        detail={},
    )
    db.add(log)
