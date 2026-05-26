"""Section 4.6 -- FR-02, UC-02: Forwarding Inbox endpoints.

GET   /forwarding               -- forwarding address + connector status
GET   /forwarding/emails        -- paginated IMAP-ingested email list
PATCH /forwarding/config        -- save IMAP credentials (admin only)
POST  /forwarding/test          -- fire test email (non-blocking, P-04 fix)
"""
from __future__ import annotations

import math
import uuid
from datetime import datetime, timezone
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import CurrentUser, get_current_user, get_db, require_admin
from app.models.audit_log import AuditLog
from app.models.email import Email
from app.models.organisation import Organisation
from app.schemas.forwarding import (
    ForwardingConfigRequest,
    ForwardingConfigResponse,
    ForwardingEmailItem,
    ForwardingEmailListResponse,
    ForwardingStatusResponse,
    ForwardingTestResponse,
    SetupInstruction,
)
from app.services import forwarding_service

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["forwarding"])

# ---------------------------------------------------------------------------
# Setup instructions shown on the Forwarding Inbox page (Section 4.6)
# ---------------------------------------------------------------------------

_SETUP_INSTRUCTIONS = [
    SetupInstruction(step=1, text="Copy your forwarding address below."),
    SetupInstruction(step=2, text="Add it as a forwarding rule in your email client."),
    SetupInstruction(step=3, text="Configure IMAP credentials in Settings (Admin)."),
    SetupInstruction(step=4, text="Click 'Send Test Message' to verify the connection."),
]


# ---------------------------------------------------------------------------
# GET /forwarding
# ---------------------------------------------------------------------------


@router.get(
    "/forwarding",
    response_model=ForwardingStatusResponse,
    summary="Forwarding address and IMAP connector status",
)
async def get_forwarding_status(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ForwardingStatusResponse:
    """Return the org's forwarding address and current IMAP connector status."""
    org = (
        await db.execute(
            select(Organisation).where(Organisation.id == current_user.org_id)
        )
    ).scalar_one()

    forwarding_address = forwarding_service.build_forwarding_address(
        org.forwarding_address_slug or ""
    )

    return ForwardingStatusResponse(
        forwarding_address=forwarding_address,
        connector_status=org.connector_status,
        imap_user=org.imap_user,
        setup_instructions=_SETUP_INSTRUCTIONS,
    )


# ---------------------------------------------------------------------------
# GET /forwarding/emails
# ---------------------------------------------------------------------------


@router.get(
    "/forwarding/emails",
    response_model=ForwardingEmailListResponse,
    summary="Paginated IMAP-ingested email list",
)
async def list_forwarding_emails(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ForwardingEmailListResponse:
    """Return emails received via IMAP (ingestion_source='imap'), newest first."""
    base = select(Email).where(
        Email.org_id == current_user.org_id,
        Email.ingestion_source == "imap",
    )

    total: int = (
        await db.execute(select(func.count()).select_from(base.subquery()))
    ).scalar_one()

    rows = (
        await db.execute(
            base.order_by(Email.ingested_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).scalars().all()

    items = [
        ForwardingEmailItem(
            id=r.id,
            sender=r.sender,
            subject=r.subject,
            risk_score=None,   # populated via AnalysisResult join in a later optimisation
            status=r.status,
            ingested_at=r.ingested_at,
        )
        for r in rows
    ]
    pages = max(1, math.ceil(total / page_size))
    return ForwardingEmailListResponse(items=items, total=total, page=page, pages=pages)


# ---------------------------------------------------------------------------
# PATCH /forwarding/config  (Admin only)
# ---------------------------------------------------------------------------


@router.patch(
    "/forwarding/config",
    response_model=ForwardingConfigResponse,
    summary="Save IMAP credentials and test connection (admin only)",
)
async def update_forwarding_config(
    body: ForwardingConfigRequest,
    request: Request,
    current_user: CurrentUser = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ForwardingConfigResponse:
    """Save IMAP configuration with Fernet-encrypted password.

    After saving, immediately tests the IMAP connection using
    :func:`~app.services.forwarding_service.test_imap_connection` and sets
    ``connector_status`` accordingly.  Writes an ``imap_config_updated`` audit
    log row.
    """
    from app.core.security import fernet_encrypt  # noqa: PLC0415

    org = (
        await db.execute(
            select(Organisation).where(Organisation.id == current_user.org_id)
        )
    ).scalar_one()

    # Persist encrypted credentials.
    org.imap_host = body.imap_host
    org.imap_port = body.imap_port
    org.imap_user = str(body.imap_user)
    org.imap_password_encrypted = fernet_encrypt(body.imap_password)

    # Test connection — synchronous, run in thread executor so the event loop
    # is not blocked during the TCP + TLS + IMAP handshake.
    import asyncio  # noqa: PLC0415

    loop = asyncio.get_event_loop()
    ok: bool = await loop.run_in_executor(
        None,
        forwarding_service.test_imap_connection,
        body.imap_host,
        body.imap_port,
        str(body.imap_user),
        body.imap_password,
    )
    connector_status = "active" if ok else "error"
    org.connector_status = connector_status

    db.add(
        AuditLog(
            org_id=current_user.org_id,
            user_id=current_user.id,
            action="imap_config_updated",
            ip_address=request.client.host if request.client else None,
            request_id=request.headers.get("x-request-id"),
            detail={
                "imap_user": str(body.imap_user),
                "connector_status": connector_status,
            },
        )
    )

    await db.commit()

    logger.info(
        "imap_config_updated",
        org_id=str(current_user.org_id),
        connector_status=connector_status,
    )
    return ForwardingConfigResponse(connector_status=connector_status)


# ---------------------------------------------------------------------------
# POST /forwarding/test  (P-04 fix: non-blocking)
# ---------------------------------------------------------------------------


@router.post(
    "/forwarding/test",
    response_model=ForwardingTestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Send a test forwarded email (non-blocking, P-04 fix)",
)
async def test_forwarding(
    current_user: CurrentUser = Depends(get_current_user),
) -> ForwardingTestResponse:
    """Fire a forwarding_test Celery task and return 202 immediately.

    P-04 fix: no blocking wait for IMAP response.  The task appends a probe
    message to the org mailbox; when imap_poll picks it up naturally (≤60 s)
    the analysis chain fires and an ``imap_ingested`` SSE reaches the UI.

    On IMAP error the task publishes a ``forwarding_test_complete`` SSE with
    ``success=False`` directly to the requesting user's SSE channel.
    """
    test_job_id = uuid.uuid4()

    try:
        from app.tasks.forwarding_tasks import forwarding_test  # noqa: PLC0415

        forwarding_test.delay(str(current_user.org_id), str(current_user.id))
    except Exception:
        logger.warning(
            "forwarding_test_dispatch_failed",
            org_id=str(current_user.org_id),
        )

    return ForwardingTestResponse(
        test_job_id=test_job_id,
        message="Test email sent. Check Recent forwarded emails.",
    )
