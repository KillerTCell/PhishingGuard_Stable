"""Email outcome routing and SSE notification service (Section 5.1 Task 5, FR-05).

Public API:
    apply_outcome  -- async; routes email by classification, publishes SSE events,
                      and increments per-analyst unread-notification counters.

Section 5.1 Task 5 routing table:
    'safe'       → Email.status = 'delivered'
    'suspicious' → Email.status = 'flagged';
                   if Organisation.prepend_subject_warning: prefix '[SUSPICIOUS] '
    'phishing'   → Email.status = 'quarantined';
                   AnalysisResult.quarantined = True;
                   if Organisation.auto_quarantine_high_risk: fire send_digest.delay()

Section 2.2 SSE events published:
    scan_complete     -- always; fields: type, email_id, risk_score, status,
                         sender, subject, classification, severity
    quarantine_created -- when status becomes 'quarantined'; fields: type,
                         email_id, sender, subject, risk_score, top_reason

Section 6 notification counters:
    INCR notif:{user_id}:unread for every active analyst in the org.
    Analyst ID list is cached at org:{org_id}:analyst_ids (TTL 300 s).
"""
from __future__ import annotations

import json
from typing import Any
from uuid import UUID

import redis.asyncio as aioredis
import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis_result import AnalysisResult
from app.models.email import Email
from app.models.organisation import Organisation
from app.models.user import User

log = structlog.get_logger(__name__)

# Analyst-IDs cache TTL — invalidated explicitly on user add/deactivate (Section 6).
_ANALYST_IDS_CACHE_TTL = 300  # seconds


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _severity(risk_score: int) -> str:
    """Map risk_score (0-100) to a severity band string.

    Args:
        risk_score: Integer ML risk score.

    Returns:
        One of ``'critical'``, ``'high'``, ``'medium'``, or ``'low'``.
    """
    if risk_score >= 90:
        return "critical"
    if risk_score >= 80:
        return "high"
    if risk_score >= 30:
        return "medium"
    return "low"


async def _publish_sse(
    redis: aioredis.Redis,
    org_id: UUID,
    payload: dict[str, Any],
) -> None:
    """PUBLISH to the org pub/sub channel and XADD to the org stream.

    Both operations use the same JSON-serialised *payload*.  The stream is
    capped at 200 entries with MAXLEN ~ (approximate) so cleanup is O(1).

    Args:
        redis:   Async Redis client.
        org_id:  Organisation UUID — determines channel and stream key.
        payload: JSON-serialisable event dict (must include a ``'type'`` key).
    """
    data = json.dumps(payload)
    channel = f"org:{org_id}:events"
    stream_key = f"org:{org_id}:stream"
    await redis.publish(channel, data)
    await redis.xadd(stream_key, {"data": data}, maxlen=200, approximate=True)


async def _bump_analyst_notifications(
    redis: aioredis.Redis,
    db: AsyncSession,
    org_id: UUID,
) -> None:
    """INCR ``notif:{user_id}:unread`` for every active analyst in the org.

    Analyst UUID list is served from ``org:{org_id}:analyst_ids`` in Redis
    (TTL :data:`_ANALYST_IDS_CACHE_TTL`).  On cache miss the list is fetched
    from the DB and written back.

    Args:
        redis:  Async Redis client.
        db:     Async DB session (read-only — no writes performed here).
        org_id: Organisation UUID whose analysts receive the notification bump.
    """
    cache_key = f"org:{org_id}:analyst_ids"
    cached = await redis.get(cache_key)
    if cached:
        try:
            user_ids: list[str] = json.loads(cached)
        except (json.JSONDecodeError, TypeError):
            user_ids = []
    else:
        rows = (
            await db.execute(
                select(User.id).where(
                    User.org_id == org_id,
                    User.is_active.is_(True),
                )
            )
        ).scalars().all()
        user_ids = [str(uid) for uid in rows]
        await redis.setex(cache_key, _ANALYST_IDS_CACHE_TTL, json.dumps(user_ids))

    for user_id in user_ids:
        await redis.incr(f"notif:{user_id}:unread")


# ---------------------------------------------------------------------------
# apply_outcome — public entry point
# ---------------------------------------------------------------------------


async def apply_outcome(
    email_id: UUID,
    db: AsyncSession,
    redis: aioredis.Redis,
) -> None:
    """Route email by classification, publish SSE, and bump notification counters.

    Caller is responsible for the AsyncSession lifecycle (commit / rollback /
    close).  This function issues its own ``await db.commit()`` after all DB
    mutations so callers using auto-commit sessions do not need to do so
    themselves.

    SSE publishing and notification counter failures are caught and logged at
    WARNING level — they must never block the routing outcome (Section 5.1
    Task 5: non-blocking pub/sub).

    Args:
        email_id: UUID of the Email row to process.
        db:       Async SQLAlchemy session.
        redis:    Async Redis client.
    """
    email_id_str = str(email_id)

    # ── Load records ─────────────────────────────────────────────────────────
    email = (
        await db.execute(select(Email).where(Email.id == email_id))
    ).scalar_one_or_none()
    if email is None:
        log.error("apply_outcome_email_not_found", email_id=email_id_str)
        return

    org = (
        await db.execute(
            select(Organisation).where(Organisation.id == email.org_id)
        )
    ).scalar_one_or_none()
    auto_quarantine: bool = org.auto_quarantine_high_risk if org else True
    prepend_warning: bool = org.prepend_subject_warning if org else False

    analysis = (
        await db.execute(
            select(AnalysisResult).where(AnalysisResult.email_id == email_id)
        )
    ).scalar_one_or_none()
    classification: str = (analysis.classification if analysis else None) or "safe"
    risk_score: int = analysis.risk_score if analysis else 0
    top_features: list = analysis.top_features if analysis else []

    # ── Routing ───────────────────────────────────────────────────────────────
    new_status: str

    if classification == "phishing":
        new_status = "quarantined"

        await db.execute(
            update(Email.__table__)
            .where(Email.__table__.c.id == email_id)
            .values(status="quarantined")
        )
        if analysis is not None:
            await db.execute(
                update(AnalysisResult.__table__)
                .where(AnalysisResult.__table__.c.email_id == email_id)
                .values(quarantined=True)
            )
        if auto_quarantine:
            try:
                from app.tasks.digest_tasks import send_digest  # noqa: PLC0415

                send_digest.delay(email_id_str)
            except Exception as digest_exc:
                log.warning(
                    "apply_outcome_digest_dispatch_failed",
                    email_id=email_id_str,
                    error=str(digest_exc),
                )

    elif classification == "suspicious":
        new_status = "flagged"
        update_values: dict[str, Any] = {"status": "flagged"}
        if prepend_warning:
            original_subject = email.subject or ""
            if not original_subject.startswith("[SUSPICIOUS] "):
                update_values["subject"] = f"[SUSPICIOUS] {original_subject}"
        await db.execute(
            update(Email.__table__)
            .where(Email.__table__.c.id == email_id)
            .values(**update_values)
        )

    else:  # safe (or unknown)
        new_status = "delivered"
        await db.execute(
            update(Email.__table__)
            .where(Email.__table__.c.id == email_id)
            .values(status="delivered")
        )

    await db.commit()

    # ── Derived SSE fields ────────────────────────────────────────────────────
    severity = _severity(risk_score)
    sender = email.sender or ""
    subject = email.subject or ""

    # ── Publish scan_complete SSE (Section 2.2) ────────────────────────────
    scan_complete: dict[str, Any] = {
        "type": "scan_complete",
        "email_id": email_id_str,
        "risk_score": risk_score,
        "status": new_status,
        "sender": sender,
        "subject": subject,
        "classification": classification,
        "severity": severity,
    }
    try:
        await _publish_sse(redis, email.org_id, scan_complete)
    except Exception as sse_exc:
        log.warning(
            "SSE publish failed for %s",
            email_id_str,
            exc_type=type(sse_exc).__name__,
            error=str(sse_exc),
        )

    # ── Publish quarantine_created SSE when applicable (Section 2.2) ───────
    if new_status == "quarantined":
        top_reason: str | None = (
            top_features[0].get("name") if top_features else None
        )
        quarantine_created: dict[str, Any] = {
            "type": "quarantine_created",
            "email_id": email_id_str,
            "sender": sender,
            "subject": subject,
            "risk_score": risk_score,
            "top_reason": top_reason,
        }
        try:
            await _publish_sse(redis, email.org_id, quarantine_created)
        except Exception as sse_exc:
            log.warning(
                "SSE publish failed for %s",
                email_id_str,
                exc_type=type(sse_exc).__name__,
                error=str(sse_exc),
            )

    # ── Notification counters (Section 6) ─────────────────────────────────
    try:
        await _bump_analyst_notifications(redis, db, email.org_id)
    except Exception as notif_exc:
        log.warning(
            "apply_outcome_notif_failed",
            email_id=email_id_str,
            error=str(notif_exc),
        )

    log.info(
        "apply_outcome_done",
        email_id=email_id_str,
        classification=classification,
        risk_score=risk_score,
        new_status=new_status,
        severity=severity,
    )
