"""Quarantine digest Celery tasks (Section 5.2, Section 8, FR-06, UC-05).

Queue: digest

Task:
    send_digest(email_id, digest_log_id=None)
        -- Build WCAG-compliant HTML, sign a one-time HMAC token,
           INSERT DigestLog, send via Resend SDK, publish digest_sent SSE.

Retry policy (Section 5.2):
    Manual retry up to max_retries=3 with exponential back-off
    (30 × 2^n seconds: 30 s, 60 s, 120 s).
    After 3 failures DigestLog.status is set to 'failed' permanently.
"""
from __future__ import annotations

import asyncio
import functools
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import structlog
from celery import shared_task

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Shared sync session factory (cached per worker process)
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _sync_session_factory():
    """Return a cached SQLAlchemy sessionmaker backed by the psycopg2 engine."""
    from sqlalchemy.orm import sessionmaker  # noqa: PLC0415

    from app.core.database import get_sync_engine  # noqa: PLC0415

    return sessionmaker(bind=get_sync_engine(), autocommit=False, autoflush=False)


def _make_sync_session():
    """Create a fresh synchronous SQLAlchemy session."""
    return _sync_session_factory()()


# ---------------------------------------------------------------------------
# SSE publish helper (best-effort, synchronous Redis)
# ---------------------------------------------------------------------------


def _publish_sse(org_id: uuid.UUID, event_type: str, data: dict) -> None:
    """PUBLISH + XADD to the org SSE channel (synchronous Redis).

    Failures are caught and logged at WARNING level — a failed SSE publish
    must never block a digest send.
    """
    try:
        import redis as _sync_redis  # noqa: PLC0415

        from app.core.config import settings  # noqa: PLC0415

        r = _sync_redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
        payload = json.dumps({"type": event_type, "data": data})
        channel = f"org:{org_id}:events"
        r.publish(channel, payload)
        r.xadd(f"org:{org_id}:stream", {"data": payload}, maxlen=200, approximate=True)
        r.close()
    except Exception as exc:
        log.warning(
            "digest_sse_publish_failed",
            event_type=event_type,
            org_id=str(org_id),
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# send_digest task
# ---------------------------------------------------------------------------


@shared_task(bind=True, queue="digest", max_retries=3)
def send_digest(self, email_id: str, digest_log_id: str | None = None) -> None:
    """Build and deliver a quarantine digest email (FR-06, UC-05).

    Steps:
    1. Load Email; abort if recipient_address is NULL.
    2. Generate ``jti = secrets.token_urlsafe(32)`` and sign HMAC token.
    3. Upsert DigestLog row (INSERT on first attempt, UPDATE on retry via
       ON CONFLICT so the same ``digest_log_id`` is reused across retries
       with a fresh JTI).
    4. Render WCAG-compliant HTML via :func:`~app.services.resend_service.build_digest_html`.
    5. Send via :func:`~app.services.resend_service.send_digest_email`.
    6. On success: ``DigestLog.status='sent'``, ``sent_at=now()``;
       publish ``digest_sent`` SSE.
    7. On failure: increment ``retry_count`` and retry with exponential
       back-off (30 × 2^n s).  After max_retries=3:
       ``DigestLog.status='failed'`` permanently.

    Args:
        email_id:      UUID string of the quarantined Email row.
        digest_log_id: Optional pre-generated UUID string for the DigestLog
                       row.  Provided by the router so the ID can be returned
                       immediately; generated internally when called from
                       :func:`~app.services.quarantine_service.apply_outcome`.
    """
    from celery.exceptions import MaxRetriesExceededError  # noqa: PLC0415
    from sqlalchemy import select, update  # noqa: PLC0415
    from sqlalchemy.dialects.postgresql import insert as pg_insert  # noqa: PLC0415

    from app.core.security import sign_digest_token  # noqa: PLC0415
    from app.models.analysis_result import AnalysisResult  # noqa: PLC0415
    from app.models.digest_log import DigestLog  # noqa: PLC0415
    from app.models.email import Email  # noqa: PLC0415
    from app.services import resend_service  # noqa: PLC0415

    email_uuid = uuid.UUID(email_id)
    log_uuid = uuid.UUID(digest_log_id) if digest_log_id else uuid.uuid4()

    session = _make_sync_session()
    try:
        # ── Load email ────────────────────────────────────────────────────────
        email = session.execute(
            select(Email).where(Email.id == email_uuid)
        ).scalar_one_or_none()
        if email is None:
            log.error("send_digest_email_not_found", email_id=email_id)
            return
        if not email.recipient_address:
            log.warning("send_digest_no_recipient", email_id=email_id)
            return

        analysis = session.execute(
            select(AnalysisResult).where(AnalysisResult.email_id == email_uuid)
        ).scalar_one_or_none()

        # ── Generate one-time signed token ────────────────────────────────────
        jti = secrets.token_urlsafe(32)
        hmac_hex = sign_digest_token(email_id, jti)
        signed_token = f"{email_id}:{jti}:{hmac_hex}"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=72)

        # ── Upsert DigestLog (idempotent across retries) ──────────────────────
        # ON CONFLICT on 'id': on retry the existing row is updated with a
        # fresh JTI (since the previous JTI's email may not have been sent)
        # and the retry_count is incremented.
        stmt = (
            pg_insert(DigestLog.__table__)
            .values(
                id=log_uuid,
                email_id=email_uuid,
                recipient_address=email.recipient_address,
                status="pending",
                signed_token_jti=jti,
                token_expires_at=expires_at,
                retry_count=self.request.retries,
            )
            .on_conflict_do_update(
                index_elements=["id"],
                set_={
                    "signed_token_jti": jti,
                    "token_expires_at": expires_at,
                    "retry_count": self.request.retries,
                    "status": "pending",
                },
            )
        )
        session.execute(stmt)
        session.commit()

        # ── Build HTML ────────────────────────────────────────────────────────
        html = resend_service.build_digest_html(email, analysis, signed_token, expires_at)
        subject = (
            "[PhishGuard] Quarantine Notice: "
            f"{(email.subject or 'email')[:50]}"
        )

        # ── Send via Resend ───────────────────────────────────────────────────
        success: bool = asyncio.run(
            resend_service.send_digest_email(email.recipient_address, html, subject)
        )

        if success:
            now = datetime.now(timezone.utc)
            session.execute(
                update(DigestLog.__table__)
                .where(DigestLog.__table__.c.id == log_uuid)
                .values(status="sent", sent_at=now)
            )
            session.commit()
            log.info(
                "send_digest_sent",
                email_id=email_id,
                digest_log_id=str(log_uuid),
                recipient=email.recipient_address,
            )
            _publish_sse(
                email.org_id,
                "digest_sent",
                {
                    "email_id": email_id,
                    "digest_log_id": str(log_uuid),
                    "recipient": email.recipient_address,
                },
            )
        else:
            # Raise to trigger the retry / max-retries logic below.
            raise RuntimeError(
                f"Resend API returned failure for email_id={email_id}"
            )

    except Exception as exc:
        session.rollback()
        log.warning(
            "send_digest_failed",
            email_id=email_id,
            digest_log_id=str(log_uuid),
            retries=self.request.retries,
            error=str(exc),
            exc_type=type(exc).__name__,
        )
        try:
            raise self.retry(
                exc=exc,
                countdown=30 * (2 ** self.request.retries),
            )
        except MaxRetriesExceededError:
            log.error(
                "send_digest_max_retries_exceeded",
                email_id=email_id,
                digest_log_id=str(log_uuid),
            )
            # Mark DigestLog as permanently failed.
            failed_session = _make_sync_session()
            try:
                failed_session.execute(
                    update(DigestLog.__table__)
                    .where(DigestLog.__table__.c.id == log_uuid)
                    .values(status="failed")
                )
                failed_session.commit()
            except Exception as upd_exc:
                log.error(
                    "send_digest_mark_failed_error",
                    email_id=email_id,
                    error=str(upd_exc),
                )
                try:
                    failed_session.rollback()
                except Exception:
                    pass
            finally:
                failed_session.close()
            raise

    finally:
        session.close()
