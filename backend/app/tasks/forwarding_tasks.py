"""Forwarding inbox Celery tasks (Section 5.4, Section 8, FR-07, P-04 fix).

Queue: forwarding

Task:
    forwarding_test(org_id, user_id)
        -- Append a probe .eml to the org IMAP inbox via IMAP4_SSL APPEND.
           imap_poll_all_orgs will pick it up within ≤60 s, triggering the
           normal analysis chain and an imap_ingested SSE — no explicit
           forwarding_test_complete SSE is needed on success.
           On IMAP error: PUBLISH forwarding_test_complete to
           user:{user_id}:events with success=False so the UI shows the
           failure immediately.
"""
from __future__ import annotations

import imaplib
import json
import uuid
from datetime import datetime, timezone
from email.mime.text import MIMEText

import structlog
from celery import shared_task

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Sync session factory (shared pattern — one engine per worker process)
# ---------------------------------------------------------------------------

import functools


@functools.lru_cache(maxsize=1)
def _sync_session_factory():
    """Return a cached SQLAlchemy sessionmaker backed by the psycopg2 engine."""
    from sqlalchemy.orm import sessionmaker  # noqa: PLC0415

    from app.core.database import get_sync_engine  # noqa: PLC0415

    return sessionmaker(bind=get_sync_engine(), autocommit=False, autoflush=False)


def _make_sync_session():
    return _sync_session_factory()()


# ---------------------------------------------------------------------------
# SSE publish helper (best-effort, synchronous Redis)
# ---------------------------------------------------------------------------


def _publish_user_sse(user_id: str, event_type: str, data: dict) -> None:
    """PUBLISH an event to the per-user SSE channel (synchronous Redis).

    Used to deliver forwarding_test_complete failure events directly to the
    requesting user (not the full org) via the ``user:{user_id}:events``
    pub/sub channel that events.py subscribes to.

    Failures are caught and logged at WARNING level — a failed SSE publish
    must never surface to the caller.
    """
    try:
        import redis as _sync_redis  # noqa: PLC0415

        from app.core.config import settings  # noqa: PLC0415

        r = _sync_redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
        payload = json.dumps({"type": event_type, **data})
        r.publish(f"user:{user_id}:events", payload)
        r.close()
    except Exception as exc:
        log.warning(
            "forwarding_sse_publish_failed",
            user_id=user_id,
            event_type=event_type,
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# forwarding_test task
# ---------------------------------------------------------------------------


@shared_task(bind=True, queue="forwarding")
def forwarding_test(self, org_id: str, user_id: str) -> None:
    """Append a probe message to the org IMAP inbox and return (Section 5.4).

    Steps:
    1. Load Organisation; abort with SSE if connector not configured.
    2. Fernet-decrypt imap_password_encrypted → plaintext password.
    3. Build a minimal RFC 2822 .eml with a timestamped subject so the
       operator can identify the test message in the mailbox.
    4. Open IMAP4_SSL(imap_host, imap_port), login, and APPEND the bytes
       to INBOX.  The server places the message in the mailbox.
    5. Logout and return.  imap_poll_all_orgs picks up the message on its
       next 60-second tick, fires the analysis chain, and emits
       imap_ingested SSE — no explicit success SSE is needed here.
    6. On any IMAP error: PUBLISH forwarding_test_complete SSE with
       success=False to user:{user_id}:events so the requesting user
       sees an immediate failure notification.

    Args:
        org_id:  UUID string of the Organisation whose IMAP inbox to probe.
        user_id: UUID string of the requesting User (for error SSE routing).
    """
    from cryptography.fernet import InvalidToken  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    from app.core.config import settings  # noqa: PLC0415
    from app.core.security import fernet_decrypt  # noqa: PLC0415
    from app.models.organisation import Organisation  # noqa: PLC0415

    org_uuid = uuid.UUID(org_id)

    session = _make_sync_session()
    try:
        org = session.execute(
            select(Organisation).where(Organisation.id == org_uuid)
        ).scalar_one_or_none()
    finally:
        session.close()

    if org is None:
        log.error("forwarding_test_org_not_found", org_id=org_id)
        _publish_user_sse(
            user_id,
            "forwarding_test_complete",
            {
                "success": False,
                "message": "Organisation not found.",
            },
        )
        return

    if not org.imap_host or not org.imap_user or not org.imap_password_encrypted:
        log.warning("forwarding_test_missing_config", org_id=org_id)
        _publish_user_sse(
            user_id,
            "forwarding_test_complete",
            {
                "success": False,
                "message": "Could not connect to mailbox. Verify IMAP credentials.",
            },
        )
        return

    # ── Decrypt password ────────────────────────────────────────────────────
    try:
        imap_password = fernet_decrypt(org.imap_password_encrypted)
    except (InvalidToken, Exception) as exc:
        log.error(
            "forwarding_test_decrypt_failed",
            org_id=org_id,
            error=str(exc),
        )
        _publish_user_sse(
            user_id,
            "forwarding_test_complete",
            {
                "success": False,
                "message": "Could not connect to mailbox. Verify IMAP credentials.",
            },
        )
        return

    # ── Build test .eml ─────────────────────────────────────────────────────
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    msg = MIMEText(
        "This is an automated connectivity test from PhishGuard.\n\n"
        "If you see this message in your inbox, the forwarding and IMAP\n"
        "configuration is working correctly.\n\n"
        f"Test ID: {uuid.uuid4()}\n"
        f"Timestamp: {timestamp}\n",
        "plain",
        "utf-8",
    )
    msg["From"] = "test@phishguard.app"
    msg["To"] = org.imap_user
    msg["Subject"] = f"PhishGuard Connectivity Test — {timestamp}"
    msg["Date"] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    test_eml_bytes: bytes = msg.as_bytes()

    # ── IMAP APPEND ─────────────────────────────────────────────────────────
    port: int = org.imap_port or 993
    try:
        conn = imaplib.IMAP4_SSL(org.imap_host, port, timeout=10)
        try:
            conn.login(org.imap_user, imap_password)
            conn.append("INBOX", None, None, test_eml_bytes)
            log.info(
                "forwarding_test_appended",
                org_id=org_id,
                imap_host=org.imap_host,
                port=port,
            )
        finally:
            try:
                conn.logout()
            except Exception:
                pass

    except Exception as exc:
        log.warning(
            "forwarding_test_imap_failed",
            org_id=org_id,
            imap_host=org.imap_host,
            port=port,
            error=str(exc),
            exc_type=type(exc).__name__,
        )
        _publish_user_sse(
            user_id,
            "forwarding_test_complete",
            {
                "success": False,
                "message": "Could not connect to mailbox. Verify IMAP credentials.",
            },
        )
