"""Quarantine digest Celery tasks (Section 8, FR-06, UC-03).

Queue: digest

All functions are stubs.  Full implementation follows in a later iteration.
"""
from __future__ import annotations

import structlog
from celery import shared_task

log = structlog.get_logger(__name__)


@shared_task
def send_digest(email_id: str) -> None:
    """Build and deliver a quarantine digest email for a single quarantined message.

    Creates a DigestLog row, signs a one-time HMAC action token, and sends
    a Resend transactional email containing Confirm/Release action links (FR-06).

    Args:
        email_id: UUID string of the quarantined Email row.
    """
    log.info("task_not_implemented", task="send_digest", email_id=email_id)
