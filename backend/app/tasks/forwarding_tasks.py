"""Forwarding inbox Celery tasks (Section 8, FR-07).

Queue: forwarding

All functions are stubs.  Full implementation follows in a later iteration.
"""
from __future__ import annotations

import structlog
from celery import shared_task

log = structlog.get_logger(__name__)


@shared_task
def forwarding_test(org_id: str) -> None:
    """Send a probe message to an organisation's forwarding address and verify receipt.

    Used by PATCH /forwarding/test to confirm that the MX record and inbox
    routing are functioning correctly end-to-end.

    Args:
        org_id: UUID string of the Organisation whose forwarding address to probe.
    """
    log.info("task_not_implemented", task="forwarding_test", org_id=org_id)
