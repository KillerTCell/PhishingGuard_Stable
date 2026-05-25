"""Maintenance Celery tasks (Section 8, D-02 fix, data retention).

Queue: maintenance

Triggered by Celery Beat on a schedule defined in celery_app.py:
    auto_delete_expired_emails      — daily at 02:00 UTC
    auto_create_monthly_partition   — 1st of every month at 01:00 UTC

All functions are stubs.  Full implementation follows in a later iteration.
"""
from __future__ import annotations

import structlog
from celery import shared_task

log = structlog.get_logger(__name__)


@shared_task
def auto_delete_expired_emails() -> None:
    """Delete emails older than each organisation's ``data_retention_days`` setting.

    Runs daily at 02:00 UTC (Celery Beat schedule in celery_app.py).
    For each organisation, DELETEs Email rows where
    ``created_at < now() - interval '{data_retention_days} days'``.
    Writes an ``auto_data_retention_delete`` AuditLog row per org affected.
    """
    log.info("task_not_implemented", task="auto_delete_expired_emails")


@shared_task
def auto_create_monthly_partition() -> None:
    """Pre-create the next calendar month's Postgres table partition (D-02 fix).

    Runs on the 1st of every month at 01:00 UTC (Celery Beat schedule in
    celery_app.py).  Issues a ``CREATE TABLE IF NOT EXISTS ... PARTITION OF``
    DDL statement for the ``emails`` table's next monthly range partition so
    that INSERTs never fail due to a missing partition.
    """
    log.info("task_not_implemented", task="auto_create_monthly_partition")
