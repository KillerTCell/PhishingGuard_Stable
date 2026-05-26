"""Maintenance Celery tasks — Section 5.6, Section 3.1, NFR-4, P-03 fix, D-02 fix.

Queue: maintenance

Triggered by Celery Beat on a schedule defined in celery_app.py:
    auto_delete_expired_emails      — daily at 02:00 UTC
    auto_create_monthly_partition   — 1st of every month at 01:00 UTC

Architecture note: both tasks open their own synchronous SQLAlchemy sessions
via _make_sync_session() (psycopg2 driver) so they can be called from the
Celery worker process without an event loop.
"""
from __future__ import annotations

import functools
import uuid
from datetime import datetime, timedelta, timezone

import structlog
from celery import shared_task

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Shared sync-session factory (cached per worker process)
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
# auto_delete_expired_emails  (P-03 fix, D-02 fix, Section 5.6, Section 3.1)
# ---------------------------------------------------------------------------


@shared_task(bind=True, queue="maintenance")
def auto_delete_expired_emails(self) -> None:
    """Delete emails older than each org's data_retention_days — daily 02:00 UTC.

    Algorithm (Section 5.6, Section 3.1):
      1. SELECT all organisations (id, data_retention_days).
      2. For each org compute cutoff = now() - timedelta(days=data_retention_days).
      3. DELETE FROM emails WHERE org_id = :org_id AND ingested_at < :cutoff.
         ON DELETE CASCADE propagates to: email_features, analysis_results,
         feedback, digest_log rows automatically.
      4. If deleted_count > 0: write AuditLog(action='auto_data_retention_delete').
      5. Log INFO with org_id, deleted_count, retention_days.
      6. On exception for this org: log ERROR and continue to the next org.
         A per-org failure MUST NOT halt processing of subsequent orgs (P-03).
    """
    from sqlalchemy import select, text  # noqa: PLC0415

    from app.models.audit_log import AuditLog  # noqa: PLC0415
    from app.models.organisation import Organisation  # noqa: PLC0415

    session = _make_sync_session()
    try:
        orgs = session.execute(
            select(Organisation.id, Organisation.data_retention_days)
        ).all()
    except Exception as exc:
        log.error(
            "auto_delete_expired_emails_load_orgs_failed",
            error=str(exc),
            exc_type=type(exc).__name__,
        )
        session.close()
        return

    now_utc = datetime.now(timezone.utc)

    for org_row in orgs:
        org_id: uuid.UUID = org_row.id
        retention_days: int = org_row.data_retention_days

        try:
            cutoff = now_utc - timedelta(days=retention_days)

            result = session.execute(
                text(
                    "DELETE FROM emails "
                    "WHERE org_id = :org_id "
                    "  AND ingested_at < :cutoff"
                ),
                {"org_id": org_id, "cutoff": cutoff},
            )
            deleted_count: int = result.rowcount
            session.commit()

            if deleted_count > 0:
                session.add(
                    AuditLog(
                        org_id=org_id,
                        user_id=None,
                        action="auto_data_retention_delete",
                        detail={
                            "deleted_count": deleted_count,
                            "retention_days": retention_days,
                        },
                    )
                )
                session.commit()

            log.info(
                "auto_delete_expired_emails_org_done",
                message=(
                    f"Deleted {deleted_count} emails for org {org_id} "
                    f"(retention: {retention_days} days)"
                ),
                org_id=str(org_id),
                deleted_count=deleted_count,
                retention_days=retention_days,
            )

        except Exception as org_exc:
            # Per-org failure — roll back and continue; do NOT halt entire task.
            try:
                session.rollback()
            except Exception:
                pass
            log.error(
                "auto_delete_expired_emails_org_error",
                org_id=str(org_id),
                error=str(org_exc),
                exc_type=type(org_exc).__name__,
            )

    session.close()


# ---------------------------------------------------------------------------
# auto_create_monthly_partition  (NFR-4, Section 5.6)
# ---------------------------------------------------------------------------


@shared_task(bind=True, queue="maintenance")
def auto_create_monthly_partition(self) -> None:
    """Pre-create next month's emails partition — 1st of month at 01:00 UTC (NFR-4).

    Runs on the 1st of every month so the next month's partition always exists
    before any rows with that month's received_at are inserted.  Uses
    ``CREATE TABLE IF NOT EXISTS ... PARTITION OF`` so re-runs are idempotent.

    Partition naming convention: ``emails_YYYY_MM``
    Partition range:  [YYYY-MM-01 00:00:00+00, next-month-01 00:00:00+00)

    If the emails table has not yet been converted to a partitioned table
    (i.e. the partitioning migration has not been applied) this task logs a
    warning and exits cleanly — it must never raise in that case.
    """
    from sqlalchemy import text  # noqa: PLC0415

    now = datetime.now(timezone.utc)

    # ── Compute next month ────────────────────────────────────────────────────
    if now.month == 12:
        next_year, next_mon = now.year + 1, 1
    else:
        next_year, next_mon = now.year, now.month + 1

    # ── Compute the month after next (upper bound, exclusive) ─────────────────
    if next_mon == 12:
        to_year, to_mon = next_year + 1, 1
    else:
        to_year, to_mon = next_year, next_mon + 1

    partition_name = f"emails_{next_year:04d}_{next_mon:02d}"
    from_date = f"{next_year:04d}-{next_mon:02d}-01"
    to_date = f"{to_year:04d}-{to_mon:02d}-01"

    ddl = (
        f"CREATE TABLE IF NOT EXISTS {partition_name} "
        f"PARTITION OF emails "
        f"FOR VALUES FROM ('{from_date}') TO ('{to_date}')"
    )

    session = _make_sync_session()
    try:
        session.execute(text(ddl))
        session.commit()
        log.info(
            "auto_create_monthly_partition_done",
            partition=partition_name,
            from_date=from_date,
            to_date=to_date,
        )
    except Exception as exc:
        try:
            session.rollback()
        except Exception:
            pass

        err_str = str(exc)

        # If the emails table is not partitioned yet the DDL will fail with
        # "is not partitioned" — log a warning (not error) and exit cleanly.
        if "is not partitioned" in err_str.lower() or "not partitioned" in err_str.lower():
            log.warning(
                "auto_create_monthly_partition_table_not_partitioned",
                partition=partition_name,
                message=(
                    "emails table is not yet a partitioned table; "
                    "apply the emails_monthly_partitioning Alembic migration first."
                ),
            )
        else:
            log.error(
                "auto_create_monthly_partition_failed",
                partition=partition_name,
                from_date=from_date,
                to_date=to_date,
                error=err_str,
                exc_type=type(exc).__name__,
            )
    finally:
        session.close()
