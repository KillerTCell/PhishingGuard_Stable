"""Export generation Celery task (Section 5.5, Section 8, FR-08, P-05 fix).

Queue: export

Task:
    generate_export(job_id)
        -- UPDATE ExportJob status='generating', build the email + analysis +
           feedback query, serialise to CSV / JSONL / JSON, write to the Docker
           volume, then UPDATE status='ready'.
           On any failure: DELETE partial file, UPDATE status='failed',
           write audit_log('export_failed').

P-05 fix: export runs asynchronously so POST /settings/export returns 202
immediately and the UI polls GET /settings/export/{job_id} for progress.
"""
from __future__ import annotations

import csv
import functools
import json
import os
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate
from typing import Any

import structlog
from celery import shared_task
from sqlalchemy.orm import Session, sessionmaker

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Shared sync-session factory (one engine per worker process)
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _sync_session_factory() -> sessionmaker[Session]:
    """Return a cached SQLAlchemy sessionmaker backed by the psycopg2 engine."""
    from app.core.database import get_sync_engine  # noqa: PLC0415

    return sessionmaker(bind=get_sync_engine(), autocommit=False, autoflush=False)


def _make_sync_session() -> Session:
    """Create a fresh synchronous SQLAlchemy session."""
    return _sync_session_factory()()


# ---------------------------------------------------------------------------
# Export field list — columns written to every format
# ---------------------------------------------------------------------------

_EXPORT_FIELDS: list[str] = [
    "email_id",
    "sender",
    "recipient_address",
    "subject",
    "received_at",
    "status",
    "ingestion_source",
    "spf",
    "dkim",
    "dmarc",
    "classification",
    "risk_score",
    "explanation",
    "model_version",
    "feedback_label",
]


def _row_to_dict(row: Any) -> dict[str, Any]:
    """Serialise one result row to a plain dict ready for CSV/JSON output."""
    return {
        "email_id": str(row.email_id),
        "sender": row.sender,
        "recipient_address": row.recipient_address,
        "subject": row.subject,
        "received_at": row.received_at.isoformat() if row.received_at else None,
        "status": row.status,
        "ingestion_source": row.ingestion_source,
        "spf": row.spf,
        "dkim": row.dkim,
        "dmarc": row.dmarc,
        "classification": row.classification,
        "risk_score": row.risk_score,
        "explanation": row.explanation,
        "model_version": row.model_version,
        "feedback_label": row.feedback_label,
    }


# ---------------------------------------------------------------------------
# generate_export task
# ---------------------------------------------------------------------------


@shared_task(bind=True, queue="export")  # type: ignore[misc]  # Celery lacks complete type stubs
def generate_export(self: Any, job_id: str) -> None:
    """Generate a data export file and update the ExportJob row (FR-08).

    Steps:
    1. UPDATE ExportJob.status='generating'.
    2. Load ExportJob (org_id, format, date_range, label_filter).
    3. Build query:
         emails
         LEFT JOIN analysis_results ON email_id
         correlated scalar_subquery for latest Feedback.label per email
       Filters: org_id, date_range ('7d'/'30d'/'all'), label_filter.
    4. Create ``{EXPORT_VOLUME_PATH}/{org_id}/`` directory.
    5. Write to ``{EXPORT_VOLUME_PATH}/{org_id}/{job_id}.{format}``:
         csv  — csv.DictWriter with UTF-8 BOM-free
         jsonl — one json.dumps() per line
         json  — json.dump() full array
    6. UPDATE ExportJob SET status='ready', record_count, file_path,
       completed_at=now().
    7. On any exception:
         DELETE partial file if it exists.
         UPDATE ExportJob.status='failed', error_message=str(exc)[:500].
         Write audit_log('export_failed').

    Args:
        job_id: UUID string of the ExportJob row to process.
    """
    from sqlalchemy import select, update  # noqa: PLC0415

    from app.core.config import settings  # noqa: PLC0415
    from app.models.analysis_result import AnalysisResult  # noqa: PLC0415
    from app.models.audit_log import AuditLog  # noqa: PLC0415
    from app.models.email import Email  # noqa: PLC0415
    from app.models.export_job import ExportJob  # noqa: PLC0415
    from app.models.feedback import Feedback  # noqa: PLC0415

    job_uuid = uuid.UUID(job_id)
    file_path: str | None = None
    session = _make_sync_session()

    try:
        # ── 1. Mark generating ────────────────────────────────────────────
        session.execute(
            update(ExportJob.__table__)
            .where(ExportJob.__table__.c.id == job_uuid)
            .values(status="generating")
        )
        session.commit()

        # ── 2. Load ExportJob ─────────────────────────────────────────────
        job = session.execute(
            select(ExportJob).where(ExportJob.id == job_uuid)
        ).scalar_one_or_none()

        if job is None:
            log.error("generate_export_job_not_found", job_id=job_id)
            return

        org_id: uuid.UUID = job.org_id
        fmt: str = job.format                   # 'csv' | 'json' | 'jsonl' | 'eml'
        date_range: str = job.date_range        # '7d' | '30d' | 'all'
        label_filter: str = job.label_filter or "all"

        # ── 3. Build query ────────────────────────────────────────────────
        now = datetime.now(timezone.utc)
        since: datetime | None = None
        if date_range == "7d":
            since = now - timedelta(days=7)
        elif date_range == "30d":
            since = now - timedelta(days=30)
        # 'all' → no date filter

        # Correlated subquery: most-recent Feedback.label per Email.
        latest_feedback_label = (
            select(Feedback.label)
            .where(Feedback.email_id == Email.id)
            .order_by(Feedback.created_at.desc())
            .limit(1)
            .correlate(Email)
            .scalar_subquery()
        )

        q = (
            select(
                Email.id.label("email_id"),
                Email.sender,
                Email.recipient_address,
                Email.subject,
                Email.received_at,
                Email.status,
                Email.ingestion_source,
                Email.spf,
                Email.dkim,
                Email.dmarc,
                Email.body_text,
                Email.html_sanitised,
                AnalysisResult.classification,
                AnalysisResult.risk_score,
                AnalysisResult.explanation,
                AnalysisResult.model_version,
                latest_feedback_label.label("feedback_label"),
            )
            .outerjoin(AnalysisResult, AnalysisResult.email_id == Email.id)
            .where(Email.org_id == org_id)
        )

        if since is not None:
            q = q.where(Email.received_at >= since)

        if label_filter != "all":
            # Filter on the correlated subquery result — PostgreSQL evaluates
            # this per-row, equivalent to a LATERAL join with a WHERE clause.
            q = q.where(latest_feedback_label == label_filter)

        q = q.order_by(Email.received_at.desc())

        rows = session.execute(q).all()
        record_count = len(rows)

        # ── 4. Create export directory ────────────────────────────────────
        export_dir = os.path.join(settings.EXPORT_VOLUME_PATH, str(org_id))
        os.makedirs(export_dir, exist_ok=True)
        # EML exports produce a ZIP archive; all other formats use their own extension.
        file_ext = "zip" if fmt == "eml" else fmt
        file_path = os.path.join(export_dir, f"{job_id}.{file_ext}")

        # ── 5. Write file ─────────────────────────────────────────────────
        if fmt == "csv":
            with open(file_path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=_EXPORT_FIELDS)
                writer.writeheader()
                for row in rows:
                    writer.writerow(_row_to_dict(row))

        elif fmt == "jsonl":
            with open(file_path, "w", encoding="utf-8") as fh:
                for row in rows:
                    fh.write(json.dumps(_row_to_dict(row), default=str) + "\n")

        elif fmt == "json":
            with open(file_path, "w", encoding="utf-8") as fh:
                json.dump(
                    [_row_to_dict(row) for row in rows],
                    fh,
                    default=str,
                    ensure_ascii=False,
                )

        else:  # eml — ZIP archive of individual .eml files
            with zipfile.ZipFile(file_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for i, row in enumerate(rows):
                    # Build a standards-compliant .eml file for each email record.
                    msg = MIMEMultipart("mixed")

                    # Standard RFC 2822 headers
                    msg["From"]    = str(row.sender or "unknown@unknown.com")
                    msg["To"]      = str(row.recipient_address or "")
                    msg["Subject"] = str(row.subject or "(No Subject)")

                    received_at = row.received_at
                    if received_at is not None:
                        ts = received_at.timestamp() if hasattr(received_at, "timestamp") else None
                        msg["Date"] = formatdate(ts) if ts is not None else str(received_at)
                    else:
                        msg["Date"] = formatdate()

                    # PhishGuard metadata headers — surfaced for re-import and triage.
                    if row.risk_score is not None:
                        msg["X-PhishGuard-Risk-Score"]    = str(row.risk_score)
                    if row.classification:
                        msg["X-PhishGuard-Classification"] = str(row.classification)
                    if row.feedback_label:
                        msg["X-PhishGuard-Label"]          = str(row.feedback_label)

                    # Authentication headers (if stored)
                    if row.spf:
                        msg["X-PhishGuard-SPF"]  = str(row.spf)
                    if row.dkim:
                        msg["X-PhishGuard-DKIM"] = str(row.dkim)
                    if row.dmarc:
                        msg["X-PhishGuard-DMARC"] = str(row.dmarc)

                    # Body parts — prefer plain text; attach sanitised HTML when available.
                    body_text = row.body_text or ""
                    html_body = row.html_sanitised or ""
                    if body_text:
                        msg.attach(MIMEText(body_text, "plain", "utf-8"))
                    if html_body:
                        msg.attach(MIMEText(html_body, "html", "utf-8"))
                    if not body_text and not html_body:
                        # Guarantee at least one body part so the .eml is valid.
                        msg.attach(MIMEText("(No body content)", "plain", "utf-8"))

                    # Build a safe filename: index + truncated subject slug.
                    subject_raw = str(row.subject or "email")[:40]
                    subject_safe = "".join(
                        c for c in subject_raw if c.isalnum() or c in (" ", "-", "_")
                    ).strip() or f"email_{i + 1}"
                    eml_filename = f"{i + 1:04d}_{subject_safe}.eml"

                    zf.writestr(eml_filename, msg.as_string())

        # ── 6. Mark ready ─────────────────────────────────────────────────
        completed_at = datetime.now(timezone.utc)
        session.execute(
            update(ExportJob.__table__)
            .where(ExportJob.__table__.c.id == job_uuid)
            .values(
                status="ready",
                record_count=record_count,
                file_path=file_path,
                completed_at=completed_at,
            )
        )
        session.commit()

        log.info(
            "generate_export_done",
            job_id=job_id,
            org_id=str(org_id),
            format=fmt,
            record_count=record_count,
            file_path=file_path,
        )

    except Exception as exc:
        session.rollback()
        log.error(
            "generate_export_failed",
            job_id=job_id,
            error=str(exc),
            exc_type=type(exc).__name__,
        )

        # ── 7. Cleanup on failure ─────────────────────────────────────────
        # Delete any partially-written file so a corrupt file is never served.
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
                log.info("generate_export_partial_file_deleted", path=file_path)
            except OSError as rm_exc:
                log.warning(
                    "generate_export_cleanup_failed",
                    path=file_path,
                    error=str(rm_exc),
                )

        # Update ExportJob and write audit log in a fresh session so a
        # previous transaction error does not prevent the status update.
        err_session = _make_sync_session()
        try:
            err_session.execute(
                update(ExportJob.__table__)
                .where(ExportJob.__table__.c.id == job_uuid)
                .values(
                    status="failed",
                    error_message=str(exc)[:500],
                    completed_at=datetime.now(timezone.utc),
                )
            )

            # Fetch org_id for the audit log (the job row should still exist).
            org_id_row = err_session.execute(
                select(ExportJob.org_id).where(ExportJob.id == job_uuid)
            ).scalar_one_or_none()

            if org_id_row is not None:
                err_session.add(
                    AuditLog(
                        org_id=org_id_row,
                        action="export_failed",
                        target_type="export_job",
                        target_id=job_uuid,
                        detail={"error": str(exc)[:500]},
                    )
                )

            err_session.commit()
        except Exception as update_exc:
            log.error(
                "generate_export_status_update_failed",
                job_id=job_id,
                error=str(update_exc),
            )
            try:
                err_session.rollback()
            except Exception:
                pass
        finally:
            err_session.close()

    finally:
        session.close()
