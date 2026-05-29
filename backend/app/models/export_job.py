"""ExportJob ORM model (Section 3.11, UC-06) — D-10 fix."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ExportJob(Base):  # type: ignore[misc]  # SQLAlchemy declarative_base() returns Any
    """Persistent export job record — powers the 'Recent exports' UI (D-10 fix).

    D-10: prior plan used ephemeral Redis-only tracking, so completed
    exports disappeared on Redis flush.  This table replaces that with
    durable records shown in UI Figure 16 'Recent exports audit table'.

    The export CSV / JSON / JSONL file is written to the Docker bind-mounted
    volume at ``/mnt/exports/{org_id}/{id}.{format}`` by the
    ``generate_export`` Celery task (P-05 fix).  The file path is stored
    in ``file_path`` and served via nginx X-Accel-Redirect on
    ``GET /settings/export/{id}`` (FileResponse — A-02 fix).

    ``date_range`` uses an enum string (A-04 fix): '7d' | '30d' | 'all'
    instead of raw date values because the UI shows named options
    (Last 7 days / Last 30 days / All available data).

    ``estimated_scope_*`` fields are pre-computed counts returned in the
    POST /settings/export response body (A-05 fix, UI Estimated scope card).
    """

    __tablename__ = "export_jobs"
    __table_args__ = (
        CheckConstraint(
            "format IN ('csv','json','jsonl','eml')",
            name="export_job_format_check",
        ),
        CheckConstraint(
            "date_range IN ('7d','30d','all')",
            name="export_job_date_range_check",
        ),
        CheckConstraint(
            "status IN ('pending','generating','ready','failed')",
            name="export_job_status_check",
        ),
        CheckConstraint(
            "label_filter IN ('all','phishing','safe','needs_investigation')",
            name="export_job_label_filter_check",
        ),
        # Recent exports table — primary access pattern
        Index("ix_export_job_org_created", "org_id", "created_at"),
        # Celery task polling for pending jobs
        Index("ix_export_job_status", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organisations.id"),
        nullable=False,
    )
    requested_by_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
    )

    # ── Export configuration ─────────────────────────────────────────────
    format: Mapped[str] = mapped_column(String(10), nullable=False)
    # A-04 FIX: enum string, not raw dates (UI shows named options)
    date_range: Mapped[str] = mapped_column(String(5), nullable=False)
    # NULL label_filter means 'all'
    label_filter: Mapped[str | None] = mapped_column(String(25), nullable=True)

    # ── Job lifecycle ────────────────────────────────────────────────────
    status: Mapped[str] = mapped_column(
        String(15), nullable=False, server_default="pending"
    )
    # Records in the completed export — NULL until ready
    record_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ── A-05 FIX — Estimated scope counts (UI Estimated scope card) ──────
    estimated_scope_emails: Mapped[int | None] = mapped_column(Integer, nullable=True)
    estimated_scope_phishing: Mapped[int | None] = mapped_column(Integer, nullable=True)
    estimated_scope_safe: Mapped[int | None] = mapped_column(Integer, nullable=True)
    estimated_scope_review: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ── Output ──────────────────────────────────────────────────────────
    # /mnt/exports/{org_id}/{id}.{format} on the Docker bind-mounted volume
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # Populated if status=failed; no partial file is retained (UC-06 alt flow)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    # NULL until status = 'ready' or 'failed'
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
