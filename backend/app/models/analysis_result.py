"""AnalysisResult ORM model (Section 3.5, FR-04)."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AnalysisResult(Base):  # type: ignore[misc]  # SQLAlchemy declarative_base() returns Any
    """ML classification result — 1:1 with emails (FR-04, arch step 4–5).

    D-05 fix: ``threshold_applied_suspicious`` and
    ``threshold_applied_phishing`` are **separate** columns (not a single
    ``threshold_applied`` field).  This preserves a full snapshot of both
    thresholds at the moment of analysis, independent of any future Admin
    changes to org sensitivity settings (UC-04 accuracy requirement).

    Classification boundaries (arch ④ defaults):
        0–29  → safe
        30–79 → suspicious
        80–100 → phishing

    ``model_version`` is stamped from the ``MODEL_VERSION`` env var so
    the arch ⑤ F1 quality gate can track which model produced each result.
    """

    __tablename__ = "analysis_results"
    __table_args__ = (
        UniqueConstraint("email_id", name="uq_analysis_result_email_id"),
        CheckConstraint(
            "classification IN ('safe','suspicious','phishing','failed')",
            name="analysis_result_classification_check",
        ),
        CheckConstraint(
            "risk_score BETWEEN 0 AND 100",
            name="analysis_result_risk_score_range",
        ),
        Index("ix_analysis_result_email_id", "email_id"),
        # Severity sort on dashboard cards
        Index("ix_analysis_result_risk_score", "risk_score"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    # UNIQUE: 1:1 with emails — CASCADE so deleting the email removes this row
    email_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("emails.id", ondelete="CASCADE"),
        nullable=False,
    )
    classification: Mapped[str] = mapped_column(String(20), nullable=False)
    risk_score: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    # e.g. 'rf_v1.0.0' — stamped from MODEL_VERSION env var at analysis time
    model_version: Mapped[str] = mapped_column(String(50), nullable=False)

    # D-05 FIX — two separate snapshot fields, not a single threshold_applied
    threshold_applied_suspicious: Mapped[int] = mapped_column(
        SmallInteger, nullable=False
    )
    threshold_applied_phishing: Mapped[int] = mapped_column(
        SmallInteger, nullable=False
    )

    # Claude API 2–3 sentence explanation or RULE_TEXT_TEMPLATES fallback
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Top 3 [{name, value, score_contribution}] sorted desc — UI Figure 10–11
    top_features: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    quarantined: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    # Unified detection confidence 0-100. Internal only — never labelled as
    # "claude confidence" or "ml confidence" on any user-facing surface.
    detection_confidence: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
