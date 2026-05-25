"""Shared enums, pagination helpers, and base response wrapper used across schemas.

All enums mirror the CHECK constraint values defined in Section 3 of the plan.
Pagination follows the {items, total, page, pages} contract from Section 4.
"""
from __future__ import annotations

import math
from enum import Enum
from typing import Any, Generic, Optional, TypeVar

from pydantic import BaseModel, ConfigDict

# ---------------------------------------------------------------------------
# Enums — values must exactly match DB CHECK constraints (Section 3)
# ---------------------------------------------------------------------------


class UserRole(str, Enum):
    """roles allowed in users.role CHECK."""

    admin = "admin"
    analyst = "analyst"


class EmailStatus(str, Enum):
    """emails.status CHECK values (state-machine transitions)."""

    pending = "pending"
    delivered = "delivered"
    flagged = "flagged"
    quarantined = "quarantined"
    confirmed_phishing = "confirmed_phishing"
    failed = "failed"


class IngestionSource(str, Enum):
    """emails.ingestion_source CHECK values."""

    imap = "imap"
    upload = "upload"
    paste = "paste"


class Classification(str, Enum):
    """analysis_results.classification CHECK values."""

    safe = "safe"
    suspicious = "suspicious"
    phishing = "phishing"
    unknown = "unknown"


class Severity(str, Enum):
    """Computed severity band (not a DB column — derived at classify time)."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class FeedbackLabel(str, Enum):
    """feedback.label CHECK values."""

    phishing = "phishing"
    safe = "safe"
    needs_investigation = "needs_investigation"


class FeedbackSource(str, Enum):
    """feedback.source CHECK values."""

    dashboard = "dashboard"
    digest_link = "digest_link"
    api = "api"


class ConnectorStatus(str, Enum):
    """organisations.connector_status CHECK values."""

    unconfigured = "unconfigured"
    active = "active"
    error = "error"


class DigestAction(str, Enum):
    """digest_log.action_taken CHECK values (used in GET /digest/action)."""

    confirmed_phishing = "confirmed_phishing"
    marked_safe = "marked_safe"


class ExportFormat(str, Enum):
    """export_jobs.format CHECK values."""

    csv = "csv"
    json = "json"
    jsonl = "jsonl"


class ExportDateRange(str, Enum):
    """export_jobs.date_range CHECK values (A-04 fix)."""

    days_7 = "7d"
    days_30 = "30d"
    all = "all"


class ExportStatus(str, Enum):
    """export_jobs.status CHECK values."""

    pending = "pending"
    generating = "generating"
    ready = "ready"
    failed = "failed"


class LabelFilter(str, Enum):
    """Filter for export label_filter param (superset of FeedbackLabel)."""

    all = "all"
    phishing = "phishing"
    safe = "safe"
    needs_investigation = "needs_investigation"


class RiskBand(str, Enum):
    """risk_band query param — maps to score ranges (A-07 fix).

    Ranges (inclusive):
        critical  90–100
        high      80–89
        medium    30–79
        low       0–29
    """

    all = "all"
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class StatsPeriod(str, Enum):
    """period param for GET /analysis/stats."""

    this_week = "this_week"
    days_30 = "30d"
    all_time = "all_time"


class FeedbackState(str, Enum):
    """Quarantine list feedback_state filter values."""

    none = "none"
    confirmed = "confirmed"
    released = "released"
    investigating = "investigating"


class InsightType(str, Enum):
    """Type discriminator for GET /dashboard/insights items."""

    alert = "alert"
    info = "info"


class SortDir(str, Enum):
    """Generic sort direction for paginated endpoints."""

    asc = "asc"
    desc = "desc"


class AssistantRole(str, Enum):
    """Role values for assistant conversation messages (Section 4.5)."""

    user = "user"
    assistant = "assistant"


# ---------------------------------------------------------------------------
# Error response envelope
# ---------------------------------------------------------------------------


class ErrorResponse(BaseModel):
    """Standard JSON error body returned on 4xx/5xx responses.

    Registered as a response model on all routes so OpenAPI documents the
    shape.  FastAPI exception handlers populate this via JSONResponse.

    Attributes:
        code:    Machine-readable error code, e.g. ``VALIDATION_ERROR``,
                 ``NOT_FOUND``, ``RATE_LIMIT_EXCEEDED``.
        message: Human-readable description suitable for display.
        details: Optional structured payload — field-level validation errors
                 from Pydantic, or additional context from the handler.
    """

    code: str
    message: str
    details: Optional[Any] = None


# ---------------------------------------------------------------------------
# Generic paginated response
# ---------------------------------------------------------------------------

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    """Generic paginated list envelope used by multiple endpoints.

    Section 4 contract: {items, total, page, pages}
    """

    model_config = ConfigDict(from_attributes=True)

    items: list[T]
    total: int
    page: int
    pages: int

    @classmethod
    def build(cls, items: list[T], total: int, page: int, page_size: int) -> "Page[T]":
        """Convenience constructor — computes ``pages`` from total + page_size."""
        pages = max(1, math.ceil(total / page_size)) if page_size > 0 else 1
        return cls(items=items, total=total, page=page, pages=pages)


# Alias so callers may use either name interchangeably.
PaginatedResponse = Page
