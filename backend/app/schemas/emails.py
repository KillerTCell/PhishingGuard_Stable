"""Pydantic v2 request/response schemas for routers/emails.py.

Covers Section 4.2 (FR-02, UC-02, UC-03):
    POST /emails/upload        — multipart upload
    GET  /emails               — paginated list with risk_band filter (A-07)
    GET  /emails/{id}          — full detail with features
    DELETE /emails/{id}        — hard delete (admin only)
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import (
    Classification,
    EmailStatus,
    IngestionSource,
    RiskBand,
    Severity,
    SortDir,
)


# ---------------------------------------------------------------------------
# POST /emails/upload
# ---------------------------------------------------------------------------


class EmailUploadResponse(BaseModel):
    """202 returned immediately after a single .eml ingestion is queued (legacy)."""

    email_id: uuid.UUID
    status: str = "pending"


class BulkUploadItem(BaseModel):
    """One successfully queued email within a bulk upload response."""

    email_id: uuid.UUID
    filename: str
    status: str = "pending"


class BulkUploadError(BaseModel):
    """One file that was skipped during a bulk upload (validation failure)."""

    filename: str
    error: str


class BulkUploadResponse(BaseModel):
    """202 returned after POST /emails/upload with multiple files."""

    queued: list[BulkUploadItem] = []
    errors: list[BulkUploadError] = []
    total_queued: int = 0
    total_errors: int = 0


# ---------------------------------------------------------------------------
# GET /emails  — query params  (passed as FastAPI Query, not a BaseModel)
# ---------------------------------------------------------------------------

# Query params are declared inline on the route function; documented here
# as a dataclass-style reference so the plan mapping is explicit:
#
#   page:       int = 1
#   page_size:  int = 20
#   status:     Optional[EmailStatus] = None
#   risk_band:  RiskBand = RiskBand.all
#   search:     Optional[str] = None          (matches sender OR subject)
#   sort_by:    Literal["received_at","risk_score"] = "received_at"
#   sort_dir:   SortDir = SortDir.desc


# ---------------------------------------------------------------------------
# Shared sub-schemas used by list and detail responses
# ---------------------------------------------------------------------------


class LinkDetail(BaseModel):
    """One extracted hyperlink from the email body (JSONB element)."""

    displayed_text: str
    actual_href: str
    is_mismatch: bool


class AttachmentMetadata(BaseModel):
    """Attachment record stored in JSONB — no binary content (data minimisation)."""

    filename: str
    size: int
    mime_type: str


class EmailFeatureDetail(BaseModel):
    """Single NLP/ML feature with its score contribution."""

    model_config = ConfigDict(from_attributes=True)

    name: str
    value: float
    score_contribution: float


class FeedbackEntry(BaseModel):
    """One contributor opinion attached to an email (joined from feedback + users).

    Only feedback rows from the contributor review flow (detail.source ==
    'contributor_review') or rows carrying a comment are returned.
    """

    id: uuid.UUID
    label: str
    comment: Optional[str] = None
    user_name: str
    created_at: datetime


# ---------------------------------------------------------------------------
# GET /emails  — list item
# ---------------------------------------------------------------------------


class EmailListItem(BaseModel):
    """Compact row returned by the paginated email list (UI Figure 5)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    sender: Optional[str] = None
    subject: Optional[str] = None
    risk_score: Optional[int] = None
    severity: Optional[Severity] = None
    status: EmailStatus
    classification: Optional[Classification] = None
    top_reason: Optional[str] = None
    received_at: datetime


class EmailListResponse(BaseModel):
    """Paginated email list envelope."""

    items: list[EmailListItem]
    total: int
    page: int
    pages: int


# ---------------------------------------------------------------------------
# GET /emails/{id}  — full detail
# ---------------------------------------------------------------------------


class EmailDetail(BaseModel):
    """Complete email detail used by the email viewer and quarantine detail view.

    JOIN across emails + analysis_results + email_features.

    protected_namespaces=() silences the Pydantic warning for the
    model_version field which starts with the reserved model_ prefix.
    """

    model_config = ConfigDict(from_attributes=True, protected_namespaces=())

    id: uuid.UUID
    sender: Optional[str] = None
    reply_to: Optional[str] = None
    recipient_address: Optional[str] = None
    subject: Optional[str] = None
    received_at: datetime
    ingestion_source: IngestionSource
    status: EmailStatus

    # Body
    body_text: Optional[str] = None
    html_sanitised: Optional[str] = None

    # Extracted link and attachment data
    links: list[LinkDetail] = Field(default_factory=list)
    attachment_metadata: list[AttachmentMetadata] = Field(default_factory=list)

    # Authentication headers
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None

    # Analysis results (None while status==pending)
    risk_score: Optional[int] = None
    classification: Optional[Classification] = None
    severity: Optional[Severity] = None
    explanation: Optional[str] = None
    top_features: list[EmailFeatureDetail] = Field(default_factory=list)
    model_version: Optional[str] = None
    detection_confidence: Optional[int] = None

    # Lifecycle flags
    quarantined: bool = False
    added_to_training: bool = False

    # Contributor opinions (Change 4 — owner review summary)
    feedback: list[FeedbackEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# POST /emails/{id}/request-help
# ---------------------------------------------------------------------------


class HelpRequestBody(BaseModel):
    """Owner/contributor asks other workspace members to review an email."""

    user_ids: list[uuid.UUID] = Field(..., min_length=1, max_length=20)
    note: Optional[str] = Field(None, max_length=500)


class HelpRequestResponse(BaseModel):
    """202 returned after help-request notifications are dispatched."""

    notified: int
    skipped: int
