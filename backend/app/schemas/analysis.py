"""Pydantic v2 request/response schemas for routers/analysis.py.

Covers Section 4.3 (FR-03, FR-04, UI Dashboard):
    POST /analysis/paste           — raw source analysis (S-03: max_length=500000)
    GET  /analysis/sample          — load demo .eml for UI 'Load Sample' button
    GET  /analysis/{id}/status     — polling fallback before SSE connects
    GET  /analysis/stats           — dashboard stats (A-09, A-12, A-07 fixes)
    GET  /dashboard/insights       — AI insights panel
    POST /analysis/assistant       — Claude AI assistant streaming chat (UC-10)
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import (
    AssistantRole,
    Classification,
    InsightType,
    Severity,
    StatsPeriod,
)


# ---------------------------------------------------------------------------
# POST /analysis/paste
# ---------------------------------------------------------------------------


class PasteAnalysisRequest(BaseModel):
    """Submit raw email source for analysis via the paste UI (UI Figure 8).

    S-03 fix: raw_source max_length=500_000 to prevent DoS via oversized payloads.
    """

    sender: Optional[str] = Field(default=None, max_length=320)
    subject: Optional[str] = Field(default=None, max_length=998)
    raw_source: str = Field(min_length=1, max_length=500_000)
    add_to_training: bool = False


class PasteAnalysisResponse(BaseModel):
    """202 returned immediately after paste is queued for analysis."""

    email_id: uuid.UUID
    status: str = "pending"


# ---------------------------------------------------------------------------
# GET /analysis/sample
# ---------------------------------------------------------------------------


class SampleEmailResponse(BaseModel):
    """Hardcoded realistic phishing sample for the 'Load Sample' button."""

    sender: str
    subject: str
    raw_source: str


# ---------------------------------------------------------------------------
# GET /analysis/{id}/status  — polling fallback
# ---------------------------------------------------------------------------


class AnalysisStatusResponse(BaseModel):
    """Lightweight status poll — used before SSE connection is established."""

    model_config = ConfigDict(from_attributes=True)

    status: str
    risk_score: Optional[int] = None
    classification: Optional[Classification] = None
    severity: Optional[Severity] = None
    explanation: Optional[str] = None
    detection_confidence: Optional[int] = None


# ---------------------------------------------------------------------------
# GET /analysis/stats  — dashboard statistics cards
# ---------------------------------------------------------------------------


class DetectionDriverItem(BaseModel):
    """One row in the feature-breakdown bar chart (UI Figure 4)."""

    feature_name: str
    count: int
    pct: float


class SeverityDistribution(BaseModel):
    """Percentage breakdown for the severity donut chart."""

    critical_pct: float
    high_pct: float
    medium_pct: float
    low_pct: float


class CurrentThreshold(BaseModel):
    """The org's active detection thresholds — shown in the Stats response."""

    suspicious: int
    phishing: int


class RecentQuarantinedItem(BaseModel):
    """Row in the 'Recent Quarantine' mini-table (A-09 fix: severity + top_reason)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    sender: Optional[str] = None
    subject: Optional[str] = None
    risk_score: Optional[int] = None
    severity: Optional[Severity] = None
    top_reason: Optional[str] = None
    received_at: datetime


class AnalysisStatsResponse(BaseModel):
    """Full dashboard stats payload (UI Figure 4, all cards + charts).

    A-12 fix: has_pending_quarantine drives 'Prepare Digest' button state.
    """

    total_analysed: int
    safe_count: int
    suspicious_count: int
    quarantined_count: int
    feedback_count: int
    current_threshold: CurrentThreshold
    detection_driver_breakdown: list[DetectionDriverItem]
    severity_distribution: SeverityDistribution
    recent_quarantined: list[RecentQuarantinedItem]
    has_pending_quarantine: bool


# ---------------------------------------------------------------------------
# GET /dashboard/insights
# ---------------------------------------------------------------------------


class InsightItem(BaseModel):
    """One insight card returned by the insights panel (UI Figure 4).

    type=alert → shown with warning styling.
    type=info  → informational card (threshold info always included).
    """

    type: InsightType
    title: str
    message: str
    severity: Optional[Severity] = None


# ---------------------------------------------------------------------------
# POST /analysis/assistant  (Claude AI assistant — UC-10, UI Figure 13)
# ---------------------------------------------------------------------------


class AssistantMessage(BaseModel):
    """Single turn in the assistant conversation history."""

    role: AssistantRole
    content: str = Field(min_length=1, max_length=32_000)


class AssistantRequest(BaseModel):
    """Full conversation context sent to the assistant endpoint.

    messages must include the complete history so the backend is stateless.
    local_mode=True forces deterministic LOCAL_ANSWER_MAP responses
    (used when Claude API is unavailable or for demos).

    Rate limit: 30 req/min per user (enforced via slowapi in main.py).
    """

    messages: list[AssistantMessage] = Field(min_length=1, max_length=50)
    local_mode: bool = False
