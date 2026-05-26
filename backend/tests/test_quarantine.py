"""Section 9 Phase 2K — Quarantine queue and action endpoint tests.

Tests cover:
  - GET  /quarantine            paginated list with A-06 total_count field
  - GET  /quarantine/{id}       detail + 404 for missing email
  - POST /quarantine/{id}/confirm       → confirmed_phishing + Feedback row
  - POST /quarantine/{id}/release       → delivered + safe Feedback row
  - POST /quarantine/{id}/investigate   → quarantined (unchanged) + Feedback row
  - POST /quarantine/{id}/send-digest   → 422 when recipient_address missing
  - POST /quarantine/{id}/send-digest   → 202 + digest_log_id when recipient set
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis_result import AnalysisResult
from app.models.email import Email
from app.models.feedback import Feedback
from app.models.organisation import Organisation
from app.models.user import User
from tests.conftest import EmailFactory


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _quarantined_email(org_id: uuid.UUID, *, recipient_address: str | None = None) -> Email:
    """Build a quarantined Email ORM object for test injection."""
    email = EmailFactory(org_id=org_id, status="quarantined")
    if recipient_address is not None:
        email.recipient_address = recipient_address
    return email


def _make_analysis(email_id: uuid.UUID) -> AnalysisResult:
    """Build a minimal AnalysisResult for a quarantined email."""
    return AnalysisResult(
        email_id=email_id,
        classification="phishing",
        risk_score=88,
        model_version="rf_test_v1",
        threshold_applied_suspicious=30,
        threshold_applied_phishing=80,
        top_features=[{"name": "urgency_language", "value": 0.9, "score_contribution": 0.9}],
        explanation="Urgency language and credential request patterns detected.",
    )


# ---------------------------------------------------------------------------
# 1. test_quarantine_list_empty
# ---------------------------------------------------------------------------


async def test_quarantine_list_empty(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /quarantine with no quarantined emails → empty items list, total_count=0."""
    resp = await async_client.get("/api/v1/quarantine", headers=_auth(admin_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["total_count"] == 0
    assert data["items"] == []
    assert data["page"] == 1
    assert data["pages"] >= 1


# ---------------------------------------------------------------------------
# 2. test_quarantine_list_total_count  (A-06 fix)
# ---------------------------------------------------------------------------


async def test_quarantine_list_total_count(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """total_count equals quarantined email count and items are returned (A-06 fix)."""
    e1 = _quarantined_email(org.id)
    e2 = _quarantined_email(org.id)
    db_session.add(e1)
    db_session.add(e2)
    await db_session.flush()

    resp = await async_client.get("/api/v1/quarantine", headers=_auth(admin_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "total_count" in data
    assert data["total_count"] >= 2
    assert len(data["items"]) >= 2


# ---------------------------------------------------------------------------
# 3. test_quarantine_detail_404
# ---------------------------------------------------------------------------


async def test_quarantine_detail_404(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /quarantine/{id} for non-existent email → 404 Not Found."""
    resp = await async_client.get(
        f"/api/v1/quarantine/{uuid.uuid4()}",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 404, resp.text


# ---------------------------------------------------------------------------
# 4. test_confirm_phishing
# ---------------------------------------------------------------------------


async def test_confirm_phishing(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """POST /quarantine/{id}/confirm → status='confirmed_phishing'; Feedback label='phishing'."""
    email = _quarantined_email(org.id)
    db_session.add(email)
    await db_session.flush()

    resp = await async_client.post(
        f"/api/v1/quarantine/{email.id}/confirm",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "confirmed_phishing"

    # Verify feedback row is visible in the test session.
    feedback = (
        await db_session.execute(
            select(Feedback).where(
                Feedback.email_id == email.id,
                Feedback.label == "phishing",
            )
        )
    ).scalar_one_or_none()
    assert feedback is not None


# ---------------------------------------------------------------------------
# 5. test_release_email
# ---------------------------------------------------------------------------


async def test_release_email(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """POST /quarantine/{id}/release → status='delivered'; Feedback label='safe'."""
    email = _quarantined_email(org.id)
    db_session.add(email)
    await db_session.flush()

    resp = await async_client.post(
        f"/api/v1/quarantine/{email.id}/release",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "delivered"

    feedback = (
        await db_session.execute(
            select(Feedback).where(
                Feedback.email_id == email.id,
                Feedback.label == "safe",
            )
        )
    ).scalar_one_or_none()
    assert feedback is not None


# ---------------------------------------------------------------------------
# 6. test_investigate_email
# ---------------------------------------------------------------------------


async def test_investigate_email(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """POST /quarantine/{id}/investigate → status stays 'quarantined'; Feedback label='needs_investigation'."""
    email = _quarantined_email(org.id)
    db_session.add(email)
    await db_session.flush()

    resp = await async_client.post(
        f"/api/v1/quarantine/{email.id}/investigate",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "quarantined"

    feedback = (
        await db_session.execute(
            select(Feedback).where(
                Feedback.email_id == email.id,
                Feedback.label == "needs_investigation",
            )
        )
    ).scalar_one_or_none()
    assert feedback is not None


# ---------------------------------------------------------------------------
# 7. test_send_digest_no_recipient_422
# ---------------------------------------------------------------------------


async def test_send_digest_no_recipient_422(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """POST /quarantine/{id}/send-digest with no recipient_address → 422."""
    # EmailFactory sets recipient_address=None by default.
    email = _quarantined_email(org.id, recipient_address=None)
    db_session.add(email)
    await db_session.flush()

    resp = await async_client.post(
        f"/api/v1/quarantine/{email.id}/send-digest",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 422, resp.text


# ---------------------------------------------------------------------------
# 8. test_send_digest_returns_202
# ---------------------------------------------------------------------------


async def test_send_digest_returns_202(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """POST /quarantine/{id}/send-digest with recipient → 202 + valid digest_log_id.

    The Celery task (task_always_eager=True) runs synchronously but opens its
    own psycopg2 session and cannot see the uncommitted test email row.  It
    returns early silently; the route still returns 202 with a pre-generated
    digest_log_id.
    """
    email = _quarantined_email(org.id, recipient_address="victim@company.example")
    db_session.add(email)
    await db_session.flush()

    resp = await async_client.post(
        f"/api/v1/quarantine/{email.id}/send-digest",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 202, resp.text
    data = resp.json()
    assert "digest_log_id" in data
    # Verify the returned ID is a valid UUID.
    uuid.UUID(data["digest_log_id"])
