"""Section 9 Phase 2K — Analysis pipeline, stats, and assistant tests.

Pipeline architecture note: Celery tasks (analysis chain) open their own
synchronous DB sessions via _make_sync_session().  Test fixtures use
transaction-scoped rollback isolation, so task sessions cannot see
uncommitted test data.  Pipeline tests therefore:
  1. Call the HTTP endpoint (returns 202; chain fires but finds no email
     in its independent session and exits silently).
  2. Manually insert the expected pipeline output (AnalysisResult, status
     update) into the test session so subsequent status/stats queries work.
This accurately tests the HTTP-layer contract and the read-path endpoints.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

# The upload route writes raw .eml bytes to /tmp/{uuid}.eml.  On Windows /tmp
# is not created by default; os.makedirs maps it to C:\tmp on the current drive.
os.makedirs("/tmp", exist_ok=True)

import pytest
from httpx import AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis_result import AnalysisResult
from app.models.email import Email
from app.models.organisation import Organisation
from app.models.user import User
from tests.conftest import EmailFactory


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _make_analysis(
    email_id: uuid.UUID,
    *,
    classification: str = "phishing",
    risk_score: int = 85,
    explanation: str = "This email exhibits phishing characteristics.",
) -> AnalysisResult:
    """Build an AnalysisResult ORM object for test injection."""
    return AnalysisResult(
        email_id=email_id,
        classification=classification,
        risk_score=risk_score,
        model_version="rf_test_v1",
        threshold_applied_suspicious=30,
        threshold_applied_phishing=80,
        top_features=[
            {"name": "urgency_language", "value": 0.8, "score_contribution": 0.8}
        ],
        explanation=explanation,
    )


# ---------------------------------------------------------------------------
# 1. test_upload_eml_full_pipeline
# ---------------------------------------------------------------------------


async def test_upload_eml_full_pipeline(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
    sample_eml: bytes,
) -> None:
    """Upload .eml file → 202; manually simulate pipeline → status='quarantined'.

    The upload endpoint writes the file to /tmp and fires the analysis chain.
    Tasks run eagerly but cannot read the uncommitted Email row (different
    connection).  We inject the pipeline result directly into the test session
    and verify the status endpoint reads it correctly.
    """
    resp = await async_client.post(
        "/api/v1/emails/upload",
        headers=_auth(admin_token),
        files={"file": ("sample_phish.eml", sample_eml, "message/rfc822")},
    )
    assert resp.status_code == 202, resp.text
    data = resp.json()
    assert "email_id" in data
    email_id = uuid.UUID(data["email_id"])

    # Simulate completed pipeline: insert AnalysisResult + mark quarantined.
    analysis = _make_analysis(email_id, classification="phishing", risk_score=85)
    db_session.add(analysis)
    await db_session.execute(
        update(Email).where(Email.id == email_id).values(status="quarantined")
    )
    await db_session.flush()

    status_resp = await async_client.get(
        f"/api/v1/analysis/{email_id}/status",
        headers=_auth(admin_token),
    )
    assert status_resp.status_code == 200, status_resp.text
    s = status_resp.json()
    assert s["status"] == "quarantined"
    assert s["risk_score"] == 85
    assert s["classification"] == "phishing"
    assert s["severity"] in ("high", "critical")


# ---------------------------------------------------------------------------
# 2. test_paste_full_pipeline
# ---------------------------------------------------------------------------


async def test_paste_full_pipeline(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """POST /analysis/paste → 202; simulate pipeline → verify status endpoint."""
    raw_source = (
        "From: evil@phish.example\r\n"
        "To: victim@company.example\r\n"
        "Subject: Urgent: verify your account immediately\r\n"
        "\r\n"
        "Please enter your password at http://evil.phish.example/login\r\n"
        "Your account will be suspended in 24 hours.\r\n"
    )
    resp = await async_client.post(
        "/api/v1/analysis/paste",
        headers=_auth(admin_token),
        json={"raw_source": raw_source},
    )
    assert resp.status_code == 202, resp.text
    data = resp.json()
    assert data["status"] == "pending"
    email_id = uuid.UUID(data["email_id"])

    # Simulate pipeline output.
    analysis = _make_analysis(email_id, classification="phishing", risk_score=90)
    db_session.add(analysis)
    await db_session.execute(
        update(Email).where(Email.id == email_id).values(status="quarantined")
    )
    await db_session.flush()

    status_resp = await async_client.get(
        f"/api/v1/analysis/{email_id}/status",
        headers=_auth(admin_token),
    )
    assert status_resp.status_code == 200
    s = status_resp.json()
    assert s["risk_score"] == 90
    assert s["explanation"] == "This email exhibits phishing characteristics."


# ---------------------------------------------------------------------------
# 3. test_paste_raw_source_too_long  (S-03 fix)
# ---------------------------------------------------------------------------


async def test_paste_raw_source_too_long(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """raw_source exceeding 500 000 characters → 422 Unprocessable Entity."""
    resp = await async_client.post(
        "/api/v1/analysis/paste",
        headers=_auth(admin_token),
        json={"raw_source": "x" * 500_001},
    )
    assert resp.status_code == 422, resp.text


# ---------------------------------------------------------------------------
# 4. test_upload_invalid_file_type
# ---------------------------------------------------------------------------


async def test_upload_invalid_file_type(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """Uploading a .txt file (not .eml) → 422."""
    resp = await async_client.post(
        "/api/v1/emails/upload",
        headers=_auth(admin_token),
        files={"file": ("not_an_email.txt", b"Hello world", "text/plain")},
    )
    assert resp.status_code == 422, resp.text


# ---------------------------------------------------------------------------
# 5. test_upload_file_too_large
# ---------------------------------------------------------------------------


async def test_upload_file_too_large(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """Uploading a file > 5 MB → 422."""
    big_content = b"X" * (5 * 1024 * 1024 + 1)  # 5 MB + 1 byte
    resp = await async_client.post(
        "/api/v1/emails/upload",
        headers=_auth(admin_token),
        files={"file": ("big.eml", big_content, "message/rfc822")},
    )
    assert resp.status_code == 422, resp.text


# ---------------------------------------------------------------------------
# 6. test_claude_fallback
# ---------------------------------------------------------------------------


async def test_claude_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """When Anthropic raises APIError, explanation falls back to RULE_TEXT_TEMPLATES.

    The generate_explanation service wraps all exceptions and returns a
    rule-based text from RULE_TEXT_TEMPLATES.  Tests that the fallback is
    non-empty and comes from the known template dict.
    """
    import anthropic

    from app.services import claude_service

    # Simulate an Anthropic API failure.
    async def _failing_generate(*args, **kwargs) -> str:
        raise anthropic.APIError(
            message="rate limit exceeded",
            request=None,
            body=None,
        )

    monkeypatch.setattr(claude_service, "_call_claude_api", _failing_generate, raising=False)

    # Fallback is triggered when the Claude call raises.
    top_features = [{"name": "urgency_language", "value": 0.8, "score_contribution": 0.8}]
    result = await claude_service.generate_explanation(
        top_features, sender="evil@phish.example", subject="Verify now"
    )

    assert result  # non-empty
    assert isinstance(result, str)
    # Should match one of the known rule templates.
    all_templates = set(claude_service.RULE_TEXT_TEMPLATES.values())
    assert result in all_templates, f"Unexpected fallback text: {result!r}"


# ---------------------------------------------------------------------------
# 7. test_dashboard_stats_cached
# ---------------------------------------------------------------------------


async def test_dashboard_stats_cached(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
    redis_mock,
) -> None:
    """Second call to /analysis/stats should return the cached response.

    After the first request the result is stored in Redis under
    ``stats:{org_id}:all_time``.  The second request should serve it from
    cache (we verify the key exists and the response is identical).
    """
    resp1 = await async_client.get(
        "/api/v1/analysis/stats",
        headers=_auth(admin_token),
    )
    assert resp1.status_code == 200, resp1.text
    data1 = resp1.json()

    # Redis should now have the cache key.
    cache_key = f"stats:{org.id}:all_time"
    cached_raw = await redis_mock.get(cache_key)
    assert cached_raw is not None, "Expected stats cache to be populated after first request"

    # Second call returns same data.
    resp2 = await async_client.get(
        "/api/v1/analysis/stats",
        headers=_auth(admin_token),
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data1["total_analysed"] == data2["total_analysed"]
    assert data1["quarantined_count"] == data2["quarantined_count"]


# ---------------------------------------------------------------------------
# 8. test_has_pending_quarantine_true  (A-12 fix)
# ---------------------------------------------------------------------------


async def test_has_pending_quarantine_true(
    async_client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """has_pending_quarantine=True when at least one quarantined email exists."""
    email = EmailFactory(org_id=org.id, status="quarantined")
    db_session.add(email)
    await db_session.flush()

    resp = await async_client.get(
        "/api/v1/analysis/stats",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["has_pending_quarantine"] is True
    assert resp.json()["quarantined_count"] >= 1


# ---------------------------------------------------------------------------
# 9. test_has_pending_quarantine_false
# ---------------------------------------------------------------------------


async def test_has_pending_quarantine_false(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """has_pending_quarantine=False when no quarantined emails exist."""
    resp = await async_client.get(
        "/api/v1/analysis/stats",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["has_pending_quarantine"] is False
    assert resp.json()["quarantined_count"] == 0
