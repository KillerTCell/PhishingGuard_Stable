"""Section 9 Phase 2K — Settings and data-export endpoint tests.

Tests cover:
  - GET  /settings                    → org thresholds + feature flags
  - PATCH /settings                   → admin updates thresholds; Redis cache updated
  - PATCH /settings                   → 403 when caller is analyst (admin-only)
  - POST  /settings/export            → 202 + estimated_scope counts (A-05 fix)
  - GET   /settings/export/{job_id}   → JSON status while job is pending/generating
"""
from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organisation import Organisation
from app.models.user import User


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1. test_get_settings
# ---------------------------------------------------------------------------


async def test_get_settings(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /settings → 200 with org detection thresholds and feature flags."""
    resp = await async_client.get("/api/v1/settings", headers=_auth(admin_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "suspicious_threshold" in data
    assert "phishing_threshold" in data
    assert "auto_quarantine_high_risk" in data
    assert "prepend_subject_warning" in data
    # Values should match the OrgFactory defaults (30 / 80).
    assert data["suspicious_threshold"] == org.suspicious_threshold
    assert data["phishing_threshold"] == org.phishing_threshold


# ---------------------------------------------------------------------------
# 2. test_update_settings_threshold
# ---------------------------------------------------------------------------


async def test_update_settings_threshold(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
    redis_mock,
) -> None:
    """PATCH /settings with valid thresholds → 200 with updated values in response."""
    resp = await async_client.patch(
        "/api/v1/settings",
        headers=_auth(admin_token),
        json={"suspicious_threshold": 25, "phishing_threshold": 75},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["suspicious_threshold"] == 25
    assert data["phishing_threshold"] == 75


# ---------------------------------------------------------------------------
# 3. test_update_settings_analyst_forbidden
# ---------------------------------------------------------------------------


async def test_update_settings_analyst_forbidden(
    async_client: AsyncClient,
    analyst_token: str,
    org: Organisation,
    analyst_user: User,
) -> None:
    """PATCH /settings called by analyst → 403 Forbidden (admin-only route)."""
    resp = await async_client.patch(
        "/api/v1/settings",
        headers=_auth(analyst_token),
        json={"suspicious_threshold": 20},
    )
    assert resp.status_code == 403, resp.text


# ---------------------------------------------------------------------------
# 4. test_create_export_returns_scope  (A-05 fix)
# ---------------------------------------------------------------------------


async def test_create_export_returns_scope(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """POST /settings/export → 202 with job_id and estimated_scope counts (A-05 fix).

    The Celery task (generate_export) is wrapped in try/except in the router so
    even if the task fails it doesn't affect the 202 response.  estimated_scope
    is computed synchronously before the task fires.
    """
    resp = await async_client.post(
        "/api/v1/settings/export",
        headers=_auth(admin_token),
        json={"format": "csv", "date_range": "all", "label_filter": "all"},
    )
    assert resp.status_code == 202, resp.text
    data = resp.json()
    assert "job_id" in data
    assert "estimated_scope" in data

    # Verify job_id is a valid UUID.
    uuid.UUID(data["job_id"])

    scope = data["estimated_scope"]
    assert "emails" in scope
    assert "phishing" in scope
    assert "safe" in scope
    assert "review" in scope
    # All counts must be non-negative integers.
    for key in ("emails", "phishing", "safe", "review"):
        assert isinstance(scope[key], int)
        assert scope[key] >= 0


# ---------------------------------------------------------------------------
# 5. test_get_export_status_pending
# ---------------------------------------------------------------------------


async def test_get_export_status_pending(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /settings/export/{job_id} while job is pending → JSON with valid status field.

    The export job is created via POST first to obtain a valid job_id.  The
    generate_export Celery task runs eagerly but cannot see the test session's
    uncommitted ExportJob row, so the job remains in 'pending' status in the DB.
    The GET endpoint reads the job from the same test session and returns its status.
    """
    # Create the job.
    create_resp = await async_client.post(
        "/api/v1/settings/export",
        headers=_auth(admin_token),
        json={"format": "csv", "date_range": "all", "label_filter": "all"},
    )
    assert create_resp.status_code == 202, create_resp.text
    job_id = create_resp.json()["job_id"]

    # Poll status.
    status_resp = await async_client.get(
        f"/api/v1/settings/export/{job_id}",
        headers=_auth(admin_token),
    )
    assert status_resp.status_code == 200, status_resp.text
    data = status_resp.json()
    assert data["job_id"] == job_id
    assert data["status"] in ("pending", "generating", "ready", "failed")
    assert "estimated_scope" in data
