"""Section 9 Phase 2K — Forwarding inbox and configuration endpoint tests.

Tests cover:
  - GET  /forwarding              → forwarding_address + connector_status + setup steps
  - PATCH /forwarding/config      → saves IMAP creds, tests connection (mocked), returns status
  - PATCH /forwarding/config      → 403 when caller is analyst (admin-only)
  - POST  /forwarding/test        → 202 + test_job_id (P-04 fix: non-blocking)

The IMAP connection test (test_imap_connection) is a synchronous function run
in a thread executor by the route handler.  It is monkeypatched in tests so no
real TCP connection is attempted.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.models.organisation import Organisation
from app.models.user import User
from app.services import forwarding_service


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1. test_get_forwarding_status
# ---------------------------------------------------------------------------


async def test_get_forwarding_status(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """GET /forwarding → 200 with forwarding_address, connector_status and 4 setup steps."""
    resp = await async_client.get("/api/v1/forwarding", headers=_auth(admin_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "forwarding_address" in data
    assert "connector_status" in data
    assert "setup_instructions" in data
    assert isinstance(data["setup_instructions"], list)
    assert len(data["setup_instructions"]) == 4
    # Verify step numbers are sequential.
    steps = [s["step"] for s in data["setup_instructions"]]
    assert steps == [1, 2, 3, 4]


# ---------------------------------------------------------------------------
# 2. test_forwarding_config_update_success
# ---------------------------------------------------------------------------


async def test_forwarding_config_update_success(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PATCH /forwarding/config → 200, connector_status='active' when IMAP test passes.

    forwarding_service.test_imap_connection is monkeypatched to return True so
    no real TCP/IMAP handshake is attempted during the test.
    """
    monkeypatch.setattr(
        forwarding_service, "test_imap_connection", lambda *_args: True
    )

    resp = await async_client.patch(
        "/api/v1/forwarding/config",
        headers=_auth(admin_token),
        json={
            "imap_host": "imap.example.com",
            "imap_port": 993,
            "imap_user": "testuser@example.com",
            "imap_password": "SuperSecret123!",
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["connector_status"] == "active"


# ---------------------------------------------------------------------------
# 3. test_forwarding_config_analyst_forbidden
# ---------------------------------------------------------------------------


async def test_forwarding_config_analyst_forbidden(
    async_client: AsyncClient,
    analyst_token: str,
    org: Organisation,
    analyst_user: User,
) -> None:
    """PATCH /forwarding/config called by analyst → 403 Forbidden (admin-only route)."""
    resp = await async_client.patch(
        "/api/v1/forwarding/config",
        headers=_auth(analyst_token),
        json={
            "imap_host": "imap.example.com",
            "imap_port": 993,
            "imap_user": "user@example.com",
            "imap_password": "secret",
        },
    )
    assert resp.status_code == 403, resp.text


# ---------------------------------------------------------------------------
# 4. test_forwarding_test_returns_202
# ---------------------------------------------------------------------------


async def test_forwarding_test_returns_202(
    async_client: AsyncClient,
    admin_token: str,
    org: Organisation,
    admin_user: User,
) -> None:
    """POST /forwarding/test → 202 with test_job_id and message (P-04 non-blocking fix).

    The forwarding_test Celery task is dispatched asynchronously (wrapped in
    try/except in the router), so even if the task cannot find the org in its
    own psycopg2 session the endpoint still returns 202 immediately.
    """
    resp = await async_client.post(
        "/api/v1/forwarding/test",
        headers=_auth(admin_token),
    )
    assert resp.status_code == 202, resp.text
    data = resp.json()
    assert "test_job_id" in data
    assert "message" in data
    assert isinstance(data["message"], str)
