"""Section 9 Phase 2K — HMAC digest token and action endpoint tests.

Tests cover:
  - sign_digest_token / verify_digest_token round-trip (pure crypto)
  - Tampered HMAC → verify returns False
  - GET /digest/action?action=confirm  → 200 HTML + CSP header
  - GET /digest/action?action=release  → 200 HTML "Email Marked Safe"
  - Tampered token (bad HMAC) → 400
  - Replayed token (action_taken already set) → 410
  - Expired token (token_expires_at in the past) → 410

Architecture note: /digest/action is a PUBLIC endpoint (no Bearer token).
The DigestLog row is created directly in the test session so validate_digest_token
(which uses the same test db_session via get_db override) can find it.
"""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import sign_digest_token, verify_digest_token
from app.models.digest_log import DigestLog
from app.models.organisation import Organisation
from app.models.user import User
from tests.conftest import EmailFactory


def _make_digest_log(
    email_id: uuid.UUID,
    *,
    jti: str,
    action_taken: str | None = None,
    hours_until_expiry: int = 72,
) -> DigestLog:
    """Build a DigestLog ORM object for test injection.

    DigestLog has NO created_at column — only token_expires_at.
    """
    return DigestLog(
        id=uuid.uuid4(),
        email_id=email_id,
        recipient_address="victim@company.example",
        status="pending",
        retry_count=0,
        signed_token_jti=jti,
        token_expires_at=datetime.now(timezone.utc) + timedelta(hours=hours_until_expiry),
        action_taken=action_taken,
    )


# ---------------------------------------------------------------------------
# 1. test_sign_verify_roundtrip
# ---------------------------------------------------------------------------


def test_sign_verify_roundtrip() -> None:
    """sign_digest_token + verify_digest_token with the same inputs → True."""
    email_id = str(uuid.uuid4())
    jti = secrets.token_urlsafe(32)
    hmac_hex = sign_digest_token(email_id, jti)
    assert verify_digest_token(token=hmac_hex, email_id=email_id, jti=jti) is True


# ---------------------------------------------------------------------------
# 2. test_verify_tampered_token_fails
# ---------------------------------------------------------------------------


def test_verify_tampered_token_fails() -> None:
    """Incorrect HMAC → verify_digest_token returns False (timing-safe comparison)."""
    email_id = str(uuid.uuid4())
    jti = secrets.token_urlsafe(32)
    tampered = "0" * 64  # wrong 64-char hex, same length as SHA-256 output
    assert verify_digest_token(token=tampered, email_id=email_id, jti=jti) is False


# ---------------------------------------------------------------------------
# 3. test_digest_action_confirm
# ---------------------------------------------------------------------------


async def test_digest_action_confirm(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """Valid confirm token → 200 HTML 'Phishing Confirmed' + CSP header (S-05 fix)."""
    email = EmailFactory(org_id=org.id, status="quarantined")
    db_session.add(email)
    await db_session.flush()

    jti = secrets.token_urlsafe(32)
    hmac_hex = sign_digest_token(str(email.id), jti)
    signed_token = f"{email.id}:{jti}:{hmac_hex}"

    digest_log = _make_digest_log(email.id, jti=jti)
    db_session.add(digest_log)
    await db_session.flush()

    resp = await async_client.get(
        "/api/v1/digest/action",
        params={"token": signed_token, "action": "confirm"},
    )
    assert resp.status_code == 200, resp.text
    assert "text/html" in resp.headers["content-type"]
    # CSP may be set by both the route handler and a middleware; assert the
    # required directive is present rather than doing an exact equality check.
    csp = resp.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp
    assert "Phishing Confirmed" in resp.text


# ---------------------------------------------------------------------------
# 4. test_digest_action_release
# ---------------------------------------------------------------------------


async def test_digest_action_release(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """Valid release token → 200 HTML 'Email Marked Safe'."""
    email = EmailFactory(org_id=org.id, status="quarantined")
    db_session.add(email)
    await db_session.flush()

    jti = secrets.token_urlsafe(32)
    hmac_hex = sign_digest_token(str(email.id), jti)
    signed_token = f"{email.id}:{jti}:{hmac_hex}"

    digest_log = _make_digest_log(email.id, jti=jti)
    db_session.add(digest_log)
    await db_session.flush()

    resp = await async_client.get(
        "/api/v1/digest/action",
        params={"token": signed_token, "action": "release"},
    )
    assert resp.status_code == 200, resp.text
    assert "Email Marked Safe" in resp.text


# ---------------------------------------------------------------------------
# 5. test_digest_action_tampered_token_400
# ---------------------------------------------------------------------------


async def test_digest_action_tampered_token_400(
    async_client: AsyncClient,
    org: Organisation,
    admin_user: User,
) -> None:
    """Tampered HMAC in token → 400 Bad Request (HMAC verify fails before DB query)."""
    email_id = uuid.uuid4()
    jti = secrets.token_urlsafe(32)
    bad_hmac = "0" * 64  # 64 hex chars of zeros
    bad_token = f"{email_id}:{jti}:{bad_hmac}"

    resp = await async_client.get(
        "/api/v1/digest/action",
        params={"token": bad_token, "action": "confirm"},
    )
    assert resp.status_code == 400, resp.text


# ---------------------------------------------------------------------------
# 6. test_digest_action_replay_410
# ---------------------------------------------------------------------------


async def test_digest_action_replay_410(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """DigestLog.action_taken already set → 410 Gone (replay guard)."""
    email = EmailFactory(org_id=org.id, status="quarantined")
    db_session.add(email)
    await db_session.flush()

    jti = secrets.token_urlsafe(32)
    hmac_hex = sign_digest_token(str(email.id), jti)
    signed_token = f"{email.id}:{jti}:{hmac_hex}"

    # Mark digest as already consumed by a previous click.
    digest_log = _make_digest_log(
        email.id, jti=jti, action_taken="confirmed_phishing"
    )
    db_session.add(digest_log)
    await db_session.flush()

    resp = await async_client.get(
        "/api/v1/digest/action",
        params={"token": signed_token, "action": "confirm"},
    )
    assert resp.status_code == 410, resp.text


# ---------------------------------------------------------------------------
# 7. test_digest_action_expired_410
# ---------------------------------------------------------------------------


async def test_digest_action_expired_410(
    async_client: AsyncClient,
    db_session: AsyncSession,
    org: Organisation,
    admin_user: User,
) -> None:
    """token_expires_at in the past → 410 Gone (72-hour expiry)."""
    email = EmailFactory(org_id=org.id, status="quarantined")
    db_session.add(email)
    await db_session.flush()

    jti = secrets.token_urlsafe(32)
    hmac_hex = sign_digest_token(str(email.id), jti)
    signed_token = f"{email.id}:{jti}:{hmac_hex}"

    # Token expired 1 hour ago.
    digest_log = _make_digest_log(email.id, jti=jti, hours_until_expiry=-1)
    db_session.add(digest_log)
    await db_session.flush()

    resp = await async_client.get(
        "/api/v1/digest/action",
        params={"token": signed_token, "action": "confirm"},
    )
    assert resp.status_code == 410, resp.text
