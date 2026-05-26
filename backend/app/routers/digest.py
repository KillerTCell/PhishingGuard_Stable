"""Section 4.7 -- Digest action link: GET /digest/action

Public endpoint with HMAC-signed token.  Returns HTML confirmation page.
CSP header applied by CSPMiddleware in main.py (S-05 fix).
"""
from __future__ import annotations

from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import DigestTokenInfo, get_db, validate_digest_token
from app.models.digest_log import DigestLog
from app.models.feedback import Feedback

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["digest"])


def _html_page(title: str, message: str, is_error: bool = False) -> str:
    """Build a minimal semantic HTML page (NFR-5: WCAG 2.1 AA contrast)."""
    colour = "#c0392b" if is_error else "#27ae60"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title} — PhishGuard</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 600px; margin: 60px auto;
            padding: 0 24px; color: #222; background: #f9f9f9; }}
    h1 {{ color: {colour}; font-size: 1.5rem; }}
    p {{ line-height: 1.6; }}
    .badge {{ display: inline-block; padding: 6px 14px; border-radius: 4px;
              background: {colour}; color: #fff; font-weight: 600; margin-top: 12px; }}
  </style>
</head>
<body>
  <h1>{title}</h1>
  <p>{message}</p>
  <p>You may close this window.</p>
</body>
</html>"""


@router.get(
    "/digest/action",
    response_class=HTMLResponse,
    summary="Recipient digest action link (public, HMAC-signed)",
    responses={
        200: {"description": "HTML confirmation or error page"},
        400: {"description": "Tampered token"},
        410: {"description": "Replayed or expired token"},
    },
)
async def digest_action(
    token_info: DigestTokenInfo = Depends(validate_digest_token),
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    """Handle a recipient clicking 'Confirm phishing' or 'Mark safe' in the digest email.

    validate_digest_token() (in dependencies.py) handles:
      - HMAC verification (400 on failure)
      - 72-hour expiry (410)
      - Replay guard via action_taken (410)

    On success:
      - INSERT feedback(label, source='digest_link')
      - UPDATE digest_log.action_taken
      - Write audit_log
      - Return HTML confirmation page with CSP header (S-05)
    """
    digest_log = token_info.digest_log
    action = token_info.action  # 'confirm' | 'release'

    label = "phishing" if action == "confirm" else "safe"
    action_taken = "confirmed_phishing" if action == "confirm" else "marked_safe"

    # INSERT feedback
    feedback = Feedback(
        email_id=digest_log.email_id,
        user_id=None,   # recipient is not a system user
        label=label,
        source="digest_link",
        created_at=datetime.now(timezone.utc),
    )
    db.add(feedback)

    # UPDATE digest_log.action_taken + action_taken_at
    digest_log.action_taken = action_taken
    digest_log.action_taken_at = datetime.now(timezone.utc)

    # Best-effort audit write (digest_log has org context via email)
    try:
        from sqlalchemy import select as sa_select
        from app.models.email import Email
        from app.models.audit_log import AuditLog

        email_row = (
            await db.execute(
                sa_select(Email.org_id).where(Email.id == digest_log.email_id)
            )
        ).scalar_one_or_none()

        if email_row:
            log = AuditLog(
                org_id=email_row,
                user_id=None,
                action=f"digest_{action_taken}",
                target_type="email",
                target_id=digest_log.email_id,
                detail={"digest_log_id": str(digest_log.id)},
            )
            db.add(log)
    except Exception:
        logger.warning("digest_audit_write_failed")

    if action == "confirm":
        title = "Phishing Confirmed"
        message = (
            "Thank you. This email has been reported as phishing and your "
            "security team has been notified."
        )
    else:
        title = "Email Marked Safe"
        message = (
            "Thank you. This email has been marked as safe and will be "
            "released to your inbox."
        )

    await db.commit()

    html = _html_page(title, message)
    return HTMLResponse(
        content=html,
        status_code=200,
        headers={"Content-Security-Policy": "default-src 'self'"},
    )
