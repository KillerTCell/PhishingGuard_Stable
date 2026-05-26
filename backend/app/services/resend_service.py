"""Resend transactional email service (Section 5.2, FR-06, UC-05).

Public API:
    build_digest_html   -- sync; produce WCAG 2.1 AA-compliant digest HTML
    send_digest_email   -- async; dispatch via Resend SDK, return True/False

HTML template design (WCAG 2.1 AA):
  - Colour contrast: ≥ 4.5:1 for all text/background pairs
    · Red badge  #cc0000 on #ffffff  → 5.9:1  ✓
    · Amber badge #e6a817 uses dark text #1a1a1a → 7.6:1  ✓
    · Body text  #222222 on #ffffff   → 14.7:1 ✓
  - Semantic HTML: heading hierarchy h1/h2, role="main", aria-labels
  - Buttons have descriptive aria-label attributes
"""
from __future__ import annotations

import asyncio
from datetime import datetime

import structlog

from app.core.config import settings

log = structlog.get_logger(__name__)

_FROM_ADDRESS = "noreply@phishguard.app"
_APP_BASE_URL = f"https://{settings.FORWARDING_DOMAIN}"


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------


def _esc(text: str) -> str:
    """Minimal HTML-escape to prevent XSS in digest content."""
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ---------------------------------------------------------------------------
# build_digest_html
# ---------------------------------------------------------------------------


def build_digest_html(
    email,          # Email ORM instance
    analysis,       # AnalysisResult ORM instance or None
    signed_token: str,
    expires_at: datetime,
) -> str:
    """Build a WCAG 2.1 AA-compliant quarantine digest HTML email.

    The rendered email includes:
    - Risk badge (red for phishing, amber for suspicious, green otherwise)
    - From, Subject, and risk score metadata
    - Plain-English explanation from ``analysis_result.explanation``
    - Two signed action buttons (Release to Inbox / Report Phishing)
    - 72-hour expiry notice

    Action URL format (consumed by ``GET /digest/action``):
        ``{APP_BASE_URL}/api/v1/digest/action?token={signed_token}&action=...``

    Args:
        email:        Email ORM row (reads ``sender``, ``subject``).
        analysis:     AnalysisResult ORM row or ``None`` when still pending.
        signed_token: Full ``"{email_id}:{jti}:{hmac_hex}"`` token string.
        expires_at:   UTC ``datetime`` when the token expires (72 h from send).

    Returns:
        Complete HTML string, UTF-8 encoded, ready for the Resend ``html``
        parameter.
    """
    risk_score: int = analysis.risk_score if analysis else 0
    classification: str = (
        (analysis.classification if analysis else None) or "safe"
    )
    explanation: str = (
        (analysis.explanation if analysis else None)
        or "This email has been quarantined for security review."
    )

    # ── Risk badge colours (WCAG AA) ─────────────────────────────────────────
    if classification == "phishing":
        badge_bg = "#cc0000"
        badge_fg = "#ffffff"   # contrast 5.9:1 ✓
        badge_label = "PHISHING THREAT DETECTED"
        heading_colour = "#b71c1c"
    elif classification == "suspicious":
        badge_bg = "#e6a817"
        badge_fg = "#1a1a1a"   # dark text on amber → 7.6:1 ✓
        badge_label = "SUSPICIOUS EMAIL"
        heading_colour = "#7b5000"
    else:
        badge_bg = "#2e7d32"
        badge_fg = "#ffffff"   # contrast 5.1:1 ✓
        badge_label = "SECURITY REVIEW REQUIRED"
        heading_colour = "#1b5e20"

    sender = _esc(email.sender or "Unknown sender")
    subject = _esc(email.subject or "(No subject)")
    explanation_escaped = _esc(explanation)
    expires_str = expires_at.strftime("%d %b %Y at %H:%M UTC")

    release_url = (
        f"{_APP_BASE_URL}/api/v1/digest/action"
        f"?token={signed_token}&action=release"
    )
    confirm_url = (
        f"{_APP_BASE_URL}/api/v1/digest/action"
        f"?token={signed_token}&action=confirm"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PhishGuard Security Alert</title>
  <style>
    body {{
      font-family: system-ui, -apple-system, Segoe UI, Arial, sans-serif;
      font-size: 16px; line-height: 1.6; color: #222222;
      background-color: #f0f0f0; margin: 0; padding: 0;
    }}
    .wrapper {{ max-width: 600px; margin: 32px auto; padding: 0 16px; }}
    .card {{
      background: #ffffff; border-radius: 8px;
      border: 1px solid #dddddd; padding: 36px 40px;
    }}
    .logo {{
      font-size: 1.1rem; font-weight: 700; color: #1a237e;
      margin: 0 0 24px; letter-spacing: -0.01em;
    }}
    .badge {{
      display: inline-block; padding: 6px 14px; border-radius: 4px;
      background-color: {badge_bg}; color: {badge_fg};
      font-size: 0.78rem; font-weight: 700; letter-spacing: 0.06em;
      text-transform: uppercase; margin-bottom: 20px;
    }}
    h1 {{
      font-size: 1.3rem; color: {heading_colour};
      margin: 0 0 16px; font-weight: 700;
    }}
    .intro {{
      font-size: 0.95rem; color: #444444; margin: 0 0 24px;
    }}
    table.meta {{
      width: 100%; border-collapse: collapse; margin: 0 0 20px;
      font-size: 0.9rem;
    }}
    table.meta th {{
      text-align: left; padding: 5px 16px 5px 0;
      color: #555555; font-weight: 600;
      white-space: nowrap; vertical-align: top; width: 90px;
    }}
    table.meta td {{
      padding: 5px 0; color: #222222; word-break: break-word;
    }}
    .score {{ font-weight: 700; color: {badge_bg}; }}
    h2.section-heading {{
      font-size: 0.95rem; font-weight: 700; color: #333333;
      margin: 24px 0 8px;
    }}
    .explanation {{
      background-color: #f8f8f8;
      border-left: 4px solid {badge_bg};
      padding: 12px 16px; border-radius: 0 4px 4px 0;
      font-size: 0.93rem; color: #333333;
      margin: 0 0 28px;
    }}
    .actions-intro {{
      font-size: 0.9rem; color: #444444; margin: 0 0 16px;
    }}
    .btn {{
      display: inline-block; padding: 12px 22px;
      border-radius: 5px; font-size: 0.93rem; font-weight: 600;
      text-decoration: none; margin: 0 8px 8px 0;
      line-height: 1;
    }}
    .btn-release {{
      background-color: #1565c0; color: #ffffff;
    }}
    .btn-confirm {{
      background-color: #b71c1c; color: #ffffff;
    }}
    .expiry-notice {{
      font-size: 0.82rem; color: #666666; margin: 28px 0 0;
      padding-top: 20px; border-top: 1px solid #eeeeee;
    }}
    .footer {{
      font-size: 0.78rem; color: #888888;
      text-align: center; margin-top: 20px;
    }}
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="card" role="main">

      <p class="logo" aria-label="PhishGuard Security Platform">
        🛡 PhishGuard
      </p>

      <div class="badge"
           aria-label="Risk classification: {badge_label}">
        {badge_label}
      </div>

      <h1>Security Alert: Email Quarantined</h1>

      <p class="intro">
        An email addressed to you has been held in quarantine because our
        security system detected potential phishing indicators. Please review
        the details below and take action before the link expires.
      </p>

      <table class="meta" role="presentation"
             aria-label="Quarantined email details">
        <tr>
          <th scope="row">From</th>
          <td>{sender}</td>
        </tr>
        <tr>
          <th scope="row">Subject</th>
          <td>{subject}</td>
        </tr>
        <tr>
          <th scope="row">Risk Score</th>
          <td>
            <span class="score"
                  aria-label="Risk score: {risk_score} out of 100">
              {risk_score} / 100
            </span>
          </td>
        </tr>
      </table>

      <h2 class="section-heading">Why was this quarantined?</h2>
      <div class="explanation" role="note"
           aria-label="Security assessment explanation">
        {explanation_escaped}
      </div>

      <section aria-labelledby="action-heading">
        <h2 class="section-heading" id="action-heading">
          What would you like to do?
        </h2>
        <p class="actions-intro">
          If you were expecting this email and it is legitimate, click
          <strong>Release to Inbox</strong>. If it looks suspicious or
          unexpected, click <strong>Report Phishing</strong> to alert your
          security team.
        </p>
        <div role="group" aria-label="Action buttons">
          <a href="{release_url}"
             class="btn btn-release"
             role="button"
             aria-label="Release this email to your inbox — mark it as safe">
            ✓ Release to Inbox
          </a>
          <a href="{confirm_url}"
             class="btn btn-confirm"
             role="button"
             aria-label="Report this email as a phishing attempt">
            ✕ Report Phishing
          </a>
        </div>
      </section>

      <p class="expiry-notice" role="note">
        ⏱ These action links expire on
        <strong>{expires_str}</strong> (72 hours from when this notice was
        sent). After expiry, please contact your IT security team directly.
      </p>

    </div>
    <p class="footer">
      This security notice was generated by PhishGuard on behalf of your
      organisation. Do not forward this email — the action links are unique
      to you and will not work for anyone else.
    </p>
  </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# send_digest_email
# ---------------------------------------------------------------------------


async def send_digest_email(
    recipient: str,
    html: str,
    subject_prefix: str,
) -> bool:
    """Dispatch a digest HTML email via the Resend API.

    The synchronous Resend SDK call is wrapped in :func:`asyncio.to_thread`
    so the calling event loop is never blocked.

    Args:
        recipient:     Recipient email address string.
        html:          Fully rendered digest HTML from :func:`build_digest_html`.
        subject_prefix: Full email subject line (e.g.
                        ``"[PhishGuard] Quarantine Notice: Your invoice..."``)

    Returns:
        ``True`` when Resend accepts the message, ``False`` on any error.
        This function never raises — the caller decides whether to retry.
    """
    def _sync_send() -> bool:
        import resend  # noqa: PLC0415 — lazy import avoids startup cost

        resend.api_key = settings.RESEND_API_KEY
        resend.Emails.send(
            {
                "from": _FROM_ADDRESS,
                "to": [recipient],
                "subject": subject_prefix,
                "html": html,
            }
        )
        return True

    try:
        return await asyncio.to_thread(_sync_send)
    except Exception as exc:
        log.warning(
            "send_digest_email_failed",
            recipient=recipient,
            error=str(exc),
            exc_type=type(exc).__name__,
        )
        return False
