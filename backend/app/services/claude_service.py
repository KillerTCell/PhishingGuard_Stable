"""Anthropic Claude integration service (Section 5.1 Task 4, Section 8, FR-04, UC-10).

Public API:
    RULE_TEXT_TEMPLATES  -- 7-key dict used as fallback for generate_explanation()
    LOCAL_ANSWER_MAP     -- 8-key dict for AI assistant local/offline mode
    generate_explanation -- async; calls Claude API, falls back to templates
    chat_stream          -- async generator; streams chat responses token-by-token

All Claude API errors are caught and handled gracefully:
    generate_explanation() returns a RULE_TEXT_TEMPLATES entry on any failure.
    chat_stream()         yields a LOCAL_ANSWER_MAP entry on any failure.

Neither function ever raises — callers can treat them as fire-and-forget.
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator
from typing import Any

import anthropic
from anthropic.types import TextBlock
import httpx
import structlog

from app.core.config import settings

log = structlog.get_logger(__name__)

_CLAUDE_MODEL = "claude-sonnet-4-20250514"

# ---------------------------------------------------------------------------
# Rule-text fallback templates (Section 5.1 Task 4)
# ---------------------------------------------------------------------------

RULE_TEXT_TEMPLATES: dict[str, str] = {
    "urgency_language": (
        "This email uses urgent language to pressure you into acting quickly "
        "without thinking, a classic phishing tactic."
    ),
    "credential_request": (
        "This email explicitly requests your login credentials or personal "
        "financial information, which legitimate services never ask for via email."
    ),
    "link_mismatch": (
        "The links in this email display one domain but actually point to a "
        "different, suspicious domain designed to steal your information."
    ),
    "impersonation_language": (
        "This email impersonates a known brand or organisation to gain your "
        "trust before requesting sensitive information."
    ),
    "auth_failure": (
        "This email failed email authentication checks (SPF/DKIM/DMARC), "
        "indicating it may not actually be from the claimed sender."
    ),
    "known_bad_url": (
        "This email contains URLs that have been reported as phishing sites "
        "in public threat intelligence databases."
    ),
    "grammar_quality": (
        "This email contains an unusually high number of spelling errors and "
        "grammatical mistakes, a common characteristic of phishing emails that "
        "are often composed quickly or translated from another language."
    ),
    "default": (
        "This email exhibits multiple characteristics commonly associated with "
        "phishing attempts. Exercise caution before clicking any links or "
        "providing information."
    ),
}

# ---------------------------------------------------------------------------
# Local answer map — AI assistant offline / demo mode (Section 4.5, Section 8)
# ---------------------------------------------------------------------------

LOCAL_ANSWER_MAP: dict[str, str] = {
    "tech stack": (
        "PhishGuard uses FastAPI with Python 3.12, PostgreSQL 16, Redis 7, and "
        "Celery 5 for the backend. Machine learning uses scikit-learn RandomForest "
        "and spaCy for NLP."
    ),
    "admin flow": (
        "Admins can adjust detection thresholds, manage users, view the audit log, "
        "configure IMAP forwarding, and export training data."
    ),
    "spf dkim": (
        "SPF checks if the sending IP is authorised. DKIM verifies the email "
        "signature. DMARC combines both policies. Failure on any indicates "
        "potential spoofing."
    ),
    "phishing threshold": (
        "Emails scoring above the phishing threshold (default 80/100) are "
        "automatically quarantined. The suspicious threshold (default 30/100) "
        "flags emails for review."
    ),
    "random forest": (
        "PhishGuard uses a Random Forest classifier trained on 7 features: "
        "urgency language, credential requests, link mismatches, impersonation, "
        "auth failure, grammar quality, and known bad URLs."
    ),
    "how does": (
        "PhishGuard follows a 5-step pipeline: email ingestion → parsing & "
        "sanitisation → NLP feature extraction → Random Forest classification "
        "→ outcome routing with real-time SSE alerts."
    ),
    "quarantine": (
        "Quarantined emails are held for analyst review. You can confirm as "
        "phishing, release to inbox, or mark for investigation. Quarantined "
        "emails trigger a digest email to the original recipient."
    ),
    "export": (
        "The export feature generates training datasets from analyst feedback. "
        "Filter by date range and label, then download in CSV, JSON, or JSONL "
        "format for model retraining."
    ),
}


# ---------------------------------------------------------------------------
# Hybrid scoring engine — internal only, never referenced in API responses
# ---------------------------------------------------------------------------


async def _call_claude_hybrid(
    sender: str,
    subject: str,
    body_text: str,
    spf: str,
    dkim: str,
    dmarc: str,
    top_features: list,
    ml_score: int,
) -> dict | None:
    """Internal hybrid engine. Calls Claude with full email context.

    Returns dict: final_score, explanation, confidence, verdict.
    Returns None on any failure so the caller falls back to rule-text.
    """
    feature_lines = []
    for f in (top_features or []):
        name = f.get("name", "")
        val = float(f.get("value", 0) or 0)
        if val > 0.1:
            feature_lines.append(f"- {name}: {val:.2f}")
    feature_text = "\n".join(feature_lines) or "- No strong signals"

    auth_parts = []
    if spf and spf != "none":
        auth_parts.append(f"SPF={spf}")
    if dkim and dkim != "none":
        auth_parts.append(f"DKIM={dkim}")
    if dmarc and dmarc != "none":
        auth_parts.append(f"DMARC={dmarc}")
    auth_str = ", ".join(auth_parts) or "Not checked"

    body_sample = (body_text or "").strip()[:600]

    prompt = f"""You are an email security system analysing whether an email is phishing.

EMAIL:
  From: {sender or 'unknown'}
  Subject: {subject or '(no subject)'}
  Authentication: {auth_str}
  Body: {body_sample}

AUTOMATED SIGNALS DETECTED:
{feature_text}
  Initial automated score: {ml_score}/100

Analyse this email for phishing risk. Consider:
- Sender domain legitimacy (random strings, suspicious TLDs, typosquatting)
- Whether the body content matches the claimed sender
- Urgency, threats, or pressure tactics
- Requests for credentials, personal data, or money
- Link deception, spoofed branding, or impersonation
- Authentication failures indicating spoofed sender
- Overall intent — is this deceptive?

Respond ONLY with this exact JSON (no other text):
{{
  "verdict": "safe" | "suspicious" | "phishing",
  "confidence": <integer 0-100>,
  "score": <integer 0-100>,
  "explanation": "<2-4 plain English sentences. Write for a non-technical person. Do NOT mention AI, machine learning, models, or algorithms. Explain what specific things about this email are suspicious or safe. Be direct and clear.>"
}}

SCORING GUIDE:
  0-19: Safe — clearly legitimate
  20-44: Low Risk — minor concerns
  45-64: Suspicious — needs review
  65-84: High Risk — likely phishing
  85-100: Critical — almost certainly phishing

If automated score and your analysis significantly disagree,
trust your analysis of the actual email content."""

    try:
        import re as _re  # noqa: PLC0415

        client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
        response = await asyncio.wait_for(
            client.messages.create(
                model=_CLAUDE_MODEL,
                max_tokens=350,
                messages=[{"role": "user", "content": prompt}],
            ),
            timeout=12.0,
        )
        raw = response.content[0].text.strip()

        json_match = _re.search(r"\{.*\}", raw, _re.DOTALL)
        if not json_match:
            raise ValueError(f"No JSON in response: {raw[:100]}")

        data = json.loads(json_match.group())
        verdict = data.get("verdict", "suspicious")
        confidence = max(0, min(100, int(data.get("confidence", 50))))
        claude_score = max(0, min(100, int(data.get("score", ml_score))))
        explanation = data.get("explanation", "")

        # Blend: Claude leads (65%), ML anchors (35%).
        # Gap <20 pts → trust ML. Wider divergence → blend toward Claude.
        gap = abs(claude_score - ml_score)
        if gap < 20:
            final_score = ml_score
        elif claude_score > ml_score:
            final_score = int(claude_score * 0.65 + ml_score * 0.35)
        else:
            blended = int(claude_score * 0.50 + ml_score * 0.50)
            final_score = max(blended, ml_score - 20)

        final_score = max(0, min(100, final_score))

        log.info(
            "hybrid_scoring",
            ml_score=ml_score,
            claude_score=claude_score,
            final_score=final_score,
            verdict=verdict,
            confidence=confidence,
        )
        return {
            "final_score": final_score,
            "explanation": explanation,
            "confidence": confidence,
            "verdict": verdict,
        }

    except Exception as exc:
        log.warning("hybrid_claude_failed", error=str(exc))
        return None


def _fallback_explanation(top_features: list, ml_score: int) -> dict:
    """Rule-based fallback when Claude API is unavailable.

    Returns plain-English explanation without mentioning technology.
    """
    top_name = (
        top_features[0].get("name", "default") if top_features else "default"
    )
    explanation = RULE_TEXT_TEMPLATES.get(top_name, RULE_TEXT_TEMPLATES["default"])
    verdict = (
        "phishing" if ml_score >= 60
        else "suspicious" if ml_score >= 30
        else "safe"
    )
    if ml_score >= 80:
        confidence = 85 + (ml_score - 80) // 4
    elif ml_score >= 60:
        confidence = 70 + (ml_score - 60) // 2
    elif ml_score >= 30:
        confidence = 50 + ml_score // 3
    else:
        confidence = 40 + ml_score
    confidence = max(0, min(100, confidence))
    return {
        "final_score": ml_score,
        "explanation": explanation,
        "confidence": confidence,
        "verdict": verdict,
    }


# Public interface — only function called externally
async def generate_explanation(
    top_features: list,
    sender: str,
    subject: str,
    body_text: str = "",
    ml_score: int = 0,
    spf: str = "none",
    dkim: str = "none",
    dmarc: str = "none",
) -> dict:
    """Unified public interface for the hybrid scoring engine.

    Returns dict: final_score, explanation, confidence, verdict. Never raises.
    """
    result = await _call_claude_hybrid(
        sender=sender,
        subject=subject,
        body_text=body_text,
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        top_features=top_features,
        ml_score=ml_score,
    )
    if result is None:
        result = _fallback_explanation(top_features, ml_score)
    return result


# ---------------------------------------------------------------------------
# chat_stream
# ---------------------------------------------------------------------------


async def chat_stream(
    messages: list[Any],
    org_stats: dict[str, Any],
    local_mode: bool = False,
) -> AsyncGenerator[str, None]:
    """Stream an AI assistant response, yielding text deltas token-by-token.

    Args:
        messages:   Full conversation history.  Each entry must have ``role``
                    (``'user'`` or ``'assistant'``) and ``content`` keys.
                    May be Pydantic ``AssistantMessage`` objects or plain dicts.
        org_stats:  Organisation statistics dict (from AnalysisStatsResponse)
                    used to build the system prompt context.  Expected keys:
                    ``current_threshold``, ``total_analysed``,
                    ``quarantined_count``, ``detection_driver_breakdown``,
                    ``model_version`` (optional).
        local_mode: When ``True``, skip the Claude API and return a
                    deterministic answer from :data:`LOCAL_ANSWER_MAP`.

    Yields:
        Text delta strings as they arrive from the Claude API (or a single
        full string from :data:`LOCAL_ANSWER_MAP` in local/error mode).
    """
    # ── Resolve last user message for keyword matching ────────────────────────
    last_user_msg = ""
    for msg in reversed(messages):
        role = msg.get("role") if isinstance(msg, dict) else str(getattr(msg, "role", ""))
        if role == "user":
            raw_content = msg.get("content") if isinstance(msg, dict) else getattr(msg, "content", "")
            last_user_msg = str(raw_content or "").lower()
            break

    # ── Local mode: keyword lookup only ──────────────────────────────────────
    if local_mode:
        for keyword, answer in LOCAL_ANSWER_MAP.items():
            if keyword in last_user_msg:
                yield answer
                return
        yield LOCAL_ANSWER_MAP["how does"]
        return

    # ── Build system prompt with org context ─────────────────────────────────
    threshold = org_stats.get("current_threshold") or {}
    suspicious = threshold.get("suspicious", 30) if isinstance(threshold, dict) else 30
    phishing = threshold.get("phishing", 80) if isinstance(threshold, dict) else 80
    total_analysed = org_stats.get("total_analysed", 0)
    quarantine_count = org_stats.get("quarantined_count", 0)
    model_version = org_stats.get("model_version", settings.MODEL_VERSION)

    raw_drivers = org_stats.get("detection_driver_breakdown") or []
    top_drivers = raw_drivers[:3]
    top_drivers_str = (
        ", ".join(
            d.get("feature_name", "") if isinstance(d, dict) else str(getattr(d, "feature_name", ""))
            for d in top_drivers
        )
        if top_drivers
        else "none recorded"
    )

    system_prompt = (
        "You are PhishGuard's security assistant. Answer concisely and helpfully.\n"
        "Never mention that you are Claude, never mention Anthropic, never mention "
        "AI or machine learning models. You are the PhishGuard security assistant. "
        "Refer to yourself as 'PhishGuard' or 'the security system'.\n"
        "Organisation context (use this to personalise your answers):\n"
        f"  Suspicious threshold : {suspicious}/100\n"
        f"  Phishing threshold   : {phishing}/100\n"
        f"  Emails analysed      : {total_analysed}\n"
        f"  Currently quarantined: {quarantine_count}\n"
        f"  Top detection signals: {top_drivers_str}"
    )

    # ── Normalise messages for the Anthropic API ──────────────────────────────
    from anthropic.types import MessageParam  # noqa: PLC0415
    from typing import cast  # noqa: PLC0415

    raw_api_messages: list[dict[str, str]] = []
    for msg in messages:
        if isinstance(msg, dict):
            raw_api_messages.append({
                "role": str(msg.get("role", "user")),
                "content": str(msg.get("content", "")),
            })
        else:
            raw_api_messages.append({
                "role": str(getattr(msg, "role", "user")),
                "content": str(getattr(msg, "content", "")),
            })
    api_messages = cast(list[MessageParam], raw_api_messages)

    # ── Resolve fallback keyword in case of API error ─────────────────────────
    fallback_key = "how does"
    for keyword in LOCAL_ANSWER_MAP:
        if keyword in last_user_msg:
            fallback_key = keyword
            break

    # ── Stream from Claude API ────────────────────────────────────────────────
    try:
        async_client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
        async with async_client.messages.stream(
            model=_CLAUDE_MODEL,
            max_tokens=500,
            system=system_prompt,
            messages=api_messages,
        ) as stream:
            async for text in stream.text_stream:
                yield text
    except Exception as exc:
        log.warning(
            "chat_stream_api_error",
            exc_type=type(exc).__name__,
            error=str(exc),
        )
        yield LOCAL_ANSWER_MAP.get(fallback_key, LOCAL_ANSWER_MAP["how does"])
