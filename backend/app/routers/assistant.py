"""Section 4.5 -- UC-10: AI Assistant streaming chat.

POST /analysis/assistant   -- Claude API streaming or LOCAL_ANSWER_MAP fallback

Rate limit: 30 req/min per user (Section 7.4).

Note: from __future__ import annotations is intentionally omitted here.
slowapi's @limiter.limit uses functools.wraps, which copies __annotations__ but
NOT __globals__.  With PEP-563 deferred annotations, string annotations like
'AssistantRequest' are evaluated in the wrapper's globals (slowapi's module),
not this module's globals, causing NameError.  Python 3.12 resolves all types
used here without deferred evaluation.
"""
import json
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from app.core.config import settings as app_settings
from app.dependencies import CurrentUser, get_current_user, get_org_thresholds, OrgThresholds
from app.main import limiter
from app.schemas.analysis import AssistantRequest

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["assistant"])

# Local fallback answers (UC-10: local_mode=True or Claude API unavailable)
_LOCAL_ANSWER_MAP: dict[str, str] = {
    "tech stack": (
        "PhishGuard uses FastAPI 0.111.0 (Python 3.12), PostgreSQL 16, "
        "Redis 7, Celery 5.4.0, spaCy 3.7.4 for NLP, scikit-learn 1.5.0 "
        "Random Forest for classification, and Claude (Anthropic) for "
        "plain-English explanations."
    ),
    "admin flow": (
        "Admins can: invite users, set detection thresholds (suspicious/phishing), "
        "review the quarantine queue, send digest emails to recipients, "
        "export data, configure IMAP forwarding, and view the full audit log."
    ),
    "spf": (
        "SPF (Sender Policy Framework) verifies that the sending mail server "
        "is authorised by the domain owner. DKIM (DomainKeys Identified Mail) "
        "adds a cryptographic signature. DMARC ties SPF and DKIM together and "
        "tells receivers what to do when checks fail."
    ),
    "dkim": (
        "DKIM adds a cryptographic signature to outgoing messages so recipients "
        "can verify they haven't been tampered with in transit."
    ),
    "dmarc": (
        "DMARC (Domain-based Message Authentication, Reporting & Conformance) "
        "lets domain owners publish policies for handling emails that fail SPF "
        "or DKIM checks, and receive reports about authentication failures."
    ),
    "risk score": (
        "The risk score is a 0–100 integer produced by the Random Forest "
        "classifier based on seven NLP features: urgency language, credential "
        "requests, impersonation, grammar quality, link mismatches, "
        "authentication failures, and known bad URLs."
    ),
    "threshold": (
        "Detection thresholds define when emails are classified: "
        "below the suspicious threshold → safe; "
        "between suspicious and phishing threshold → suspicious; "
        "above phishing threshold → phishing and quarantined."
    ),
}


def _local_answer(question: str) -> str:
    """Return a deterministic answer from LOCAL_ANSWER_MAP (case-insensitive keyword match)."""
    q_lower = question.lower()
    for keyword, answer in _LOCAL_ANSWER_MAP.items():
        if keyword in q_lower:
            return answer
    return (
        "I'm running in local mode and don't have a specific answer for that. "
        "Please connect to the Claude API for full AI assistant capabilities."
    )


async def _stream_local(answer: str):  # type: ignore[return]
    """Yield a single SSE data event with the local answer."""
    event = f"data: {json.dumps({'text': answer})}\n\n"
    yield event.encode()
    yield b"data: [DONE]\n\n"


async def _stream_claude(messages: list[dict[str, str]], context: str):  # type: ignore[return]
    """Stream Claude API response as SSE text/event-stream."""
    try:
        import anthropic

        client = anthropic.AsyncAnthropic(api_key=app_settings.ANTHROPIC_API_KEY)
        system_prompt = (
            "You are the PhishGuard AI security assistant. "
            f"Context about this organisation: {context}\n"
            "Answer questions about phishing detection, email security, and the PhishGuard system. "
            "Be concise and accurate."
        )
        async with client.messages.stream(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1024,
            system=system_prompt,
            messages=messages,
        ) as stream:
            async for text in stream.text_stream:
                yield f"data: {json.dumps({'text': text})}\n\n".encode()
        yield b"data: [DONE]\n\n"
    except Exception as exc:
        logger.error("claude_stream_error", error=str(exc))
        local_msg = _local_answer(" ".join(m.get("content", "") for m in messages[-1:]))
        async for chunk in _stream_local(local_msg):
            yield chunk


@router.post(
    "/analysis/assistant",
    summary="AI security assistant (streaming)",
    response_class=StreamingResponse,
)
@limiter.limit("30/minute")
async def assistant_chat(
    request: Request,
    body: AssistantRequest,
    current_user: CurrentUser = Depends(get_current_user),
    thresholds: OrgThresholds = Depends(get_org_thresholds),
):
    """Stream an AI assistant response (Claude API or local fallback).

    local_mode=True forces LOCAL_ANSWER_MAP lookup (used for demos or when
    Claude API is unavailable).

    Rate limit: 30 req/min per user (Section 7.4).
    System prompt includes org thresholds for context-aware answers.
    """
    last_user_message = next(
        (m.content for m in reversed(body.messages) if m.role.value == "user"),
        "",
    )

    if body.local_mode:
        answer = _local_answer(last_user_message)
        return StreamingResponse(
            _stream_local(answer),
            media_type="text/event-stream",
        )

    context = (
        f"suspicious_threshold={thresholds.suspicious}, "
        f"phishing_threshold={thresholds.phishing}"
    )
    claude_messages = [
        {"role": m.role.value, "content": m.content} for m in body.messages
    ]

    return StreamingResponse(
        _stream_claude(claude_messages, context),
        media_type="text/event-stream",
    )
