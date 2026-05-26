"""Section 4.10 -- SSE real-time stream: GET /events

EventSource('/api/v1/events?token='+accessToken)

Auth via ?token= query param (EventSource cannot set custom headers).
All 6 SSE event types (Section 2.2):
  scan_complete, quarantine_created, threshold_changed,
  forwarding_test_complete, digest_sent, export_ready

Section 6.2 — Last-Event-ID replay:
  On reconnect the browser sends the Last-Event-ID header.  When present,
  the stream replays all entries in org:{org_id}:stream from that ID
  (inclusive) before entering the live listen loop so no events are missed.

Keepalive:
  A ``:keepalive`` SSE comment is sent every 30 s so load balancers and
  browser implementations do not close idle connections.
"""
from __future__ import annotations

import asyncio
import json
from typing import AsyncGenerator
from uuid import uuid4

import redis.asyncio as aioredis
import structlog
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from app.dependencies import CurrentUser, get_current_user, get_redis

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["events"])

_KEEPALIVE_INTERVAL = 30   # seconds (Section 4.10: comment every 30 s)
_CONNECTION_TTL = 300       # seconds (Redis NX TTL per user)
_STREAM_MAXLEN = 200        # Section 4.10 / Section 6.2: XRANGE replay cap


async def _sse_generator(
    request: Request,
    current_user: CurrentUser,
    redis: aioredis.Redis,
) -> AsyncGenerator[bytes, None]:
    """Yield SSE bytes: Last-Event-ID replay → live pub/sub → keepalive.

    Protocol (Section 4.10, Section 6.2):
      1. Redis SET NX events:connected:{user_id} TTL 300 s (presence marker).
      2. Subscribe to ``org:{org_id}:events`` and ``user:{user_id}:events``.
      3. Replay: if the ``Last-Event-ID`` request header is present, XRANGE
         the org stream from that ID so missed events are re-delivered.
      4. Live loop: poll pub/sub with a 30-s timeout; emit keepalive comment
         on timeout so proxy/browser connections stay open.
      5. On disconnect (``asyncio.CancelledError``): unsubscribe, close pubsub,
         delete the presence key.

    Each emitted event includes an ``id:`` field containing a fresh UUIDv4 so
    the browser's ``EventSource`` can send ``Last-Event-ID`` on reconnect.

    Args:
        request:      FastAPI Request — used to read the Last-Event-ID header.
        current_user: Validated, active user from JWT.
        redis:        Shared async Redis client.

    Yields:
        UTF-8 encoded SSE frames.
    """
    connected_key = f"events:connected:{current_user.id}"
    await redis.set(connected_key, "1", ex=_CONNECTION_TTL, nx=True)

    pubsub = redis.pubsub()
    org_channel = f"org:{current_user.org_id}:events"
    user_channel = f"user:{current_user.id}:events"
    await pubsub.subscribe(org_channel, user_channel)

    try:
        # ── Last-Event-ID replay (Section 6.2) ───────────────────────────
        last_event_id: str | None = request.headers.get("last-event-id")
        if last_event_id:
            stream_key = f"org:{current_user.org_id}:stream"
            try:
                # XRANGE from last_event_id inclusive so the client receives
                # every event it may have missed while disconnected.
                entries = await redis.xrange(
                    stream_key,
                    min=last_event_id,
                    count=_STREAM_MAXLEN,
                )
                for entry_id, fields in entries:
                    event_data = fields.get("data", "{}")
                    replay_id = str(uuid4())
                    yield (
                        f"id: {replay_id}\ndata: {event_data}\n\n"
                    ).encode()
            except Exception as replay_exc:
                logger.warning(
                    "sse_replay_failed",
                    user_id=str(current_user.id),
                    last_event_id=last_event_id,
                    error=str(replay_exc),
                )

        # ── Live listen loop ──────────────────────────────────────────────
        while True:
            try:
                message = await asyncio.wait_for(
                    pubsub.get_message(
                        ignore_subscribe_messages=True, timeout=None
                    ),
                    timeout=_KEEPALIVE_INTERVAL,
                )
            except asyncio.TimeoutError:
                # Keepalive comment — not an event, no id: field needed.
                yield b": keepalive\n\n"
                await redis.expire(connected_key, _CONNECTION_TTL)
                continue

            if message and message["type"] == "message":
                raw = message.get("data", "{}")
                if isinstance(raw, bytes):
                    raw = raw.decode()
                event_id = str(uuid4())
                yield f"id: {event_id}\ndata: {raw}\n\n".encode()

    except asyncio.CancelledError:
        pass
    finally:
        await pubsub.unsubscribe(org_channel, user_channel)
        await pubsub.close()
        await redis.delete(connected_key)
        logger.info(
            "sse_client_disconnected",
            user_id=str(current_user.id),
            org_id=str(current_user.org_id),
        )


@router.get(
    "/events",
    summary="Server-Sent Events stream (Section 4.10, Section 6.2)",
    response_class=StreamingResponse,
)
async def sse_events(
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
    redis: aioredis.Redis = Depends(get_redis),
):
    """Open a persistent SSE connection for this user.

    Auth: validated from ``?token=`` query param on connect (EventSource spec).
    Token is NOT re-sent per message (S-04: CSRF-immune).

    Last-Event-ID (Section 6.2):
        On reconnect the browser sends the ``Last-Event-ID`` header containing
        the last received event UUID.  The stream replays the org event stream
        from that point before entering the live loop.

    Publishes all SSE event types (Section 2.2):
        scan_complete          -- email analysis finished (quarantine_service)
        quarantine_created     -- phishing email quarantined (quarantine_service)
        threshold_changed      -- admin updated detection thresholds
        forwarding_test_complete -- IMAP test email received
        digest_sent            -- digest email dispatched
        export_ready           -- export file ready to download

    Returns a ``text/event-stream`` ``StreamingResponse`` with:
        Cache-Control: no-cache
        X-Accel-Buffering: no  (disable nginx buffering for SSE)
        Connection: keep-alive
    """
    return StreamingResponse(
        _sse_generator(request, current_user, redis),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
