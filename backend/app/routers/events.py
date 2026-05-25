"""Section 4.10 -- SSE real-time stream: GET /events

EventSource('/api/v1/events?token='+accessToken)

Auth via ?token= query param (EventSource cannot set custom headers).
All 6 SSE event types (Section 2.2):
  scan_complete, threshold_changed, forwarding_test_complete,
  digest_sent, export_ready, notification
"""
from __future__ import annotations

import asyncio
import json
from typing import AsyncGenerator

import redis.asyncio as aioredis
import structlog
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from app.dependencies import CurrentUser, get_current_user, get_redis

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["events"])

_KEEPALIVE_INTERVAL = 30  # seconds (Section 4.10: comment every 30 s)
_CONNECTION_TTL = 300      # seconds (Redis NX TTL per user)
_STREAM_MAXLEN = 200       # Section 4.10: XRANGE replay MAXLEN 200


async def _sse_generator(
    current_user: CurrentUser,
    redis: aioredis.Redis,
) -> AsyncGenerator[bytes, None]:
    """Generate SSE events from Redis pub/sub + keepalive comments.

    Section 4.10 behaviour:
      - Redis SET NX events:connected:{user_id} TTL 300 s
      - Subscribe to org:{org_id}:events + user:{user_id}:events
      - Keepalive comment every 30 s
      - On disconnect: Redis DEL events:connected:{user_id}
    """
    connected_key = f"events:connected:{current_user.id}"
    await redis.set(connected_key, "1", ex=_CONNECTION_TTL, nx=True)

    pubsub = redis.pubsub()
    org_channel = f"org:{current_user.org_id}:events"
    user_channel = f"user:{current_user.id}:events"
    await pubsub.subscribe(org_channel, user_channel)

    try:
        # Replay recent events from the org stream (Last-Event-ID support)
        stream_key = f"org:{current_user.org_id}:stream"
        try:
            stream_entries = await redis.xrange(stream_key, count=_STREAM_MAXLEN)
            for entry_id, data in stream_entries:
                event_data = data.get("data", "{}")
                yield f"id: {entry_id}\ndata: {event_data}\n\n".encode()
        except Exception:
            pass  # stream may not exist yet

        while True:
            # Check for incoming messages with timeout for keepalive
            try:
                message = await asyncio.wait_for(
                    pubsub.get_message(ignore_subscribe_messages=True, timeout=None),
                    timeout=_KEEPALIVE_INTERVAL,
                )
            except asyncio.TimeoutError:
                # Send keepalive comment
                yield b": keepalive\n\n"
                # Refresh connection TTL
                await redis.expire(connected_key, _CONNECTION_TTL)
                continue

            if message and message["type"] == "message":
                raw = message.get("data", "{}")
                if isinstance(raw, bytes):
                    raw = raw.decode()
                try:
                    parsed = json.loads(raw)
                    event_type = parsed.get("type", "message")
                    event_data = json.dumps(parsed.get("data", parsed))
                except (json.JSONDecodeError, AttributeError):
                    event_type = "message"
                    event_data = raw

                event = f"event: {event_type}\ndata: {event_data}\n\n"
                yield event.encode()

    except asyncio.CancelledError:
        pass
    finally:
        await pubsub.unsubscribe(org_channel, user_channel)
        await pubsub.close()
        await redis.delete(connected_key)


@router.get(
    "/events",
    summary="Server-Sent Events stream (all 6 event types)",
    response_class=StreamingResponse,
)
async def sse_events(
    current_user: CurrentUser = Depends(get_current_user),
    redis: aioredis.Redis = Depends(get_redis),
):
    """Open a persistent SSE connection for this user.

    Auth: validated from ``?token=`` query param on connect (EventSource spec).
    The token is NOT re-sent on each SSE message (S-04: CSRF-immune).

    Publishes all 6 event types:
        scan_complete          -- email analysis finished
        threshold_changed      -- admin updated detection thresholds
        forwarding_test_complete -- IMAP test email received
        digest_sent            -- digest email dispatched
        export_ready           -- export file ready to download
        notification           -- any other org/user notification
    """
    return StreamingResponse(
        _sse_generator(current_user, redis),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering for SSE
            "Connection": "keep-alive",
        },
    )
