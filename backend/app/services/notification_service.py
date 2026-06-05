"""Notification push helper (Section 6 — real-time in-app notifications).

publish a typed "notification" event to the org's SSE channel so every
connected browser tab sees it instantly.  Also increments per-user
``notif:{user_id}:unread`` Redis counters so the badge count is correct
across page refreshes.

All operations are fire-and-forget: failures are logged at WARNING level
and never propagate to the calling route handler.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

import structlog

log = structlog.get_logger(__name__)


async def push_notification(
    redis,
    org_id: str,
    event_type: str,
    title: str,
    message: str,
    severity: str = "info",
    analyst_ids: Optional[list] = None,
) -> None:
    """Publish a notification to the org SSE channel.

    Args:
        redis:        Active aioredis client.
        org_id:       UUID string for the organisation.
        event_type:   Machine-readable event slug (e.g. ``"email_actioned"``).
        title:        Short human-readable title shown in the panel header.
        message:      Longer description shown in the panel body.
        severity:     One of ``"info" | "success" | "warning" | "danger"``.
        analyst_ids:  Optional list of user UUID strings whose per-user
                      ``notif:{uid}:unread`` counter should be incremented.
                      Pass ``None`` to skip per-user counting (e.g. when the
                      route already calls ``_bump_analyst_notifications``).

    Never raises — all exceptions are caught and logged.
    """
    try:
        payload = json.dumps({
            "type":      "notification",
            "event":     event_type,
            "title":     title,
            "message":   message,
            "severity":  severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        channel    = f"org:{org_id}:events"
        stream_key = f"org:{org_id}:stream"
        await redis.publish(channel, payload)
        await redis.xadd(stream_key, {"data": payload}, maxlen=200, approximate=True)

        if analyst_ids:
            for uid in analyst_ids:
                await redis.incr(f"notif:{uid}:unread")

    except Exception as exc:
        log.warning(
            "notification_push_failed",
            org_id=org_id,
            event_type=event_type,
            error=str(exc),
        )
