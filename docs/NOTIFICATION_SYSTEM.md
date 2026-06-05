# PhishGuard — Notification System

## Overview

Real-time in-app notification panel for all significant user actions.
Notifications are delivered via SSE (Server-Sent Events) for backend events
and added locally for frontend actions in the current session.

## Architecture

### Backend (SSE + Redis Pub/Sub)

- `notification_service.py`: `push_notification()` helper  
- Publishes to `org:{org_id}:events` Redis channel (same channel as existing SSE events)  
- Payload type: `"notification"` — distinct from `"scan_complete"`, `"quarantine_created"`, etc.  
- Also XADDs to `org:{org_id}:stream` for Last-Event-ID replay  
- `PATCH /notifications/read` resets `notif:{user_id}:unread` counter to 0  

### Frontend (in-memory store)

- `window._notifications`: array, newest first, max 100 entries  
- `window._unreadCount`: integer badge count  
- Notification panel: fixed overlay, top-right, below the bell  
- Persists for the session only (cleared on logout / page refresh)  

## Events That Generate Notifications

| Event | Source | Severity | Title |
|---|---|---|---|
| Email analysis complete | SSE `scan_complete` | info / warning / danger | Email Analysis Complete |
| Email quarantined | SSE `quarantine_created` | danger | Email Quarantined |
| Email confirmed phishing | Local + SSE `notification` | danger | Email Confirmed |
| Email released to inbox | Local + SSE `notification` | success | Email Released |
| Email flagged for investigation | Local + SSE `notification` | warning | Email Flagged |
| Email deleted (single) | Local | info | Email Deleted |
| Emails bulk deleted | Local | info | N Emails Deleted |
| User invited | Local | info | Invitation Sent |
| User deactivated / reactivated | Local | info | User Account Updated |
| Settings / thresholds saved | Local | success | Settings Saved |
| Threshold changed via SSE | SSE `threshold_changed` | warning | Thresholds Updated |
| IMAP email received | SSE `imap_ingested` | info | New Forwarded Email |
| Export ready | SSE `export_ready` | success | Export Ready |

## Severity Levels

| Severity | Colour | Icon | Use case |
|---|---|---|---|
| `danger` | Red `#ef4444` | 🚨 | Phishing confirmed, quarantine created |
| `warning` | Amber `#f59e0b` | ⚠️ | Suspicious email, threshold change, investigation |
| `success` | Green `#16a34a` | ✅ | Email released, export ready, settings saved |
| `info` | Blue `#3b82f6` | ℹ️ | Delete, invite, status change |

## Notification Panel UX

- Bell icon (`#notification-bell`) in top-right header with red badge (`#notification-badge`)
- Badge shows count; hidden when count is 0
- Panel opens on bell click, closes on outside click
- Unread notifications: coloured background matching severity + coloured dot
- Read notifications: white background, no dot
- **Mark all read**: clears badge, removes unread styling, calls `PATCH /notifications/read`
- **Clear all**: empties the list, hides panel
- Max 50 shown in panel, max 100 stored in memory
- Timestamps: "Just now", "Xm ago", "Xh ago", or locale date string

## Notification payload structure (SSE `"type": "notification"`)

```json
{
  "type":      "notification",
  "event":     "email_actioned",
  "title":     "Email Confirmed as Phishing",
  "message":   "Email from attacker@evil.com confirmed as phishing and saved for ML training.",
  "severity":  "danger",
  "timestamp": "2026-06-05T14:32:00.000000+00:00"
}
```

## Local Events (Session Only)

Actions performed in the current browser session add notifications immediately
without waiting for SSE. This gives instant feedback to the acting user.
SSE `"notification"` events from the backend ensure other users (on different
browsers/sessions) also see the event via `handleSSEEvent → addNotification`.

## Backend — push_notification()

```python
from app.services.notification_service import push_notification

await push_notification(
    redis, str(current_user.org_id),
    event_type = "email_actioned",
    title      = "Email Confirmed as Phishing",
    message    = f"Email from {email.sender} confirmed as phishing.",
    severity   = "danger",
)
```

Currently wired in:
- `quarantine.py` — `confirm_phishing`, `release_email`, `flag_for_investigation`

Remaining endpoints to wire (future):
- `emails.py` — `delete_email`, `bulk_delete_emails` (need `redis` dep added)
- `users.py` — `patch_user` (need `redis` dep added)
- `auth.py` — `invite_user` (need `redis` dep added)
- `settings.py` — `patch_settings` (need `redis` dep added)
- `export_tasks.py` — when `status='ready'` (Celery task)

## Railway Deployment

No infrastructure changes required. The SSE channel and Redis Pub/Sub work
identically in Railway production. `notif:{user_id}:unread` counters are stored
in Redis and shared across all API instances.
