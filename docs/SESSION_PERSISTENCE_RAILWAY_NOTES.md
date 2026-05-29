# Session Persistence — Railway Deployment Notes

## Critical: Railway environment variable required

Before deploying to Railway, set this environment variable:

```
ENVIRONMENT=production
```

Without it, the refresh token cookie will have `Secure=False`, which is
intentional for local HTTP development but wrong for HTTPS production.

---

## Problem

Before this change, every browser refresh forced the user back to the
login page because `window.authToken` (the JWT access token) lives only in
JavaScript memory and is lost when the page reloads.

## Solution

The backend already issues a **HttpOnly Secure `refresh_token` cookie**
on every successful login (`POST /auth/login`). This cookie:

- Is stored by the **browser** (not JavaScript) — survives page refresh
- Cannot be read or modified by JavaScript (`HttpOnly`)
- Is only sent over HTTPS (`Secure`)
- Expires after 7 days (controlled by `REFRESH_TOKEN_EXPIRE_DAYS`)
- Is sent automatically to the same domain on every request
  (`credentials: 'include'`)

## What was added to PhishGuard.html (2026-05-29)

| Feature | Detail |
|---|---|
| `#session-loading` overlay | White full-screen spinner shown while restore runs; prevents flash of login form |
| `tryRestoreSession()` | Calls `POST /auth/refresh` on page load; if OK, calls `/auth/me` to rebuild `currentUser` |
| `startTokenRefreshTimer()` | `setInterval` every 7 hours to silently refresh before the 8-hour JWT expires |
| `showSessionExpiredMessage()` | Toast + 2 s delay before redirecting to login when refresh token itself expires |
| `visibilitychange` listener | Calls `/auth/me` when user returns to the tab after a long absence; triggers restore or expired message |
| `DOMContentLoaded` refactored | Tries session restore first; only shows login if restore fails |
| Login / invite handlers | Both call `startTokenRefreshTimer()` after authentication |
| `logout()` | Clears `_tokenRefreshTimer`, `exportPollInterval`, and export session state |

## Page load flow

```
Page load
  │
  ├─ #session-loading overlay visible (z-index 99999)
  │
  ├─ tryRestoreSession()
  │   ├─ POST /auth/refresh (with HttpOnly cookie — sent automatically)
  │   │   ├─ 200 OK → window.authToken = new access_token
  │   │   │           GET /auth/me → populate currentUser
  │   │   │           return true
  │   │   └─ 401/500 → return false
  │   └─ catch (network) → return false
  │
  ├─ Hide #session-loading overlay
  │
  ├─ Restored?
  │   ├─ YES → startTokenRefreshTimer(), connectSSE(), show dashboard
  │   └─ NO  → show login form, health check
```

## Railway deployment

No configuration changes required. Railway provides HTTPS automatically,
so the `Secure` flag on the cookie works out of the box.

**Verify these settings are correct in `.env` / Railway environment:**

```
REFRESH_TOKEN_EXPIRE_DAYS=7        # how long the cookie persists
JWT_EXPIRE_HOURS=8                 # access token lifetime (matches 7-hour refresh timer)
```

The `COOKIE_SECURE` setting (or equivalent) must be `True` in production.
If you are testing with local HTTP (not HTTPS), the cookie will not be sent —
use `localhost` with the nginx TLS proxy (`docker compose up`) for local
testing of the session restore flow.

## Testing the fix

1. Log in → navigate to Dashboard → close and reopen the browser tab
   → page should go straight to Dashboard (no login prompt)
2. Log in → hit browser refresh (F5) → should stay logged in
3. Log in → wait 7+ hours → access token expires → timer fires →
   silently refreshes → user never sees a prompt
4. Log in → wait 7+ days → refresh token expires → on next tab visit
   or 7-hour timer fires → "Your session has expired" toast →
   auto-redirect to login after 2 seconds
5. Click Logout → cookie is cleared server-side → page refresh now
   shows login (session restore fails cleanly)

---

## Inactivity Timeout (added 2026-05-30)

### Behaviour

| Time | What happens |
|---|---|
| 0–19 min of inactivity | No interruption |
| 19 min | Warning modal appears with 60-second countdown |
| 19 min + user clicks "I'm still here" | Modal closes, full 20-minute timer resets |
| 19 min + user clicks "Sign out now" | Immediate logout |
| 20 min (no interaction) | Auto-logout — login screen shows with amber warning banner |
| Escape key while modal is showing | Same as "I'm still here" |

### Activity events tracked

`mousemove`, `mousedown`, `keydown`, `scroll`, `touchstart`, `click`

Any of these events resets the 20-minute timer.

### Configuring the timeout

To change the timeout, find this line in `PhishGuard.html`:

```javascript
const INACTIVITY_TIMEOUT_MS = 20 * 60 * 1000; // 20 minutes
```

The warning always appears `WARNING_BEFORE_MS` (1 minute) before the logout fires.

### Connections cleaned up on inactivity logout

`handleInactivityLogout()` calls `logout()` which handles:
- `stopInactivityTracking()` — removes all event listeners, clears all timers
- `_tokenRefreshTimer` — cleared
- `exportPollInterval` — cleared
- `disconnectSSE()` — EventSource closed
- `POST /auth/logout` — backend blacklists the refresh token JTI and clears the cookie

### Railway impact

None — frontend only. Works identically in local Docker and Railway production.

---

## Cookie fix — SameSite=Lax (added 2026-05-30)

### Root cause of "session restore not working on page refresh"

The refresh token cookie was set with `SameSite=Strict` and `Secure=True`.

Chrome 86+ introduced **schemeful same-site**: `http://localhost:3000`
(frontend) and `https://localhost:443` (nginx backend) are treated as
**different sites** because their schemes differ (`http` vs `https`).

With `SameSite=Strict` + schemeful same-site:
- `POST /auth/refresh` from `http://localhost:3000` to `https://localhost`
  is treated as a cross-site request
- `SameSite=Strict` never sends cookies on cross-site requests
- The backend receives no cookie → returns 401
- `tryRestoreSession()` returns `false` → login page is shown

### Fix applied

`backend/app/routers/auth.py` — `_set_refresh_cookie()`:
- `samesite="strict"` → `samesite="lax"` (works across port and scheme on localhost)
- `secure=True` → `secure=is_production` (False in dev, True in prod)

`backend/app/core/config.py`:
- Added `ENVIRONMENT: str = "development"` setting

### Why SameSite=Lax is safe in production

`SameSite=Lax` still blocks CSRF on cross-site `POST` requests from
third-party pages. The only scenario where Lax is weaker than Strict is
cross-site top-level GET navigation (clicking a link from an external site).
The `/auth/refresh` endpoint is `POST`-only, so it is not affected.

### Railway deployment step

Set the environment variable before deploying:
```
ENVIRONMENT=production
```

This makes the cookie `Secure=True` in production (required for HTTPS,
which Railway provides automatically).

Without `ENVIRONMENT=production`, the cookie will have `Secure=False` in
production, which still works over HTTPS but is not best practice.
