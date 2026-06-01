# PhishGuard — Railway Deploy Master Log

Cumulative change log of features shipped and their Railway impact.

---

## Section 6 — Email Delete & Quarantine UX

**2026-06-01** `PhishGuard.html` + `backend/app/routers/emails.py`

- Email list: added checkbox column + trash icon per row (admin only)
- Bulk toolbar: appears on selection, "Delete selected" button calls `DELETE /emails/bulk`
- `DELETE /emails/bulk` endpoint already existed (max 100 per request, org-scoped)
- `DELETE /emails/{id}` endpoint already existed (admin only, 204 on success)
- All delete operations use confirmation modal before executing
- Quarantine page reverted to original 3-button style: Confirm Phishing | Needs Investigation | Mark as Safe
- Quarantine bulk select/bulk toolbar removed — single trash icon (admin only) retained
- Quarantine trash calls shared `deleteSingleEmail()` function
- New JS functions: `deleteSingleEmail`, `bulkDeleteSelectedEmails`, `onEmailCheckboxChange`,
  `updateEmailBulkToolbar`, `toggleSelectAllEmails`, `selectAllVisibleEmails`, `clearEmailSelection`,
  `confirmPhishing`, `markInvestigation`, `releaseEmail`
- RBAC enforced at render time via `isAdmin` checks in `renderEmailList()` / `renderQuarantineQueue()`
- **Railway impact: NONE for frontend (static file). Backend: no changes required — endpoints pre-existed.**
