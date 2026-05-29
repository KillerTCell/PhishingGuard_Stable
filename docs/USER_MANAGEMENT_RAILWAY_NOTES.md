# User Management — Railway Deployment Notes

## API Endpoints Used (no changes needed for Railway)
  GET    /api/v1/users/stats       → summary cards (total, admins, analysts, active)
  GET    /api/v1/users             → user list (returns { items: [...] } or array)
  PATCH  /api/v1/users/{id}        → update role ({ role: "admin"|"analyst" })
                                     or toggle active ({ is_active: true|false })
  DELETE /api/v1/users/{id}        → soft delete (sets is_active=False, returns 204)

## DELETE endpoint behaviour
  Returns 204 No Content on success.
  This is a SOFT delete — sets is_active=False in the database.
  The user record is NOT permanently removed.
  User cannot login after deletion but their audit log entries remain.
  Frontend removes the row with a fade-out animation on 204.

## Deactivate vs Delete distinction
  Deactivate: PATCH /users/{id} with { is_active: false }
    → user row status badge changes to Inactive in-place (no full reload)
    → user can be reactivated later via PATCH { is_active: true }

  Delete: DELETE /users/{id}
    → row fades out and is removed from the DOM
    → intended as a more permanent action (though data is preserved)

## Guards that must work in production
  - Cannot delete your own account:
      Delete button is disabled (opacity 0.4, cursor not-allowed) for the
      logged-in user's own row. Clicking does nothing.
  - Cannot deactivate your own account:
      Deactivate button is disabled for your own row.
  - Cannot change your own role:
      Role dropdown is disabled for your own row.
  - Only Admin role can access User Management page at all:
      Backend returns 403 if non-admin calls any of these endpoints.
      Frontend hides the User Management nav item for non-admins.

## Inline confirmation pattern
  Deactivate, Reactivate, and Delete actions all show an inline
  confirmation row directly below the affected user row — NOT in a modal
  or at the bottom of the page. Only one confirmation row can be open at
  a time; opening a second closes the first automatically.

## No changes required for Railway
  All user management endpoints use relative API_BASE URL.
  As long as API_BASE points to the Railway URL, everything works.
  No environment variables specific to user management are needed.
