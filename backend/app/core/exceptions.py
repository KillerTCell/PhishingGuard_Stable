"""Domain-specific exception types for PhishGuard (Section 9 Phase 3E).

Centralises all custom exceptions so routers can catch them and return
well-formed HTTP error responses, and services can raise them without
importing FastAPI.

Exception hierarchy
-------------------
Exception
 ├── EmailParseError       — raw bytes / MIME parsing failed
 ├── ModelNotFoundError    — model.pkl absent (first-deploy training race)
 ├── IMAPConnectionError   — IMAP4_SSL handshake / authentication failed
 └── ExportError           — data-export job could not be created or written
"""
from __future__ import annotations


class EmailParseError(Exception):
    """Raised when both primary and fallback parsers fail to parse the email."""


class ModelNotFoundError(Exception):
    """Raised when model.pkl does not exist at the expected path.

    The ``classify_email`` Celery task catches this and retries with
    ``countdown=30`` so that the first-deploy training race is handled
    gracefully.
    """


class IMAPConnectionError(Exception):
    """Raised when an IMAP4_SSL connection or authentication attempt fails."""


class ExportError(Exception):
    """Raised when a data-export job cannot be created or written to disk."""
