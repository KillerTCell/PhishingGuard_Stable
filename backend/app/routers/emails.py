"""Section 4.2 -- FR-02, UC-02, UC-03 router for PhishGuard.

Prefix: /emails
Endpoints:
    POST /emails/upload
    GET /emails
    GET /emails/{id}
    DELETE /emails/{id}

Implementation follows after services/ and tasks/ layers are complete.
"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()
