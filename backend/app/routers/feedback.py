"""Section 4.7 -- FR-07 router for PhishGuard.

Prefix: /feedback
Endpoints:
    POST /feedback/{email_id}

Implementation follows after services/ and tasks/ layers are complete.
"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()
