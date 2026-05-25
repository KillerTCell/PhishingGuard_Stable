"""Section 4.6 -- FR-02, UC-02 router for PhishGuard.

Prefix: /forwarding
Endpoints:
    GET /forwarding
    GET /forwarding/emails
    POST /forwarding/test
    PATCH /forwarding/config

Implementation follows after services/ and tasks/ layers are complete.
"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()
