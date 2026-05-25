"""Section 4.7 -- Digest action link router for PhishGuard.

Prefix: /digest
Endpoints:
    GET /digest/action

Implementation follows after services/ and tasks/ layers are complete.
"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()
