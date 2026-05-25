"""Section 4.13 -- N-03 fix router for PhishGuard.

Prefix: /health
Endpoints:
    GET /health

Implementation follows after services/ and tasks/ layers are complete.
"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()
