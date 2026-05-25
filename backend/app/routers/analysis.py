"""Section 4.3 -- FR-03, FR-04, Dashboard router for PhishGuard.

Prefix: /analysis + /dashboard
Endpoints:
    POST /analysis/paste
    GET /analysis/sample
    GET /analysis/{id}/status
    GET /analysis/stats
    GET /dashboard/insights

Implementation follows after services/ and tasks/ layers are complete.
"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()
