"""Section 4.4 -- FR-05, UC-03, UC-05 router for PhishGuard.

Prefix: /quarantine
Endpoints:
    GET /quarantine
    GET /quarantine/{id}
    GET /quarantine/{id}/digest-preview
    POST /quarantine/{id}/confirm
    POST /quarantine/{id}/release
    POST /quarantine/{id}/investigate
    POST /quarantine/{id}/send-digest

Implementation follows after services/ and tasks/ layers are complete.
"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()
