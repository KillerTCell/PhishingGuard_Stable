"""Section 4.9 -- UC admin router for PhishGuard.

Prefix: /users
Endpoints:
    GET /users/stats
    GET /users
    GET /users/{id}
    PATCH /users/{id}
    DELETE /users/{id}

Implementation follows after services/ and tasks/ layers are complete.
"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()
