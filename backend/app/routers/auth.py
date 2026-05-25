"""Section 4.1 -- FR-01, UC-01 router for PhishGuard.

Prefix: /auth
Endpoints:
    POST /auth/register
    POST /auth/login
    GET /auth/me
    POST /auth/refresh
    POST /auth/logout
    POST /auth/forgot-password
    POST /auth/reset-password
    POST /auth/invite
    POST /auth/accept-invite

Implementation follows after services/ and tasks/ layers are complete.
"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()
