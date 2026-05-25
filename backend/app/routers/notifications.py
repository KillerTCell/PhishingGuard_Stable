"""Section 4.11 -- A-01 fix router for PhishGuard.

Prefix: /notifications
Endpoints:
    PATCH /notifications/read

Implementation follows after services/ and tasks/ layers are complete.
"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()
