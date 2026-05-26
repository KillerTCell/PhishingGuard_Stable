"""Section 9 Phase 2K — NLP feature extractor unit tests.

All extractors are called directly (not via the Celery chain) so these are
pure unit tests with no DB or HTTP client required.  Async tests (PhishTank)
use a fresh fakeredis.aioredis.FakeRedis() per test and respx to mock the
PhishTank HTTP call.
"""
from __future__ import annotations

import fakeredis.aioredis
import respx
from httpx import Response

from app.services.nlp_pipeline import (
    _check_phishtank,
    _extract_auth_failure,
    _extract_credential_request,
    _extract_grammar_quality,
    _extract_known_bad_url,
    _extract_link_mismatch,
    _extract_urgency_language,
)


# ---------------------------------------------------------------------------
# 1. test_urgency_language_detected
# ---------------------------------------------------------------------------


def test_urgency_language_detected() -> None:
    """Body containing 'verify immediately' → urgency_language score > 0."""
    result = _extract_urgency_language(
        "Please verify immediately or your account will be suspended."
    )
    assert result.feature_name == "urgency_language"
    assert result.score_contribution > 0
    assert len(result.feature_value["patterns_matched"]) > 0


# ---------------------------------------------------------------------------
# 2. test_credential_request_detected
# ---------------------------------------------------------------------------


def test_credential_request_detected() -> None:
    """Body containing 'enter your password' → credential_request score == 1.0."""
    result = _extract_credential_request(
        "Please enter your password to continue and confirm your account details."
    )
    assert result.feature_name == "credential_request"
    assert result.score_contribution == 1.0
    assert len(result.feature_value["patterns_matched"]) > 0


# ---------------------------------------------------------------------------
# 3. test_link_mismatch_detected
# ---------------------------------------------------------------------------


def test_link_mismatch_detected() -> None:
    """Link with is_mismatch=True → link_mismatch score > 0, mismatch_count == 1."""
    links = [
        {
            "displayed_text": "paypal.com",
            "actual_href": "http://evil-steal.com/creds",
            "is_mismatch": True,
        }
    ]
    result = _extract_link_mismatch(links)
    assert result.feature_name == "link_mismatch"
    assert result.score_contribution > 0
    assert result.feature_value["mismatch_count"] == 1
    assert len(result.feature_value["mismatched_links"]) == 1


# ---------------------------------------------------------------------------
# 4. test_no_mismatch_same_domain
# ---------------------------------------------------------------------------


def test_no_mismatch_same_domain() -> None:
    """Link with is_mismatch=False → link_mismatch score == 0."""
    links = [
        {
            "displayed_text": "paypal.com",
            "actual_href": "https://www.paypal.com/login",
            "is_mismatch": False,
        }
    ]
    result = _extract_link_mismatch(links)
    assert result.feature_name == "link_mismatch"
    assert result.score_contribution == 0.0
    assert result.feature_value["mismatch_count"] == 0


# ---------------------------------------------------------------------------
# 5. test_auth_failure_spf_fail
# ---------------------------------------------------------------------------


def test_auth_failure_spf_fail() -> None:
    """spf='fail' → auth_failure score == 1.0 (definite authentication failure)."""
    result = _extract_auth_failure(spf="fail", dkim="pass", dmarc="pass")
    assert result.feature_name == "auth_failure"
    assert result.score_contribution == 1.0
    assert result.feature_value["spf"] == "fail"


# ---------------------------------------------------------------------------
# 6. test_auth_all_none
# ---------------------------------------------------------------------------


def test_auth_all_none() -> None:
    """All three 'none' → auth_failure score == 0.5 (no auth present — suspicious)."""
    result = _extract_auth_failure(spf="none", dkim="none", dmarc="none")
    assert result.feature_name == "auth_failure"
    assert result.score_contribution == 0.5


# ---------------------------------------------------------------------------
# 7. test_phishtank_429_returns_zero
# ---------------------------------------------------------------------------


async def test_phishtank_429_returns_zero() -> None:
    """PhishTank returns HTTP 429 → _check_phishtank returns False (fail-open, P-06 fix)."""
    redis = fakeredis.aioredis.FakeRedis()
    try:
        with respx.mock:
            respx.post("https://checkurl.phishtank.com/checkurl/").mock(
                return_value=Response(429)
            )
            result = await _check_phishtank("evil-phishing-site.com", redis)
        assert result is False
    finally:
        await redis.aclose()


# ---------------------------------------------------------------------------
# 8. test_phishtank_known_bad
# ---------------------------------------------------------------------------


async def test_phishtank_known_bad() -> None:
    """PhishTank confirms domain → _extract_known_bad_url score == 1.0 (P-06 fix)."""
    redis = fakeredis.aioredis.FakeRedis()
    try:
        with respx.mock:
            respx.post("https://checkurl.phishtank.com/checkurl/").mock(
                return_value=Response(
                    200, json={"results": {"in_database": True}}
                )
            )
            links = [{"actual_href": "http://confirmed-phish.com/steal-creds"}]
            result = await _extract_known_bad_url(links, redis)
        assert result.feature_name == "known_bad_url"
        assert result.score_contribution == 1.0
        assert "confirmed-phish.com" in result.feature_value["bad_domains"]
    finally:
        await redis.aclose()


# ---------------------------------------------------------------------------
# 9. test_grammar_quality_bad_text
# ---------------------------------------------------------------------------


def test_grammar_quality_bad_text() -> None:
    """Highly misspelled text → grammar_quality score > 0, corrected_words > 0."""
    # Uses obvious misspellings that TextBlob's probabilistic corrector reliably fixes.
    bad_text = (
        "Teh recieve accomodation acheive occured freind wierd neccessary "
        "seperate definately recomend occurence untill embarass."
    )
    result = _extract_grammar_quality(bad_text)
    assert result.feature_name == "grammar_quality"
    assert result.score_contribution > 0
    assert result.feature_value["corrected_words"] > 0
    assert result.feature_value["total_words"] > 0
