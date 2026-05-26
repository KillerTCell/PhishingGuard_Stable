"""Section 5.1 Task 2 — NLP feature extraction pipeline (FR-03).

Seven feature extractors are run sequentially by ``extract_all_features()``.
Each returns a ``FeatureResult`` dataclass that maps 1:1 to an
``EmailFeature`` DB row.

Extractors
----------
1. urgency_language      — spaCy PhraseMatcher, ≥25 patterns
2. credential_request    — spaCy PhraseMatcher, ≥20 patterns
3. impersonation_language — spaCy PhraseMatcher, brand+action phrases
4. grammar_quality       — TextBlob correction ratio (T-07: NOT language-tool)
5. link_mismatch         — aggregates ``is_mismatch`` flag from email_parser
6. auth_failure          — SPF/DKIM/DMARC result scoring
7. known_bad_url         — PhishTank async check, Redis-cached 24 h (P-06)

Fail-open strategy:  any individual extractor exception is logged at ERROR
level; extraction continues so the Celery chain never stalls.
"""
from __future__ import annotations

import asyncio
import functools
from dataclasses import dataclass
from typing import Any, List

import httpx
import spacy
import structlog
import tldextract
from spacy.matcher import PhraseMatcher
from textblob import TextBlob

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Singleton NLP model
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def get_nlp() -> spacy.language.Language:
    """Load and cache the ``en_core_web_sm`` spaCy model.

    Called once per process; all subsequent calls return the cached object.
    The model is shared by all three spaCy-based extractors.

    Returns:
        Loaded spaCy ``Language`` object.
    """
    return spacy.load("en_core_web_sm")


# ---------------------------------------------------------------------------
# FeatureResult dataclass
# ---------------------------------------------------------------------------


@dataclass
class FeatureResult:
    """Extracted feature record — maps 1:1 to an ``EmailFeature`` ORM row.

    Attributes:
        feature_name:        One of the seven canonical names defined by
                             ``EmailFeature.__table_args__`` CHECK constraint.
        feature_value:       JSON-serialisable evidence dict.
        score_contribution:  Normalised risk contribution 0.0–1.0.
    """

    feature_name: str
    feature_value: dict | Any
    score_contribution: float


# ---------------------------------------------------------------------------
# Phrase pattern lists (module-level constants — built into matchers lazily)
# ---------------------------------------------------------------------------

#: 28 urgency-language phrases (≥25 required by Section 5.1 Task 2).
_URGENCY_PHRASES: list[str] = [
    "verify immediately",
    "account suspended",
    "click now",
    "limited time offer",
    "urgent action required",
    "your account will be closed",
    "update your information",
    "confirm your details",
    "security alert",
    "unauthorized access detected",
    "action required",
    "immediate response",
    "expires today",
    "act now",
    "respond immediately",
    "account will be terminated",
    "failure to respond",
    "suspended due to",
    "must act now",
    "critical update required",
    "your access has been limited",
    "time sensitive",
    "final notice",
    "last warning",
    "account at risk",
    "immediate attention required",
    "24 hours to verify",
    "48 hours to respond",
]

#: 22 credential-harvesting phrases (≥20 required by Section 5.1 Task 2).
_CREDENTIAL_PHRASES: list[str] = [
    "enter your password",
    "provide your credentials",
    "confirm your bank details",
    "social security number",
    "credit card number",
    "login to verify",
    "verify your account",
    "update payment",
    "confirm your credit card",
    "enter your pin",
    "bank account details",
    "username and password",
    "enter your ssn",
    "provide your account number",
    "billing information",
    "payment details",
    "card verification",
    "confirm your identity",
    "identity verification",
    "date of birth",
    "mother maiden name",
    "security question",
]

#: 26 (phrase, canonical_brand) pairs for impersonation detection.
#: Each phrase combines a brand name with an action-request context.
_IMPERSONATION_PHRASE_BRAND_PAIRS: list[tuple[str, str]] = [
    ("paypal account", "PayPal"),
    ("paypal security", "PayPal"),
    ("paypal team", "PayPal"),
    ("microsoft account", "Microsoft"),
    ("microsoft security", "Microsoft"),
    ("microsoft team", "Microsoft"),
    ("apple id", "Apple"),
    ("apple account", "Apple"),
    ("apple support", "Apple"),
    ("amazon account", "Amazon"),
    ("amazon security", "Amazon"),
    ("amazon customer service", "Amazon"),
    ("google account", "Google"),
    ("google security", "Google"),
    ("google team", "Google"),
    ("netflix account", "Netflix"),
    ("netflix support", "Netflix"),
    ("it department", "IT Department"),
    ("your bank", "Bank"),
    ("bank security team", "Bank"),
    ("it support team", "IT Department"),
    ("help desk", "IT Department"),
    ("technical support", "IT Department"),
    ("system administrator", "IT Department"),
    ("account security team", "Security Team"),
    ("it helpdesk", "IT Department"),
]

#: Lookup: matched phrase text → canonical brand name.
_IMPERSONATION_PHRASE_TO_BRAND: dict[str, str] = {
    phrase: brand for phrase, brand in _IMPERSONATION_PHRASE_BRAND_PAIRS
}


# ---------------------------------------------------------------------------
# Cached matcher builders
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _build_urgency_matcher() -> PhraseMatcher:
    """Build and cache the urgency-language PhraseMatcher.

    Uses the model's vocab so the matcher and the input docs share the same
    string store.  Built once on first call; reused on all subsequent calls.
    """
    nlp = get_nlp()
    matcher = PhraseMatcher(nlp.vocab, attr="LOWER")
    matcher.add("URGENCY", [nlp.make_doc(p) for p in _URGENCY_PHRASES])
    return matcher


@functools.lru_cache(maxsize=1)
def _build_credential_matcher() -> PhraseMatcher:
    """Build and cache the credential-request PhraseMatcher."""
    nlp = get_nlp()
    matcher = PhraseMatcher(nlp.vocab, attr="LOWER")
    matcher.add("CREDENTIAL", [nlp.make_doc(p) for p in _CREDENTIAL_PHRASES])
    return matcher


@functools.lru_cache(maxsize=1)
def _build_impersonation_matcher() -> PhraseMatcher:
    """Build and cache the impersonation-language PhraseMatcher."""
    nlp = get_nlp()
    matcher = PhraseMatcher(nlp.vocab, attr="LOWER")
    phrases = [phrase for phrase, _ in _IMPERSONATION_PHRASE_BRAND_PAIRS]
    matcher.add("IMPERSONATION", [nlp.make_doc(p) for p in phrases])
    return matcher


# ---------------------------------------------------------------------------
# Feature 1 — urgency_language
# ---------------------------------------------------------------------------


def _extract_urgency_language(body_text: str) -> FeatureResult:
    """Detect urgency-language patterns via spaCy PhraseMatcher.

    Scans the first 100 000 characters of *body_text*.  Scores by how many
    pattern matches fire, normalised to 3 matches = maximum risk.

    Args:
        body_text: Plain-text email body.

    Returns:
        ``FeatureResult`` with ``patterns_matched`` (deduplicated list) and
        raw ``count`` (total match events including duplicates).
    """
    nlp = get_nlp()
    doc = nlp(body_text[:100_000])
    matcher = _build_urgency_matcher()

    matches = matcher(doc)
    matched_phrases: list[str] = []
    seen: set[str] = set()
    for _match_id, start, end in matches:
        phrase = doc[start:end].text.lower()
        if phrase not in seen:
            seen.add(phrase)
            matched_phrases.append(phrase)

    match_count = len(matches)
    score = min(match_count / 3, 1.0)

    return FeatureResult(
        feature_name="urgency_language",
        feature_value={"patterns_matched": matched_phrases, "count": match_count},
        score_contribution=score,
    )


# ---------------------------------------------------------------------------
# Feature 2 — credential_request
# ---------------------------------------------------------------------------


def _extract_credential_request(body_text: str) -> FeatureResult:
    """Detect credential-harvesting patterns via spaCy PhraseMatcher.

    Any single match yields the maximum score (binary: present or absent).

    Args:
        body_text: Plain-text email body.

    Returns:
        ``FeatureResult`` with deduplicated ``patterns_matched`` list.
    """
    nlp = get_nlp()
    doc = nlp(body_text[:100_000])
    matcher = _build_credential_matcher()

    matches = matcher(doc)
    matched_phrases: list[str] = []
    seen: set[str] = set()
    for _match_id, start, end in matches:
        phrase = doc[start:end].text.lower()
        if phrase not in seen:
            seen.add(phrase)
            matched_phrases.append(phrase)

    score = 1.0 if matches else 0.0

    return FeatureResult(
        feature_name="credential_request",
        feature_value={"patterns_matched": matched_phrases},
        score_contribution=score,
    )


# ---------------------------------------------------------------------------
# Feature 3 — impersonation_language
# ---------------------------------------------------------------------------


def _extract_impersonation_language(body_text: str) -> FeatureResult:
    """Detect brand-name impersonation phrases combined with action requests.

    Each matched phrase is mapped to a canonical brand name (PayPal,
    Microsoft, Apple, etc.).  Duplicate brand detections are deduplicated.
    Scores by how many match events fire, normalised to 2 = maximum.

    Args:
        body_text: Plain-text email body.

    Returns:
        ``FeatureResult`` with deduplicated ``brands_detected`` list.
    """
    nlp = get_nlp()
    doc = nlp(body_text[:100_000])
    matcher = _build_impersonation_matcher()

    matches = matcher(doc)
    brands_seen: set[str] = set()
    brands_detected: list[str] = []
    for _match_id, start, end in matches:
        phrase = doc[start:end].text.lower()
        brand = _IMPERSONATION_PHRASE_TO_BRAND.get(phrase, phrase.title())
        if brand not in brands_seen:
            brands_seen.add(brand)
            brands_detected.append(brand)

    match_count = len(matches)
    score = min(match_count / 2, 1.0)

    return FeatureResult(
        feature_name="impersonation_language",
        feature_value={"brands_detected": brands_detected},
        score_contribution=score,
    )


# ---------------------------------------------------------------------------
# Feature 4 — grammar_quality  (T-07 fix: textblob, NOT language-tool-python)
# ---------------------------------------------------------------------------


def _extract_grammar_quality(body_text: str) -> FeatureResult:
    """Compute spelling/grammar error ratio via TextBlob spell-correction.

    T-07 fix: explicitly uses ``textblob.correct()`` — not
    ``language-tool-python`` which is a heavyweight Java dependency.

    Formula (per Section 5.1 Task 2):
        grammar_score = corrected_word_count / max(word_count, 1)
        score_contribution = min(grammar_score * 2, 1.0)

    Args:
        body_text: Plain-text email body (full length — no truncation).

    Returns:
        ``FeatureResult`` with ``grammar_error_ratio``, ``corrected_words``,
        and ``total_words``.
    """
    words = body_text.split()
    total_words = max(len(words), 1)

    blob = TextBlob(body_text)
    corrected_words = len(
        [w for w in blob.words if str(TextBlob(w).correct()) != w]
    )

    grammar_score = corrected_words / total_words
    score = min(grammar_score * 2, 1.0)

    return FeatureResult(
        feature_name="grammar_quality",
        feature_value={
            "grammar_error_ratio": round(grammar_score, 4),
            "corrected_words": corrected_words,
            "total_words": total_words,
        },
        score_contribution=score,
    )


# ---------------------------------------------------------------------------
# Feature 5 — link_mismatch
# ---------------------------------------------------------------------------


def _extract_link_mismatch(links: list[dict[str, Any]]) -> FeatureResult:
    """Aggregate the pre-computed ``is_mismatch`` flag from parsed links.

    ``is_mismatch`` is set by ``email_parser._extract_links()`` via
    ``tldextract``; this extractor only counts and surfaces the results.

    Score formula:
        score = min(mismatch_count / max(total_links, 1), 1.0)

    Args:
        links: List of link dicts (keys: ``displayed_text``, ``actual_href``,
               ``is_mismatch``).

    Returns:
        ``FeatureResult`` with ``mismatch_count``, ``total_links``, and
        ``mismatched_links`` (displayed + actual for each mismatch).
    """
    total_links = len(links)
    mismatched = [lnk for lnk in links if lnk.get("is_mismatch")]
    mismatch_count = len(mismatched)

    score = min(mismatch_count / max(total_links, 1), 1.0)

    return FeatureResult(
        feature_name="link_mismatch",
        feature_value={
            "mismatch_count": mismatch_count,
            "total_links": total_links,
            "mismatched_links": [
                {
                    "displayed_text": lnk.get("displayed_text", ""),
                    "actual_href": lnk.get("actual_href", ""),
                }
                for lnk in mismatched
            ],
        },
        score_contribution=score,
    )


# ---------------------------------------------------------------------------
# Feature 6 — auth_failure
# ---------------------------------------------------------------------------


def _extract_auth_failure(spf: str, dkim: str, dmarc: str) -> FeatureResult:
    """Score based on SPF, DKIM, and DMARC authentication results.

    Scoring logic (Section 5.1 Task 2):
        - Any ``'fail'`` result  → 1.0 (definite authentication failure)
        - All three ``'none'``   → 0.5 (no authentication present — suspicious)
        - Otherwise              → 0.0 (at least one passing result)

    Args:
        spf:  SPF result string (``'pass'``, ``'fail'``, ``'none'``, etc.).
        dkim: DKIM result string.
        dmarc: DMARC result string.

    Returns:
        ``FeatureResult`` with raw ``spf``, ``dkim``, ``dmarc`` values.
    """
    if any(v == "fail" for v in (spf, dkim, dmarc)):
        score = 1.0
    elif all(v == "none" for v in (spf, dkim, dmarc)):
        score = 0.5
    else:
        score = 0.0

    return FeatureResult(
        feature_name="auth_failure",
        feature_value={"spf": spf, "dkim": dkim, "dmarc": dmarc},
        score_contribution=score,
    )


# ---------------------------------------------------------------------------
# Feature 7 — known_bad_url  (P-06 fix: httpx async, 429/5xx handling)
# ---------------------------------------------------------------------------

_PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/"


async def _check_phishtank(domain: str, redis: Any) -> bool:
    """Query PhishTank for *domain*, using Redis as a 24-hour cache.

    P-06 fix — async httpx with graceful degradation:
        1. Redis GET ``phishtank:{domain}`` — cache hit → return immediately.
        2. POST to PhishTank API (``timeout=3.0`` s).
        3. HTTP 429 → log WARNING ``'PhishTank rate limit hit, skipping {domain}'``,
           return ``False``.
        4. HTTP 5xx → retry ONCE after ``asyncio.sleep(5)``; on second failure
           log WARNING and return ``False``.
        5. HTTP 200 → parse ``results.in_database``; cache result via
           ``Redis.setex(key, 86400, value)``.

    Args:
        domain: Registered domain string (e.g. ``'evil-phishing.com'``).
        redis:  Async Redis client (``redis.asyncio.Redis``).

    Returns:
        ``True`` if PhishTank confirms the domain as phishing;
        ``False`` on any non-conclusive or error outcome.
    """
    cache_key = f"phishtank:{domain}"

    # 1. Redis cache lookup
    cached = await redis.get(cache_key)
    if cached is not None:
        return cached in (b"1", "1")

    # Helper: execute a single POST to the PhishTank API
    async def _do_request() -> httpx.Response:
        async with httpx.AsyncClient(timeout=3.0) as client:
            return await client.post(
                _PHISHTANK_API_URL,
                data={"url": f"http://{domain}/", "format": "json"},
            )

    result = False
    try:
        response = await _do_request()

        # 3. HTTP 429 — rate limited
        if response.status_code == 429:
            log.warning(
                "phishtank_rate_limit",
                message=f"PhishTank rate limit hit, skipping {domain}",
                domain=domain,
            )
            return False

        # 4. HTTP 5xx — retry once after 5 s
        if response.status_code >= 500:
            await asyncio.sleep(5)
            try:
                response = await _do_request()
                if response.status_code >= 500:
                    log.warning(
                        "phishtank_server_error_retry_failed",
                        domain=domain,
                        status=response.status_code,
                    )
                    return False
            except Exception as retry_exc:
                log.warning(
                    "phishtank_retry_request_failed",
                    domain=domain,
                    error=str(retry_exc),
                )
                return False

        # 5. HTTP 200 — parse response
        if response.status_code == 200:
            data = response.json()
            result = bool(data.get("results", {}).get("in_database", False))

    except Exception as exc:
        log.warning(
            "phishtank_request_failed",
            domain=domain,
            error=str(exc),
            exc_type=type(exc).__name__,
        )
        return False

    # 5. Cache result in Redis for 24 h
    await redis.setex(cache_key, 86400, "1" if result else "0")
    return result


async def _extract_known_bad_url(
    links: list[dict[str, Any]],
    redis: Any,
) -> FeatureResult:
    """Check all unique domains from *links* against PhishTank.

    Domains are extracted via ``tldextract`` and deduplicated before querying.
    Each domain is checked via :func:`_check_phishtank` (Redis-cached 24 h).

    Args:
        links: List of link dicts with ``actual_href`` key.
        redis: Async Redis client.

    Returns:
        ``FeatureResult`` with ``bad_domains`` and ``checked_domains`` lists.
        ``score_contribution`` is 1.0 if any domain is confirmed phishing.
    """
    unique_domains: list[str] = []
    seen_domains: set[str] = set()

    for lnk in links:
        url = lnk.get("actual_href", "")
        domain = tldextract.extract(url).registered_domain
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            unique_domains.append(domain)

    bad_domains: list[str] = []
    for domain in unique_domains:
        if await _check_phishtank(domain, redis):
            bad_domains.append(domain)

    score = 1.0 if bad_domains else 0.0

    return FeatureResult(
        feature_name="known_bad_url",
        feature_value={
            "bad_domains": bad_domains,
            "checked_domains": unique_domains,
        },
        score_contribution=score,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def extract_all_features(
    email_dict: dict[str, Any],
    redis: Any,
) -> List[FeatureResult]:
    """Run all 7 feature extractors on *email_dict*.

    Extractors 1–6 are synchronous (CPU-bound); extractor 7 is async
    (network I/O via httpx).  Each is wrapped in its own try/except so a
    single failure never blocks the rest of the chain.

    On any extractor exception: log at ERROR level, skip that feature, and
    return whatever partial results have already been collected.  This
    fail-open strategy ensures the Celery chain continues to
    ``classify_email`` even when one extractor fails.

    Args:
        email_dict: Parsed email fields.  Expected keys:
                    ``body_text``, ``links``, ``spf``, ``dkim``, ``dmarc``.
                    Missing keys default to empty string / empty list.
        redis:      Async Redis client (``redis.asyncio.Redis``).

    Returns:
        List of up to 7 ``FeatureResult`` objects, one per extractor.
        May contain fewer entries if an extractor raised.
    """
    body_text: str = email_dict.get("body_text") or ""
    links: list[dict[str, Any]] = email_dict.get("links") or []
    spf: str = email_dict.get("spf") or "none"
    dkim: str = email_dict.get("dkim") or "none"
    dmarc: str = email_dict.get("dmarc") or "none"

    results: List[FeatureResult] = []

    # Features 1–6: synchronous extractors
    sync_extractors: list[tuple[str, Any]] = [
        ("urgency_language",       lambda: _extract_urgency_language(body_text)),
        ("credential_request",     lambda: _extract_credential_request(body_text)),
        ("impersonation_language", lambda: _extract_impersonation_language(body_text)),
        ("grammar_quality",        lambda: _extract_grammar_quality(body_text)),
        ("link_mismatch",          lambda: _extract_link_mismatch(links)),
        ("auth_failure",           lambda: _extract_auth_failure(spf, dkim, dmarc)),
    ]

    for name, extractor in sync_extractors:
        try:
            results.append(extractor())
        except Exception as exc:
            log.error(
                "feature_extractor_failed",
                feature=name,
                error=str(exc),
                exc_type=type(exc).__name__,
            )

    # Feature 7: async extractor (PhishTank lookup)
    try:
        results.append(await _extract_known_bad_url(links, redis))
    except Exception as exc:
        log.error(
            "feature_extractor_failed",
            feature="known_bad_url",
            error=str(exc),
            exc_type=type(exc).__name__,
        )

    return results
