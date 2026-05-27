"""Section 5.1 Task 1 — Email parsing service (FR-02, UC-02).

Parse raw .eml bytes into a structured dict ready for the analysis pipeline.

Public API
----------
parse_eml(raw_bytes: bytes) -> dict
    Primary parser: :mod:`email.parser.BytesParser` (stdlib).
    Fallback parser: ``mailparser`` library.
    Raises :class:`EmailParseError` if both parsers fail.

Processing steps (Section 5.1 Task 1):
1. Walk MIME tree — prefer ``text/plain`` body; capture ``text/html`` for
   sanitisation; collect attachment metadata (filename, size, mime_type).
   D-04: ``recipient_address`` = primary ``To:`` address only.
2. ``bleach.clean()`` strips disallowed tags/attributes from HTML.
3. Link extraction — HTMLParser subclass for ``<a>`` tags; regex scan of
   plain-text body for bare URLs; mismatch detection via ``tldextract``.
4. ``checkdmarc.parse_email_auth_results()`` for SPF/DKIM/DMARC headers;
   any exception → all three default to ``'none'``.
5. Any unhandled parsing exception → :class:`EmailParseError`.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from typing import Any

import bleach
import mailparser
import structlog
import tldextract

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

#: HTML tags permitted in the sanitised email body shown to the frontend.
ALLOWED_TAGS: list[str] = [
    "a", "b", "p", "br", "ul", "li", "strong", "em", "span",
]

#: Per-tag attribute allow-list used by bleach (NFR-2 XSS prevention).
ALLOWED_ATTRS: dict[str, list[str]] = {"a": ["href"]}

# Bare URL pattern for scanning plain-text bodies.
_URL_RE = re.compile(r"https?://[^\s<>\"{}|\\^`\[\]]+", re.ASCII)

# Valid SPF values accepted by the Email model CheckConstraint.
_SPF_VALID: frozenset[str] = frozenset({"pass", "fail", "none", "neutral", "softfail"})
# Valid DKIM values.
_DKIM_VALID: frozenset[str] = frozenset({"pass", "fail", "none"})
# Valid DMARC values.
_DMARC_VALID: frozenset[str] = frozenset({"pass", "fail", "none"})


# ---------------------------------------------------------------------------
# Public exception
# ---------------------------------------------------------------------------


# Re-export from canonical location so existing imports remain unbroken.
from app.core.exceptions import EmailParseError  # noqa: F401, E402


# ---------------------------------------------------------------------------
# Private helper classes
# ---------------------------------------------------------------------------


class _HrefExtractor(HTMLParser):
    """Minimal ``html.parser.HTMLParser`` subclass that collects ``<a>`` links.

    Collects ``(displayed_text, href)`` pairs from ``<a href="...">`` tags.
    Handles nested data across multiple ``handle_data`` calls.
    """

    def __init__(self) -> None:
        super().__init__()
        self._pairs: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._buf: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        """Capture ``href`` from opening ``<a>`` tags."""
        if tag == "a":
            attrs_dict = dict(attrs)
            href = attrs_dict.get("href")
            if href:
                self._current_href = href
                self._buf = []

    def handle_data(self, data: str) -> None:
        """Accumulate text content while inside an ``<a>`` element."""
        if self._current_href is not None:
            self._buf.append(data)

    def handle_endtag(self, tag: str) -> None:
        """Finalise a link record when ``</a>`` is reached."""
        if tag == "a" and self._current_href is not None:
            self._pairs.append(
                ("".join(self._buf).strip(), self._current_href)
            )
            self._current_href = None
            self._buf = []

    @property
    def pairs(self) -> list[tuple[str, str]]:
        """Return all collected ``(displayed_text, href)`` pairs."""
        return self._pairs


# ---------------------------------------------------------------------------
# Private helpers — decoding
# ---------------------------------------------------------------------------


def _safe_decode(payload: bytes, charset: str) -> str:
    """Decode *payload* bytes with *charset*, replacing undecodable bytes.

    Falls back to UTF-8 if *charset* is unknown or unsupported.

    Args:
        payload: Raw bytes from a MIME part payload.
        charset: MIME ``Content-Type`` charset string (e.g. ``'utf-8'``).

    Returns:
        Decoded string.
    """
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, ValueError):
        return payload.decode("utf-8", errors="replace")


def _decode_header_value(value: str | None) -> str | None:
    """Decode a MIME-encoded header value (``=?utf-8?B?...?=`` style).

    Uses :func:`email.header.make_header` / :func:`email.header.decode_header`
    to handle RFC 2047 encoded-word syntax.  Returns the original string on
    any decoding error.

    Args:
        value: Raw header string or ``None``.

    Returns:
        Decoded string, or ``None`` if *value* was ``None``.
    """
    if value is None:
        return None
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _extract_first_address(header_value: str | None) -> str | None:
    """Extract the primary email address from a ``To:`` header.

    D-04 fix: only the first address is stored; CC/BCC are out of MVP scope.

    Args:
        header_value: Raw ``To:`` header string or ``None``.

    Returns:
        First email address string, or ``None`` if unavailable.
    """
    if not header_value:
        return None
    addresses = getaddresses([header_value])
    if addresses:
        _name, addr = addresses[0]
        return addr or None
    return None


def _parse_date_header(date_str: str | None) -> datetime:
    """Parse an email ``Date:`` header into an aware ``datetime``.

    Falls back to ``datetime.now(UTC)`` if the header is absent or malformed.

    Args:
        date_str: Raw ``Date:`` header string or ``None``.

    Returns:
        Timezone-aware ``datetime`` instance.
    """
    if not date_str:
        return datetime.now(timezone.utc)
    try:
        dt = parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Private helpers — normalisation
# ---------------------------------------------------------------------------


def _normalise_spf(value: str) -> str:
    """Normalise an SPF result string to a value accepted by the DB constraint."""
    v = value.lower().strip()
    return v if v in _SPF_VALID else "none"


def _normalise_dkim(value: str) -> str:
    """Normalise a DKIM result string to ``pass``, ``fail``, or ``none``."""
    v = value.lower().strip()
    return v if v in _DKIM_VALID else "none"


def _normalise_dmarc(value: str) -> str:
    """Normalise a DMARC result string to ``pass``, ``fail``, or ``none``."""
    v = value.lower().strip()
    return v if v in _DMARC_VALID else "none"


# ---------------------------------------------------------------------------
# Private helpers — link extraction & auth results
# ---------------------------------------------------------------------------


def _is_domain_mismatch(displayed: str, actual: str) -> bool:
    """Return ``True`` if the registered domains of *displayed* and *actual* differ.

    Uses :func:`tldextract.extract` to isolate the registered domain portion
    (e.g. ``example.com`` from ``www.example.com``).  Returns ``False`` when
    either domain cannot be extracted (private/invalid TLD).

    Args:
        displayed: Text shown to the user (may be a URL or plain text).
        actual:    The ``href`` attribute value.

    Returns:
        ``True`` if there is a domain mismatch; ``False`` otherwise.
    """
    d = tldextract.extract(displayed).registered_domain
    a = tldextract.extract(actual).registered_domain
    return bool(d and a and d != a)


def _extract_links(
    html_sanitised: str | None,
    body_text: str | None,
) -> list[dict[str, Any]]:
    """Extract and deduplicate links from sanitised HTML and plain-text body.

    Two sources:
    1. ``<a href="...">`` tags in *html_sanitised* (via :class:`_HrefExtractor`).
    2. Bare ``http(s)://`` URLs in *body_text* (via :data:`_URL_RE`).

    Deduplication key: ``"{displayed_text}|{actual_href}"``.

    Args:
        html_sanitised: bleach-cleaned HTML body, or ``None``.
        body_text:      Plain-text body, or ``None``.

    Returns:
        List of dicts with keys ``displayed_text``, ``actual_href``,
        ``is_mismatch``.
    """
    seen: set[str] = set()
    links: list[dict[str, Any]] = []

    # 1. HTML <a> tags
    if html_sanitised:
        extractor = _HrefExtractor()
        extractor.feed(html_sanitised)
        for displayed_text, actual_href in extractor.pairs:
            key = f"{displayed_text}|{actual_href}"
            if key not in seen:
                seen.add(key)
                links.append(
                    {
                        "displayed_text": displayed_text,
                        "actual_href": actual_href,
                        "is_mismatch": _is_domain_mismatch(
                            displayed_text, actual_href
                        ),
                    }
                )

    # 2. Bare URLs in plain-text body
    if body_text:
        for match in _URL_RE.finditer(body_text):
            url = match.group()
            key = f"{url}|{url}"
            if key not in seen:
                seen.add(key)
                links.append(
                    {
                        "displayed_text": url,
                        "actual_href": url,
                        # Same URL on both sides — no domain mismatch possible.
                        "is_mismatch": False,
                    }
                )

    return links


def _parse_auth_results(message: Any) -> tuple[str, str, str]:
    """Call ``checkdmarc.parse_email_auth_results`` and normalise the result.

    Per Section 5.1 Task 1: on *any* exception, defaults all three values
    to ``'none'``.  This makes auth-result parsing non-fatal; a missing or
    malformed ``Authentication-Results:`` header never blocks ingestion.

    Args:
        message: ``email.message.Message`` object, or ``None`` when only the
                 fallback mailparser path was used.

    Returns:
        Tuple of ``(spf, dkim, dmarc)`` strings normalised to valid DB values.
    """
    if message is None:
        return "none", "none", "none"

    try:
        import checkdmarc  # noqa: PLC0415 (intentional lazy import)

        results: dict[str, Any] = checkdmarc.parse_email_auth_results(message)

        def _first_result(field: Any) -> str:
            """Extract the result string from a checkdmarc field value."""
            if isinstance(field, list) and field:
                item = field[0]
                return item.get("result", "none") if isinstance(item, dict) else str(item)
            if isinstance(field, dict):
                return field.get("result", "none")
            return str(field) if field else "none"

        spf = _normalise_spf(_first_result(results.get("spf", [])))
        dkim = _normalise_dkim(_first_result(results.get("dkim", [])))
        dmarc = _normalise_dmarc(_first_result(results.get("dmarc", [])))
        return spf, dkim, dmarc

    except Exception as exc:
        log.warning(
            "checkdmarc_auth_results_failed",
            error=str(exc),
            exc_type=type(exc).__name__,
        )
        return "none", "none", "none"


# ---------------------------------------------------------------------------
# Private helpers — per-parser extraction
# ---------------------------------------------------------------------------


def _extract_from_stdlib_message(message: Any) -> dict[str, Any]:
    """Extract raw fields from a stdlib ``email.message.Message`` object.

    Walks the MIME tree once, collecting:
    - ``text/plain`` body (first occurrence)
    - ``text/html`` body (first occurrence, stored under ``_html_raw``)
    - Attachment metadata (no binary content — data minimisation)

    The special ``_html_raw`` and ``_message`` keys are consumed by
    :func:`parse_eml` before constructing the final return dict.

    Args:
        message: Parsed ``email.message.Message`` from :class:`BytesParser`.

    Returns:
        Raw field dict including private ``_html_raw`` and ``_message`` keys.
    """
    body_text: str | None = None
    html_raw: str | None = None
    attachment_metadata: list[dict[str, Any]] = []

    for part in message.walk():
        content_type: str = part.get_content_type()
        disposition: str = str(part.get_content_disposition() or "").lower()
        filename: str | None = part.get_filename()

        # Skip multipart container parts — walk() descends into them.
        if content_type.startswith("multipart/"):
            continue

        # Classify the part as an attachment if it is explicitly marked so,
        # or if it carries a filename but is not a plain-text / HTML body.
        is_attachment = disposition == "attachment" or (
            filename is not None
            and content_type not in ("text/plain", "text/html")
        )

        if is_attachment:
            payload = part.get_payload(decode=True)
            attachment_metadata.append(
                {
                    "filename": filename or "unknown",
                    "size": len(payload) if payload else 0,
                    "mime_type": content_type,
                }
            )
            continue

        if content_type == "text/plain" and body_text is None:
            payload = part.get_payload(decode=True)
            if payload:
                charset = part.get_content_charset() or "utf-8"
                body_text = _safe_decode(payload, charset)

        elif content_type == "text/html" and html_raw is None:
            payload = part.get_payload(decode=True)
            if payload:
                charset = part.get_content_charset() or "utf-8"
                html_raw = _safe_decode(payload, charset)

    return {
        "sender": _decode_header_value(message.get("From")),
        "reply_to": _decode_header_value(message.get("Reply-To")),
        "recipient_address": _extract_first_address(message.get("To")),
        "subject": _decode_header_value(message.get("Subject")),
        "body_text": body_text,
        "attachment_metadata": attachment_metadata,
        "received_at": _parse_date_header(message.get("Date")),
        # Private keys consumed by parse_eml() before returning.
        "_html_raw": html_raw,
        "_message": message,
    }


def _extract_from_mailparser(raw_bytes: bytes) -> dict[str, Any]:
    """Fallback extraction using the ``mailparser`` library.

    Called only when :class:`BytesParser` fails.  Returns the same field
    structure as :func:`_extract_from_stdlib_message` including private keys
    (``_html_raw`` is set; ``_message`` is ``None`` because the stdlib
    ``email.message.Message`` is not available in this path).

    Args:
        raw_bytes: Raw email bytes.

    Returns:
        Raw field dict with private ``_html_raw`` and ``_message`` keys.
    """
    msg = mailparser.parse_from_bytes(raw_bytes)
    mail: dict[str, Any] = msg.mail

    def _first_pair_address(key: str) -> str | None:
        """Return the address part of the first ``(name, address)`` tuple."""
        pairs: list[tuple[str, str]] = mail.get(key, [])
        if pairs:
            _name, addr = pairs[0]
            return addr or None
        return None

    def _format_sender(key: str) -> str | None:
        """Format the sender as ``'Name <addr>'`` or just ``'addr'``."""
        pairs: list[tuple[str, str]] = mail.get(key, [])
        if not pairs:
            return None
        name, addr = pairs[0]
        return f"{name} <{addr}>" if name else addr

    # Collect attachment metadata without storing binary payloads.
    attachment_metadata: list[dict[str, Any]] = []
    for att in msg.attachments or []:
        payload = att.get("payload", b"")
        if isinstance(payload, str):
            payload = payload.encode("utf-8", errors="replace")
        attachment_metadata.append(
            {
                "filename": att.get("filename", "unknown") or "unknown",
                "size": len(payload) if payload else 0,
                "mime_type": att.get("mail_content_type", "application/octet-stream"),
            }
        )

    # mailparser.date is a naive datetime; normalise to UTC-aware.
    raw_date: datetime | None = msg.date
    if isinstance(raw_date, datetime):
        received_at = (
            raw_date
            if raw_date.tzinfo is not None
            else raw_date.replace(tzinfo=timezone.utc)
        )
    else:
        received_at = datetime.now(timezone.utc)

    return {
        "sender": _format_sender("from"),
        "reply_to": _first_pair_address("reply-to"),
        "recipient_address": _first_pair_address("to"),
        "subject": mail.get("subject"),
        "body_text": "\n".join(msg.text_plain) if msg.text_plain else None,
        "attachment_metadata": attachment_metadata,
        "received_at": received_at,
        # Private keys consumed by parse_eml() before returning.
        "_html_raw": "\n".join(msg.text_html) if msg.text_html else None,
        "_message": None,  # No stdlib message object in the fallback path.
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_eml(raw_bytes: bytes) -> dict[str, Any]:
    """Parse raw ``.eml`` bytes into a structured dict for the analysis pipeline.

    Parsing steps (Section 5.1 Task 1):

    1. **MIME walk** — :class:`~email.parser.BytesParser` (primary) or
       ``mailparser`` (fallback).  Extracts sender, reply_to,
       recipient_address (primary ``To:`` only — D-04 fix), subject,
       body_text (``text/plain`` preferred), html_raw (``text/html``),
       attachment_metadata, received_at.
    2. **HTML sanitisation** — :func:`bleach.clean` strips all tags and
       attributes not in :data:`ALLOWED_TAGS` / :data:`ALLOWED_ATTRS`.
    3. **Link extraction** — :class:`_HrefExtractor` parses sanitised HTML
       for ``<a>`` tags; :data:`_URL_RE` scans plain-text body for bare URLs.
       Each link carries ``is_mismatch`` (registered-domain comparison via
       :func:`tldextract.extract`).
    4. **Auth results** — ``checkdmarc.parse_email_auth_results()`` provides
       SPF, DKIM, DMARC; any exception → all default to ``'none'``.

    Args:
        raw_bytes: Complete raw email file contents (RFC 2822 / MIME).

    Returns:
        Dict with keys: ``sender``, ``reply_to``, ``recipient_address``,
        ``subject``, ``body_text``, ``html_sanitised``, ``links``,
        ``attachment_metadata``, ``spf``, ``dkim``, ``dmarc``,
        ``received_at``.

    Raises:
        EmailParseError: If both primary (BytesParser) and fallback
            (mailparser) parsers raise an exception.
    """
    # ── Step 1: Parse raw bytes ──────────────────────────────────────────────
    fields: dict[str, Any]
    try:
        stdlib_message = BytesParser().parsebytes(raw_bytes)
        fields = _extract_from_stdlib_message(stdlib_message)
    except Exception as primary_exc:
        log.warning(
            "email_parse_primary_failed",
            parser="BytesParser",
            error=str(primary_exc),
            exc_type=type(primary_exc).__name__,
        )
        try:
            fields = _extract_from_mailparser(raw_bytes)
        except Exception as fallback_exc:
            raise EmailParseError(str(fallback_exc)) from fallback_exc

    # Pop internal-only keys so they are not returned to callers.
    html_raw: str | None = fields.pop("_html_raw", None)
    stdlib_message_obj: Any = fields.pop("_message", None)

    # ── Step 2: HTML sanitisation ────────────────────────────────────────────
    html_sanitised: str | None = (
        bleach.clean(
            html_raw,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRS,
            strip=True,
        )
        if html_raw
        else None
    )

    # ── Step 3: Link extraction ──────────────────────────────────────────────
    links = _extract_links(html_sanitised, fields.get("body_text"))

    # ── Step 4: Email authentication results ─────────────────────────────────
    spf, dkim, dmarc = _parse_auth_results(stdlib_message_obj)

    return {
        **fields,
        "html_sanitised": html_sanitised,
        "links": links,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
    }
