"""Analysis pipeline Celery tasks (Section 8, FR-02, FR-03, FR-04, UC-02).

Queues:
    analysis -- parse_and_sanitise, extract_features, classify_email,
                generate_explanation, apply_outcome
    imap     -- imap_poll_all_orgs (triggered by Celery Beat every 60 s)

Task chain (Section 5.1 Tasks 1-5, UC-02):

    parse_and_sanitise(email_id)           # .si() — explicit email_id
        -> extract_features(email_id)      # .s()  — receives email_id via return value
        -> classify_email(email_id)
        -> generate_explanation(email_id)
        -> apply_outcome(email_id)

Call :func:`fire_analysis_chain` from routers after INSERTing the Email row.
Each task re-loads state from the DB using email_id and returns email_id to
the next task.  No large payloads traverse the chain.
"""
from __future__ import annotations

import functools
import json
import re
import uuid

import structlog
from celery import shared_task

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# FIXED feature order — must match ml/train.py and ml_classifier.py exactly.
# Never reorder without retraining the model.
_FEATURE_ORDER: list[str] = [
    "urgency_language",
    "credential_request",
    "link_mismatch",
    "impersonation_language",
    "auth_failure",
    "grammar_quality",
    "known_bad_url",
]

# Bare URL regex — same pattern as email_parser._URL_RE, used for paste link extraction.
_BARE_URL_RE = re.compile(r"https?://[^\s<>\"{}|\\^`\[\]]+", re.ASCII)


# ---------------------------------------------------------------------------
# Shared sync-session factory (cached per worker process)
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _sync_session_factory():
    """Return a cached SQLAlchemy sessionmaker backed by the psycopg2 engine.

    ``lru_cache`` ensures the Engine (and its connection pool) is created once
    per Celery worker process, not on every task invocation.
    """
    from sqlalchemy.orm import sessionmaker  # noqa: PLC0415

    from app.core.database import get_sync_engine  # noqa: PLC0415

    return sessionmaker(bind=get_sync_engine(), autocommit=False, autoflush=False)


def _make_sync_session():
    """Create a fresh synchronous SQLAlchemy session.

    Caller is responsible for ``session.commit()`` / ``session.rollback()``
    and ``session.close()``.  Psycopg2 (sync) is required here — asyncpg
    only works inside a running asyncio event loop.
    """
    return _sync_session_factory()()


# ---------------------------------------------------------------------------
# SSE publish helper
# ---------------------------------------------------------------------------


def _publish_sse_event(org_id: uuid.UUID, event_type: str, data: dict) -> None:
    """Publish an event to the org SSE channel via synchronous Redis pub/sub.

    Also writes to the Redis stream for Last-Event-ID replay support
    (GET /events replays recent stream entries on connect).

    Args:
        org_id:     Organisation UUID — determines the pub/sub channel.
        event_type: SSE event type string (e.g. ``'scan_complete'``).
        data:       JSON-serialisable payload dict.
    """
    try:
        import redis as _sync_redis  # noqa: PLC0415

        from app.core.config import settings  # noqa: PLC0415

        r = _sync_redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
        payload = json.dumps({"type": event_type, "data": data})
        channel = f"org:{org_id}:events"
        r.publish(channel, payload)
        # XADD for replay — capped at 200 entries (Section 4.10 MAXLEN 200).
        r.xadd(f"org:{org_id}:stream", {"data": payload}, maxlen=200, approximate=True)
        r.close()
    except Exception as exc:
        log.warning(
            "sse_publish_failed",
            event_type=event_type,
            org_id=str(org_id),
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# Shared on-failure handler
# ---------------------------------------------------------------------------


def _on_task_failure(email_id: str, task_name: str, exc: Exception) -> None:
    """Mark email as failed, write audit log, and publish scan_complete SSE.

    Best-effort: any inner exception is caught and logged so this helper
    never masks the original task failure.

    Args:
        email_id:  UUID string of the failed Email row.
        task_name: Celery task name for the audit log detail field.
        exc:       The exception that caused the failure.
    """
    from sqlalchemy import select, update  # noqa: PLC0415

    from app.models.audit_log import AuditLog  # noqa: PLC0415
    from app.models.email import Email  # noqa: PLC0415

    email_uuid = uuid.UUID(email_id)
    session = _make_sync_session()
    org_id: uuid.UUID | None = None

    try:
        email_row = session.execute(
            select(Email).where(Email.id == email_uuid)
        ).scalar_one_or_none()
        if email_row:
            org_id = email_row.org_id

        session.execute(
            update(Email.__table__)
            .where(Email.__table__.c.id == email_uuid)
            .values(status="failed")
        )
        if org_id:
            session.add(
                AuditLog(
                    org_id=org_id,
                    action="task_failed",
                    target_type="email",
                    target_id=email_uuid,
                    detail={"task": task_name, "error": str(exc)[:500]},
                )
            )
        session.commit()
    except Exception as inner_exc:
        log.error(
            "on_task_failure_db_error",
            email_id=email_id,
            task_name=task_name,
            error=str(inner_exc),
        )
        try:
            session.rollback()
        except Exception:
            pass
    finally:
        session.close()

    if org_id:
        _publish_sse_event(
            org_id,
            "scan_complete",
            {"email_id": email_id, "status": "failed"},
        )


# ---------------------------------------------------------------------------
# Public chain launcher — called by routers
# ---------------------------------------------------------------------------


def fire_analysis_chain(email_id: str) -> None:
    """Fire the 5-task analysis pipeline for *email_id*.

    Called by the upload and paste routers immediately after INSERTing the
    Email row.  parse_and_sanitise receives email_id explicitly via ``.si()``;
    each subsequent task uses ``.s()`` so it receives email_id as the return
    value from the previous task.  Each task re-loads state from the DB and
    passes only the lightweight email_id string to the next step — no large
    payloads (body text, parsed data, feature vectors) traverse the chain.

    Errors in dispatching are caught and logged at WARNING level so a
    Celery/Redis outage never blocks the HTTP response.

    Args:
        email_id: UUID string of the Email row to process.
    """
    try:
        (
            parse_and_sanitise.si(email_id)
            | extract_features.s()
            | classify_email.s()
            | generate_explanation.s()
            | apply_outcome.s()
        ).apply_async()
    except Exception as exc:
        log.warning(
            "fire_analysis_chain_dispatch_failed",
            email_id=email_id,
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# Task 1: parse_and_sanitise  (Section 5.1 Task 1)
# ---------------------------------------------------------------------------


@shared_task(bind=True, max_retries=2, default_retry_delay=10, queue="analysis")
def parse_and_sanitise(self, email_id: str) -> str:
    """Parse raw bytes / paste source and persist all header + body fields.

    Ingestion-source dispatch:

    * ``upload`` / ``imap`` — reads ``/tmp/{email_id}.eml``, calls
      :func:`~app.services.email_parser.parse_eml`, and UPDATE-s all Email
      fields (sender, reply_to, recipient_address, subject, body_text,
      html_sanitised, links, attachment_metadata, spf, dkim, dmarc,
      received_at).

    * ``paste`` — body_text is already stored; MIME parsing is skipped.
      Bare URLs are extracted from body_text via :data:`_BARE_URL_RE` and
      saved to the links column.

    On :class:`~app.services.email_parser.EmailParseError`:
        Email.status is set to ``'failed'``, a ``task_failed`` audit log
        entry is written, a ``scan_complete {status: 'failed'}`` SSE event
        is published, and the exception is re-raised to stop the chain.

    On other exceptions:
        Retried up to ``max_retries=2`` times.  After exhausting retries the
        same failure path (failed + audit + SSE) is executed before re-raising.

    Args:
        email_id: UUID string of the Email row to process.

    Returns:
        *email_id* — passed to :func:`extract_features` via the chain.
    """
    from celery.exceptions import MaxRetriesExceededError  # noqa: PLC0415
    from sqlalchemy import select, update  # noqa: PLC0415

    from app.models.email import Email  # noqa: PLC0415
    from app.services.email_parser import EmailParseError, parse_eml  # noqa: PLC0415

    email_uuid = uuid.UUID(email_id)
    session = _make_sync_session()

    try:
        email = session.execute(
            select(Email).where(Email.id == email_uuid)
        ).scalar_one_or_none()

        if email is None:
            log.error("parse_and_sanitise_email_not_found", email_id=email_id)
            return email_id

        source = email.ingestion_source

        if source == "paste":
            # Body text already stored — skip MIME parsing.
            raw_text = email.body_text or ""
            seen: set[str] = set()
            links: list[dict] = []
            for url in _BARE_URL_RE.findall(raw_text):
                if url not in seen:
                    seen.add(url)
                    links.append(
                        {"displayed_text": url, "actual_href": url, "is_mismatch": False}
                    )
            session.execute(
                update(Email.__table__)
                .where(Email.__table__.c.id == email_uuid)
                .values(links=links)
            )
            session.commit()
            log.info(
                "parse_and_sanitise_done",
                email_id=email_id,
                source="paste",
                n_links=len(links),
            )

        else:
            # upload or imap: raw bytes saved to /tmp/{email_id}.eml
            tmp_path = f"/tmp/{email_id}.eml"
            try:
                with open(tmp_path, "rb") as fh:
                    raw_bytes = fh.read()
            except OSError as os_exc:
                raise EmailParseError(
                    f"Cannot read temp file '{tmp_path}': {os_exc}"
                ) from os_exc

            parsed = parse_eml(raw_bytes)

            session.execute(
                update(Email.__table__)
                .where(Email.__table__.c.id == email_uuid)
                .values(
                    sender=parsed.get("sender"),
                    reply_to=parsed.get("reply_to"),
                    recipient_address=parsed.get("recipient_address"),
                    subject=parsed.get("subject"),
                    body_text=parsed.get("body_text"),
                    html_sanitised=parsed.get("html_sanitised"),
                    links=parsed.get("links", []),
                    attachment_metadata=parsed.get("attachment_metadata", []),
                    spf=parsed.get("spf"),
                    dkim=parsed.get("dkim"),
                    dmarc=parsed.get("dmarc"),
                    received_at=parsed.get("received_at"),
                )
            )
            session.commit()
            log.info("parse_and_sanitise_done", email_id=email_id, source=source)

        return email_id

    except EmailParseError as exc:
        # Unrecoverable — retry would not help for a malformed email.
        session.rollback()
        log.error("parse_and_sanitise_parse_error", email_id=email_id, error=str(exc))
        _on_task_failure(email_id, "parse_and_sanitise", exc)
        raise  # stops the chain

    except Exception as exc:
        session.rollback()
        log.warning(
            "parse_and_sanitise_error",
            email_id=email_id,
            error=str(exc),
            exc_type=type(exc).__name__,
        )
        try:
            raise self.retry(exc=exc, countdown=10)
        except MaxRetriesExceededError:
            _on_task_failure(email_id, "parse_and_sanitise", exc)
            raise

    finally:
        session.close()


# ---------------------------------------------------------------------------
# Task 2: extract_features  (Section 5.1 Task 2)
# ---------------------------------------------------------------------------


@shared_task(bind=True, max_retries=2, default_retry_delay=10, queue="analysis")
def extract_features(self, email_id: str) -> str:
    """Extract NLP and structural features and persist EmailFeature rows.

    Calls :func:`~app.services.nlp_pipeline.extract_all_features` with the
    email dict built from the Email row.  All 7 EmailFeature rows are bulk-
    INSERTed in a single transaction; any existing rows for this email are
    deleted first (idempotent re-runs).

    On NLP exception:
        Logs ERROR and continues — the Random Forest classifier handles
        missing features by treating them as 0.0 (lowest risk contribution).

    On unexpected exception:
        Retried up to ``max_retries=2`` times; after exhausting retries
        the email is marked as ``'failed'`` via :func:`_on_task_failure`.

    Args:
        email_id: UUID string of the Email row to process.

    Returns:
        *email_id* — passed to :func:`classify_email` via the chain.
    """
    import asyncio as _asyncio  # noqa: PLC0415

    import redis.asyncio as _aioredis  # noqa: PLC0415
    from celery.exceptions import MaxRetriesExceededError  # noqa: PLC0415
    from sqlalchemy import delete, select  # noqa: PLC0415

    from app.core.config import settings  # noqa: PLC0415
    from app.models.email import Email  # noqa: PLC0415
    from app.models.email_feature import EmailFeature  # noqa: PLC0415
    from app.services.nlp_pipeline import extract_all_features  # noqa: PLC0415

    email_uuid = uuid.UUID(email_id)
    session = _make_sync_session()

    try:
        email = session.execute(
            select(Email).where(Email.id == email_uuid)
        ).scalar_one_or_none()

        if email is None:
            log.error("extract_features_email_not_found", email_id=email_id)
            return email_id

        email_dict = {
            "body_text": email.body_text or "",
            "links": email.links or [],
            "spf": email.spf,
            "dkim": email.dkim,
            "dmarc": email.dmarc,
        }

        # Run async extract_all_features inside a fresh event loop.
        # Celery workers are synchronous; asyncio.run() creates a new loop
        # for the duration of this call then tears it down.
        async def _run_nlp():
            r = await _aioredis.from_url(settings.REDIS_URL)
            try:
                return await extract_all_features(email_dict, r)
            finally:
                await r.aclose()

        try:
            features = _asyncio.run(_run_nlp())
        except Exception as nlp_exc:
            # NLP failure is non-fatal — classify_email handles 0-feature case.
            log.error(
                "extract_features_nlp_failed",
                email_id=email_id,
                error=str(nlp_exc),
                exc_type=type(nlp_exc).__name__,
            )
            return email_id

        # Bulk INSERT all features in ONE transaction (delete first for idempotency).
        session.execute(
            delete(EmailFeature.__table__).where(
                EmailFeature.__table__.c.email_id == email_uuid
            )
        )
        for feat in features:
            fv = (
                feat.feature_value
                if isinstance(feat.feature_value, dict)
                else {"value": str(feat.feature_value)}
            )
            session.add(
                EmailFeature(
                    email_id=email_uuid,
                    feature_name=feat.feature_name,
                    feature_value=fv,
                    score_contribution=feat.score_contribution,
                )
            )
        session.commit()
        log.info("extract_features_done", email_id=email_id, n_features=len(features))
        return email_id

    except Exception as exc:
        session.rollback()
        log.warning(
            "extract_features_error",
            email_id=email_id,
            error=str(exc),
            exc_type=type(exc).__name__,
        )
        try:
            raise self.retry(exc=exc, countdown=10)
        except MaxRetriesExceededError:
            _on_task_failure(email_id, "extract_features", exc)
            raise

    finally:
        session.close()


# ---------------------------------------------------------------------------
# Task 3: classify_email  (Section 5.1 Task 3)
# ---------------------------------------------------------------------------


def _classify_email_inner(email_id: str) -> str:
    """Inner sync worker for classify_email — owns the DB session lifecycle.

    Separated from the Celery task wrapper so that
    :class:`~app.services.ml_classifier.ModelNotFoundError` can propagate
    cleanly to the retry handler without conflicting with Celery's own
    :class:`~celery.exceptions.Retry` exception flow.

    Args:
        email_id: UUID string of the Email row to classify.

    Returns:
        *email_id* — for the chain to pass to :func:`generate_explanation`.

    Raises:
        ModelNotFoundError: When ``ml/model.pkl`` is absent (caller retries).
        Exception: Any other unexpected error (caller logs and re-raises).
    """
    from sqlalchemy import select  # noqa: PLC0415
    from sqlalchemy.dialects.postgresql import insert as pg_insert  # noqa: PLC0415

    from app.core.config import settings  # noqa: PLC0415
    from app.models.analysis_result import AnalysisResult  # noqa: PLC0415
    from app.models.email import Email  # noqa: PLC0415
    from app.models.email_feature import EmailFeature  # noqa: PLC0415
    from app.models.organisation import Organisation  # noqa: PLC0415
    from app.services import ml_classifier  # noqa: PLC0415
    from app.services.ml_classifier import ModelNotFoundError  # noqa: PLC0415  # noqa: F401

    email_uuid = uuid.UUID(email_id)
    session = _make_sync_session()

    try:
        email = session.execute(
            select(Email).where(Email.id == email_uuid)
        ).scalar_one_or_none()
        if email is None:
            log.error("classify_email_not_found", email_id=email_id)
            return email_id

        org = session.execute(
            select(Organisation).where(Organisation.id == email.org_id)
        ).scalar_one_or_none()
        suspicious_threshold: int = org.suspicious_threshold if org else 30
        phishing_threshold: int = org.phishing_threshold if org else 80

        features = list(
            session.execute(
                select(EmailFeature).where(EmailFeature.email_id == email_uuid)
            ).scalars()
        )

        feature_map: dict[str, float] = {
            f.feature_name: float(f.score_contribution) for f in features
        }
        feature_vector: list[float] = [
            feature_map.get(name, 0.0) for name in _FEATURE_ORDER
        ]

        # Raises ModelNotFoundError if ml/model.pkl is absent.
        clf_result = ml_classifier.classify(feature_vector)
        risk_score: int = clf_result["risk_score"]

        if risk_score < suspicious_threshold:
            classification = "safe"
        elif risk_score < phishing_threshold:
            classification = "suspicious"
        else:
            classification = "phishing"

        sorted_feats = sorted(
            features, key=lambda f: f.score_contribution, reverse=True
        )[:3]
        top_features_json: list[dict] = [
            {
                "name": f.feature_name,
                "value": float(f.score_contribution),
                "score_contribution": float(f.score_contribution),
            }
            for f in sorted_feats
        ]

        stmt = (
            pg_insert(AnalysisResult.__table__)
            .values(
                email_id=email_uuid,
                classification=classification,
                risk_score=risk_score,
                model_version=settings.MODEL_VERSION,
                threshold_applied_suspicious=suspicious_threshold,
                threshold_applied_phishing=phishing_threshold,
                top_features=top_features_json,
            )
            .on_conflict_do_update(
                constraint="uq_analysis_result_email_id",
                set_={
                    "classification": classification,
                    "risk_score": risk_score,
                    "model_version": settings.MODEL_VERSION,
                    "threshold_applied_suspicious": suspicious_threshold,
                    "threshold_applied_phishing": phishing_threshold,
                    "top_features": top_features_json,
                },
            )
        )
        session.execute(stmt)
        session.commit()

        log.info(
            "classify_email_done",
            email_id=email_id,
            classification=classification,
            risk_score=risk_score,
            n_features=len(features),
        )
        return email_id

    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _mark_email_failed(email_id: str, org_id: uuid.UUID, reason: str) -> None:
    """Set Email.status = 'failed', write audit log, publish SSE.

    Best-effort: errors are caught and logged so the audit/SSE failure never
    masks the original classification failure.

    Args:
        email_id: UUID string of the Email to mark failed.
        org_id:   Organisation UUID for the audit log row.
        reason:   Short description of the failure cause.
    """
    from sqlalchemy import update  # noqa: PLC0415

    from app.models.audit_log import AuditLog  # noqa: PLC0415
    from app.models.email import Email  # noqa: PLC0415

    email_uuid = uuid.UUID(email_id)
    session = _make_sync_session()
    try:
        session.execute(
            update(Email.__table__)
            .where(Email.__table__.c.id == email_uuid)
            .values(status="failed")
        )
        session.add(
            AuditLog(
                org_id=org_id,
                action="task_failed",
                target_type="email",
                target_id=email_uuid,
                detail={"task": "classify_email", "reason": reason},
            )
        )
        session.commit()
    except Exception as exc:
        log.error("mark_email_failed_error", email_id=email_id, error=str(exc))
        try:
            session.rollback()
        except Exception:
            pass
    finally:
        session.close()

    _publish_sse_event(
        org_id,
        "scan_complete",
        {"email_id": email_id, "status": "failed"},
    )


@shared_task(bind=True, max_retries=1, queue="analysis")
def classify_email(self, email_id: str) -> str:
    """Run the Random Forest classifier and record the AnalysisResult (FR-03).

    Reads EmailFeature rows written by :func:`extract_features`, builds a
    7-element feature vector in :data:`_FEATURE_ORDER`, and calls
    :func:`~app.services.ml_classifier.classify`.  The AnalysisResult is
    upserted via ``ON CONFLICT DO UPDATE`` for idempotency.

    Retry behaviour:
        :class:`~app.services.ml_classifier.ModelNotFoundError` is retried
        once after 30 s.  After max_retries the email is marked
        ``'failed'`` via :func:`_mark_email_failed`.

    Args:
        email_id: UUID string of the Email row to classify.

    Returns:
        *email_id* — passed to :func:`generate_explanation` via the chain.
    """
    from celery.exceptions import MaxRetriesExceededError  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    from app.models.email import Email  # noqa: PLC0415
    from app.services.ml_classifier import ModelNotFoundError  # noqa: PLC0415

    try:
        return _classify_email_inner(email_id)

    except ModelNotFoundError as model_exc:
        log.warning(
            "classify_email_model_not_found",
            email_id=email_id,
            error=str(model_exc),
        )
        try:
            raise self.retry(exc=model_exc, countdown=30)
        except MaxRetriesExceededError:
            log.error("classify_email_max_retries_exceeded", email_id=email_id)
            org_id: uuid.UUID | None = None
            try:
                session = _make_sync_session()
                try:
                    row = session.execute(
                        select(Email).where(Email.id == uuid.UUID(email_id))
                    ).scalar_one_or_none()
                    org_id = row.org_id if row else None
                finally:
                    session.close()
            except Exception as lookup_exc:
                log.error(
                    "classify_email_org_lookup_failed",
                    email_id=email_id,
                    error=str(lookup_exc),
                )
            if org_id is not None:
                _mark_email_failed(email_id, org_id, "ModelNotFoundError")
            else:
                log.error(
                    "classify_email_cannot_mark_failed_no_org",
                    email_id=email_id,
                )
            raise

    except Exception as exc:
        log.error(
            "classify_email_failed",
            email_id=email_id,
            error=str(exc),
            exc_type=type(exc).__name__,
        )
        _on_task_failure(email_id, "classify_email", exc)
        raise


# ---------------------------------------------------------------------------
# Task 4: generate_explanation  (Section 5.1 Task 4)
# ---------------------------------------------------------------------------


@shared_task(bind=True, max_retries=2, default_retry_delay=10, queue="analysis")
def generate_explanation(self, email_id: str) -> str:
    """Call the Claude API to produce a plain-English explanation (FR-04).

    Loads ``AnalysisResult.top_features`` and ``Email`` header fields, then
    calls :func:`~app.services.claude_service.generate_explanation` via
    ``asyncio.run()``.  The result is persisted to
    ``analysis_results.explanation``.

    Retry behaviour:
        Retried up to ``max_retries=2`` (countdown=10) on any exception.
        After exhausting retries the :data:`~app.services.claude_service.RULE_TEXT_TEMPLATES`
        fallback is written and the task returns *without* raising —
        explanation is a non-critical path that must not block :func:`apply_outcome`.

    Args:
        email_id: UUID string of the Email row to explain.

    Returns:
        *email_id* — passed to :func:`apply_outcome` via the chain.
    """
    import asyncio as _asyncio  # noqa: PLC0415

    from celery.exceptions import MaxRetriesExceededError  # noqa: PLC0415
    from sqlalchemy import select as _select, update as _update  # noqa: PLC0415

    from app.models.analysis_result import AnalysisResult  # noqa: PLC0415
    from app.models.email import Email  # noqa: PLC0415
    from app.services import claude_service  # noqa: PLC0415

    email_uuid = uuid.UUID(email_id)
    session = _make_sync_session()
    top_features: list = []

    try:
        analysis = session.execute(
            _select(AnalysisResult).where(AnalysisResult.email_id == email_uuid)
        ).scalar_one_or_none()

        if analysis is None:
            log.warning("generate_explanation_no_analysis", email_id=email_id)
            return email_id

        top_features = analysis.top_features or []

        email = session.execute(
            _select(Email).where(Email.id == email_uuid)
        ).scalar_one_or_none()
        sender = (email.sender or "") if email else ""
        subject = (email.subject or "") if email else ""

        explanation = _asyncio.run(
            claude_service.generate_explanation(top_features, sender, subject)
        )

        session.execute(
            _update(AnalysisResult.__table__)
            .where(AnalysisResult.__table__.c.email_id == email_uuid)
            .values(explanation=explanation)
        )
        session.commit()
        log.info("generate_explanation_done", email_id=email_id)
        return email_id

    except Exception as exc:
        session.rollback()
        log.warning(
            "generate_explanation_failed",
            email_id=email_id,
            error=str(exc),
            exc_type=type(exc).__name__,
        )
        try:
            raise self.retry(exc=exc, countdown=10)
        except MaxRetriesExceededError:
            # Non-critical — write rule-text fallback and continue the chain.
            key = top_features[0].get("name", "default") if top_features else "default"
            fallback = claude_service.RULE_TEXT_TEMPLATES.get(
                key, claude_service.RULE_TEXT_TEMPLATES["default"]
            )
            fallback_session = _make_sync_session()
            try:
                from sqlalchemy import update as _upd  # noqa: PLC0415

                fallback_session.execute(
                    _upd(AnalysisResult.__table__)
                    .where(AnalysisResult.__table__.c.email_id == email_uuid)
                    .values(explanation=fallback)
                )
                fallback_session.commit()
                log.info(
                    "generate_explanation_fallback_written",
                    email_id=email_id,
                    key=key,
                )
            except Exception as fb_exc:
                log.error(
                    "generate_explanation_fallback_write_failed",
                    email_id=email_id,
                    error=str(fb_exc),
                )
                try:
                    fallback_session.rollback()
                except Exception:
                    pass
            finally:
                fallback_session.close()
            # Return email_id so apply_outcome still runs.
            return email_id

    finally:
        session.close()


# ---------------------------------------------------------------------------
# Task 5: apply_outcome
# ---------------------------------------------------------------------------


@shared_task(bind=True, max_retries=2, default_retry_delay=10, queue="analysis")
def apply_outcome(self, email_id: str) -> str:
    """Route email and publish SSE by delegating to quarantine_service (FR-05).

    Calls :func:`~app.services.quarantine_service.apply_outcome` inside
    ``asyncio.run()`` so the fully-async service function can be executed
    from a synchronous Celery worker.

    Routing (Section 5.1 Task 5) — handled inside the service:
        'phishing'   → ``Email.status = 'quarantined'``,
                        ``AnalysisResult.quarantined = True``,
                        ``send_digest.delay()`` if auto_quarantine_high_risk
        'suspicious' → ``Email.status = 'flagged'``,
                        optional ``[SUSPICIOUS]`` subject prefix
        'safe'       → ``Email.status = 'delivered'``

    SSE events (Section 2.2) — handled inside the service:
        Always: ``scan_complete``.
        When quarantined: also ``quarantine_created``.
        Pub/Sub failure → WARNING logged, task continues (non-blocking).

    Notification counters (Section 6) — handled inside the service:
        ``INCR notif:{user_id}:unread`` for each active org analyst.

    Stats cache (Section 4.3) — invalidated here after routing so the next
        dashboard poll reflects the outcome immediately.

    Retry behaviour:
        Retried up to ``max_retries=2`` (countdown=10) on unexpected exceptions.
        After exhausting retries :func:`_on_task_failure` marks the email as
        ``'failed'`` and publishes a ``scan_complete {status:'failed'}`` SSE.

    Args:
        email_id: UUID string of the Email row to act on.

    Returns:
        *email_id* — so further chain steps remain possible.
    """
    import asyncio as _asyncio  # noqa: PLC0415

    import redis.asyncio as _aioredis  # noqa: PLC0415
    from celery.exceptions import MaxRetriesExceededError  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415

    from app.core.config import settings  # noqa: PLC0415
    from app.core.database import AsyncSessionLocal  # noqa: PLC0415
    from app.models.email import Email  # noqa: PLC0415
    from app.services import quarantine_service  # noqa: PLC0415

    async def _run() -> None:
        """Create async session + Redis, run the service, then invalidate cache."""
        async with AsyncSessionLocal() as db:
            r = await _aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
            )
            try:
                await quarantine_service.apply_outcome(
                    uuid.UUID(email_id), db, r
                )
            finally:
                await r.aclose()

        # ── Invalidate Redis stats/insights cache (non-blocking, sync) ────
        try:
            import redis as _sync_redis  # noqa: PLC0415

            r_sync = _sync_redis.Redis.from_url(
                settings.REDIS_URL, decode_responses=True
            )
            # Fetch org_id from DB for cache key construction.
            # We open a fresh sync session here rather than reusing the async
            # one (which is already closed above).
            sync_session = _make_sync_session()
            try:
                email_row = sync_session.execute(
                    select(Email).where(Email.id == uuid.UUID(email_id))
                ).scalar_one_or_none()
                if email_row:
                    org_id = email_row.org_id
                    for period in ("all_time", "this_week", "30d"):
                        r_sync.delete(f"stats:{org_id}:{period}")
                    r_sync.delete(f"insights:{org_id}")
            finally:
                sync_session.close()
                r_sync.close()
        except Exception as cache_exc:
            log.warning(
                "apply_outcome_cache_invalidation_failed",
                email_id=email_id,
                error=str(cache_exc),
            )

    try:
        _asyncio.run(_run())
        return email_id

    except Exception as exc:
        log.warning(
            "apply_outcome_error",
            email_id=email_id,
            error=str(exc),
            exc_type=type(exc).__name__,
        )
        try:
            raise self.retry(exc=exc, countdown=10)
        except MaxRetriesExceededError:
            _on_task_failure(email_id, "apply_outcome", exc)
            raise


# ---------------------------------------------------------------------------
# IMAP poller (Beat schedule)
# ---------------------------------------------------------------------------


@shared_task(bind=True, queue="imap")
def imap_poll_all_orgs(self) -> None:
    """Poll IMAP inboxes for all organisations with an active connector.

    Triggered by Celery Beat every 60 seconds (queue='imap').

    P-02 fix: ``imap_host IS NOT NULL`` is enforced at the SQL layer so orgs
    without IMAP configured are excluded from the query entirely.

    For each org where ``connector_status='active' AND imap_host IS NOT NULL``:

    1. Decrypt ``imap_password_encrypted`` using the Fernet key from settings.
    2. Open an ``IMAP4_SSL`` session with a 10-second socket timeout.
    3. Search for ``UNSEEN`` messages.
    4. For each message — fetch raw bytes (RFC822), write to
       ``/tmp/{email_id}.eml``, INSERT an Email row, fire
       :func:`fire_analysis_chain`, and PUBLISH an ``imap_ingested`` SSE.
    5. Mark fetched messages ``\\Seen`` so they are not re-processed.
    6. On *any* per-org error: UPDATE that org's ``connector_status`` to
       ``'error'``, write an ``imap_config_updated`` audit log entry, and
       continue to the next org — a single broken connector must not block
       healthy ones.
    """
    import imaplib  # noqa: PLC0415
    from datetime import datetime, timezone  # noqa: PLC0415

    from cryptography.fernet import Fernet, InvalidToken  # noqa: PLC0415
    from sqlalchemy import select, update  # noqa: PLC0415

    from app.core.config import settings  # noqa: PLC0415
    from app.models.audit_log import AuditLog  # noqa: PLC0415
    from app.models.email import Email  # noqa: PLC0415
    from app.models.organisation import Organisation  # noqa: PLC0415

    session = _make_sync_session()
    try:
        orgs = list(
            session.execute(
                select(Organisation).where(
                    Organisation.connector_status == "active",
                    Organisation.imap_host.isnot(None),
                )
            ).scalars()
        )
    except Exception as exc:
        log.error("imap_poll_db_query_failed", error=str(exc))
        session.close()
        return

    fernet = Fernet(settings.FERNET_KEY.encode())

    for org in orgs:
        org_id_str = str(org.id)
        try:
            if not org.imap_host or not org.imap_user or not org.imap_password_encrypted:
                log.warning("imap_poll_missing_config", org_id=org_id_str)
                continue

            # ── Decrypt password ───────────────────────────────────────────
            try:
                imap_password = fernet.decrypt(
                    org.imap_password_encrypted.encode()
                ).decode()
            except InvalidToken as dec_exc:
                raise RuntimeError(
                    f"Fernet decryption failed for org {org_id_str}: {dec_exc}"
                ) from dec_exc

            # ── Connect to IMAP server (10 s socket timeout) ──────────────
            port: int = org.imap_port or 993
            conn = imaplib.IMAP4_SSL(org.imap_host, port, timeout=10)

            try:
                conn.login(org.imap_user, imap_password)
                conn.select("INBOX")

                status, msg_ids_raw = conn.search(None, "UNSEEN")
                if status != "OK":
                    log.warning(
                        "imap_poll_search_failed",
                        org_id=org_id_str,
                        status=status,
                    )
                    continue

                msg_ids: list[bytes] = msg_ids_raw[0].split() if msg_ids_raw[0] else []
                log.info(
                    "imap_poll_org",
                    org_id=org_id_str,
                    n_unseen=len(msg_ids),
                )

                for msg_id in msg_ids:
                    try:
                        fetch_status, msg_data = conn.fetch(msg_id, "(RFC822)")
                        if fetch_status != "OK" or not msg_data or msg_data[0] is None:
                            log.warning(
                                "imap_poll_fetch_failed",
                                org_id=org_id_str,
                                msg_id=msg_id,
                            )
                            continue

                        raw_bytes: bytes = msg_data[0][1]  # type: ignore[index]

                        # ── Persist Email row ──────────────────────────────
                        email_id = uuid.uuid4()
                        tmp_path = f"/tmp/{email_id}.eml"
                        with open(tmp_path, "wb") as fh:
                            fh.write(raw_bytes)

                        email_row = Email(
                            id=email_id,
                            org_id=org.id,
                            ingestion_source="imap",
                            status="pending",
                            received_at=datetime.now(timezone.utc),
                        )
                        session.add(email_row)
                        session.commit()

                        # ── Fire analysis chain ────────────────────────────
                        fire_analysis_chain(str(email_id))

                        # ── Publish imap_ingested SSE ──────────────────────
                        # sender/subject are populated later by parse_and_sanitise;
                        # the UI uses this event to show the new row immediately.
                        _publish_sse_event(
                            org.id,
                            "imap_ingested",
                            {
                                "email_id": str(email_id),
                                "sender": None,
                                "subject": None,
                                "received_at": email_row.received_at.isoformat(),
                                "ingestion_source": "imap",
                            },
                        )

                        # ── Mark as Seen ───────────────────────────────────
                        conn.store(msg_id, "+FLAGS", "\\Seen")

                        log.info(
                            "imap_poll_email_queued",
                            org_id=org_id_str,
                            email_id=str(email_id),
                        )
                    except Exception as msg_exc:
                        log.warning(
                            "imap_poll_message_error",
                            org_id=org_id_str,
                            msg_id=str(msg_id),
                            error=str(msg_exc),
                        )
                        try:
                            session.rollback()
                        except Exception:
                            pass

            finally:
                try:
                    conn.logout()
                except Exception:
                    pass

        except Exception as org_exc:
            # Per-org failure — mark connector as error, write audit log, continue.
            log.error(
                "imap_poll_org_error",
                org_id=org_id_str,
                error=str(org_exc),
                exc_type=type(org_exc).__name__,
            )
            try:
                session.execute(
                    update(Organisation.__table__)
                    .where(Organisation.__table__.c.id == org.id)
                    .values(connector_status="error")
                )
                session.add(
                    AuditLog(
                        org_id=org.id,
                        action="imap_config_updated",
                        target_type="imap_config",
                        detail={"event": "connector_error", "error": str(org_exc)[:500]},
                    )
                )
                session.commit()
            except Exception as audit_exc:
                log.error(
                    "imap_poll_audit_write_failed",
                    org_id=org_id_str,
                    error=str(audit_exc),
                )
                try:
                    session.rollback()
                except Exception:
                    pass

    session.close()
    log.info("imap_poll_all_orgs_done", n_orgs=len(orgs))
