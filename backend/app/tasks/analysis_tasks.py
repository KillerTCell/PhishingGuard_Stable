"""Analysis pipeline Celery tasks (Section 8, FR-02, FR-03, FR-04, UC-02).

Queues:
    analysis — parse_and_sanitise, extract_features, classify_email,
               generate_explanation, apply_outcome
    imap     — imap_poll_all_orgs (triggered by Celery Beat every 60 s)

All functions are stubs.  Full implementation follows in a later iteration.
"""
from __future__ import annotations

import structlog
from celery import shared_task

log = structlog.get_logger(__name__)


@shared_task
def parse_and_sanitise(email_id: str) -> None:
    """Parse raw .eml bytes, sanitise HTML, extract text/headers (FR-02, UC-02 step 2).

    Args:
        email_id: UUID string of the Email row to process.
    """
    log.info("task_not_implemented", task="parse_and_sanitise", email_id=email_id)


@shared_task
def extract_features(email_id: str) -> None:
    """Extract NLP and structural features from a parsed email (FR-02, UC-02 step 3).

    Args:
        email_id: UUID string of the Email row to process.
    """
    log.info("task_not_implemented", task="extract_features", email_id=email_id)


@shared_task
def classify_email(email_id: str) -> None:
    """Run the Random Forest classifier and record the AnalysisResult (FR-03, UC-02 step 4).

    Args:
        email_id: UUID string of the Email row to classify.
    """
    log.info("task_not_implemented", task="classify_email", email_id=email_id)


@shared_task
def generate_explanation(email_id: str) -> None:
    """Call the Anthropic Claude API to produce a natural-language explanation (FR-04).

    Args:
        email_id: UUID string of the Email row whose classification to explain.
    """
    log.info("task_not_implemented", task="generate_explanation", email_id=email_id)


@shared_task
def apply_outcome(email_id: str) -> None:
    """Apply the auto-quarantine or subject-warning outcome after classification (FR-05).

    Args:
        email_id: UUID string of the Email row to act on.
    """
    log.info("task_not_implemented", task="apply_outcome", email_id=email_id)


@shared_task
def imap_poll_all_orgs() -> None:
    """Poll IMAP inboxes for all organisations with an active connector.

    Triggered by Celery Beat every 60 seconds (queue='imap').
    Iterates over organisations where ``connector_status='active'``,
    fetches unseen messages, and dispatches ``parse_and_sanitise`` tasks.
    """
    log.info("task_not_implemented", task="imap_poll_all_orgs")
