"""Celery application instance and configuration for PhishGuard.

Section 8 (tasks/celery_app.py): broker = Redis, 6 named queues,
task lifecycle settings, and Celery Beat periodic schedule.

Referenced by docker-compose as ``-A app.tasks.celery_app`` for both the
worker and beat services.

Queue assignment:
    analysis    — parse, feature extraction, classify, explanation, outcome
    digest      — quarantine digest email delivery
    forwarding  — forwarding inbox test probe
    export      — CSV export generation
    maintenance — data retention delete, monthly Postgres partition creation
    imap        — periodic IMAP inbox polling (every 60 s)
"""
from __future__ import annotations

from celery import Celery
from celery.schedules import crontab
from kombu import Queue

from app.core.config import settings

# ---------------------------------------------------------------------------
# Application instance
# ---------------------------------------------------------------------------

#: Celery application singleton.  Auto-discovered by ``celery -A app.tasks.celery_app``.
celery_app = Celery(
    "phishguard",
    broker=settings.CELERY_BROKER_URL,
    # Use None when CELERY_RESULT_BACKEND is not configured (empty string)
    backend=settings.CELERY_RESULT_BACKEND or None,
    include=[
        "app.tasks.analysis_tasks",
        "app.tasks.digest_tasks",
        "app.tasks.forwarding_tasks",
        "app.tasks.export_tasks",
        "app.tasks.maintenance_tasks",
    ],
)

# ---------------------------------------------------------------------------
# Named queues  (Section 8: 6 queues)
# ---------------------------------------------------------------------------

_QUEUES = ("analysis", "digest", "forwarding", "export", "maintenance", "imap")

celery_app.conf.task_queues = [Queue(name) for name in _QUEUES]
celery_app.conf.task_default_queue = "analysis"

# ---------------------------------------------------------------------------
# Task execution policy
# ---------------------------------------------------------------------------

celery_app.conf.update(
    # ── Serialization ────────────────────────────────────────────────────────
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",

    # ── Timezone ─────────────────────────────────────────────────────────────
    timezone="UTC",
    enable_utc=True,

    # ── Execution guarantees (Section 8) ─────────────────────────────────────
    # SIGALRM after 30 s — task can catch SoftTimeLimitExceeded and clean up
    task_soft_time_limit=30,
    # SIGKILL after 60 s — hard ceiling; prevents zombie workers
    task_time_limit=60,
    # ACK the message only after the task function returns successfully.
    # If the worker crashes mid-task the message is re-queued (at-least-once).
    task_acks_late=True,
    # Fetch exactly one task at a time — prevents a single worker from
    # monopolising the queue and ensures fair round-robin distribution.
    worker_prefetch_multiplier=1,

    # ── Celery Beat periodic schedule ─────────────────────────────────────────
    beat_schedule={
        # IMAP inbox poll — runs every 60 seconds across all active orgs
        "imap-poll-all-orgs": {
            "task": "app.tasks.analysis_tasks.imap_poll_all_orgs",
            "schedule": 60.0,                          # seconds
            "options": {"queue": "imap"},
        },
        # Data-retention sweep — runs every day at 02:00 UTC
        "auto-delete-expired-emails": {
            "task": "app.tasks.maintenance_tasks.auto_delete_expired_emails",
            "schedule": crontab(hour=2, minute=0),
            "options": {"queue": "maintenance"},
        },
        # Postgres partition creation — runs on the 1st of every month at 01:00 UTC
        # D-02 fix: pre-creates the next month's partition before it is needed
        "auto-create-monthly-partition": {
            "task": "app.tasks.maintenance_tasks.auto_create_monthly_partition",
            "schedule": crontab(hour=1, minute=0, day_of_month="1"),
            "options": {"queue": "maintenance"},
        },
    },
)
