"""Export generation Celery tasks (Section 8, FR-08).

Queue: export

All functions are stubs.  Full implementation follows in a later iteration.
"""
from __future__ import annotations

import structlog
from celery import shared_task

log = structlog.get_logger(__name__)


@shared_task
def generate_export(export_job_id: str) -> None:
    """Generate a CSV export file and write it to the exports volume (FR-08).

    Reads all email + analysis rows for the organisation, streams them into a
    CSV at ``{EXPORT_VOLUME_PATH}/{export_job_id}.csv``, then UPDATEs the
    ExportJob row with status='done' and the file path.

    Args:
        export_job_id: UUID string of the ExportJob row tracking this run.
    """
    log.info(
        "task_not_implemented",
        task="generate_export",
        export_job_id=export_job_id,
    )
