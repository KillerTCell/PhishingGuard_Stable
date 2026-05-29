"""add_eml_to_export_format_constraint

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-05-29 00:00:00.000000

Add 'eml' to the export_jobs.format CHECK constraint so EML exports can be
stored and served as a ZIP of .eml files.
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d4e5f6a7b8c9"
down_revision: Union[str, None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # asyncpg does not allow multiple statements in one execute() call.
    op.execute("ALTER TABLE export_jobs DROP CONSTRAINT IF EXISTS export_job_format_check")
    op.execute(
        "ALTER TABLE export_jobs ADD CONSTRAINT export_job_format_check"
        " CHECK (format IN ('csv', 'json', 'jsonl', 'eml'))"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE export_jobs DROP CONSTRAINT IF EXISTS export_job_format_check")
    op.execute(
        "ALTER TABLE export_jobs ADD CONSTRAINT export_job_format_check"
        " CHECK (format IN ('csv', 'json', 'jsonl'))"
    )
