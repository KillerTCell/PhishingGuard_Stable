"""add_detection_confidence_to_analysis_results

Revision ID: b2c3d4e5f6a7
Revises: a7b8c9d0e1f2
Create Date: 2026-06-12

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "b2c3d4e5f6a7"
down_revision = "a7b8c9d0e1f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "analysis_results",
        sa.Column("detection_confidence", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("analysis_results", "detection_confidence")
