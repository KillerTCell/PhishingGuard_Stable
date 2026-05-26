"""emails_monthly_partitioning

Revision ID: c3d4e5f6a7b8
Revises: a1b2c3d4e5f6
Create Date: 2026-05-27 12:00:00.000000

OPTIONAL MIGRATION — NFR-4: Convert the ``emails`` table from a regular heap
table to a PostgreSQL RANGE-partitioned table (partition key: ``received_at``).

────────────────────────────────────────────────────────────────────────────────
WHEN TO APPLY
────────────────────────────────────────────────────────────────────────────────
Apply this migration ONLY when the emails table has significant data (> 1 million
rows in production).  On small tables range partitioning adds DDL complexity
without measurable query benefit.

For development and CI testing this migration should be SKIPPED — the tests run
against a fresh schema where the emails table is always small and the
auto_create_monthly_partition task handles the non-partitioned case gracefully.

To skip this migration in dev/CI, comment out the body of upgrade() and replace
it with ``pass``, or omit it from the Alembic version chain entirely.

────────────────────────────────────────────────────────────────────────────────
WHAT IT DOES
────────────────────────────────────────────────────────────────────────────────
Step 1 — Rename existing table:
    ALTER TABLE emails RENAME TO emails_default;

    All existing data stays in ``emails_default``.  PostgreSQL automatically
    updates all FK references that previously pointed to ``emails`` to now
    point to ``emails_default``.

Step 2 — Create partitioned parent:
    CREATE TABLE emails (LIKE emails_default INCLUDING DEFAULTS)
    PARTITION BY RANGE (received_at);

    ``INCLUDING DEFAULTS`` copies column definitions and server_default
    expressions (e.g. gen_random_uuid(), now()).  Constraints and indexes are
    intentionally NOT copied to the parent — they live on the partitions.

    NOTE ON PRIMARY KEY: PostgreSQL 11+ requires that the partition key column
    (received_at) be part of any PRIMARY KEY defined on the partitioned parent.
    This migration does NOT add a PK to the parent; instead, the ``emails_default``
    partition retains its original ``PRIMARY KEY (id)`` constraint.  Uniqueness
    is therefore enforced at partition level, which is correct for the existing
    single-partition layout.  When monthly partitions are created, add a PK or
    UNIQUE constraint on (id, received_at) to each new partition as needed.

Step 3 — Attach existing table as DEFAULT partition:
    ALTER TABLE emails ATTACH PARTITION emails_default DEFAULT;

    The DEFAULT partition catches any rows whose ``received_at`` does not fall
    in a specific monthly partition.  ``ATTACH PARTITION`` is a metadata-only
    operation on PostgreSQL 14+ — no data is copied, so it is instant even on
    large tables.

    CORRECTION FROM SPEC: the spec describes step 3 as
    ``CREATE TABLE emails_default PARTITION OF emails DEFAULT``
    but that statement fails because ``emails_default`` already exists after
    step 1.  ``ALTER TABLE emails ATTACH PARTITION emails_default DEFAULT``
    is the correct equivalent DDL that attaches the renamed existing table.

Step 4 — Restore top-level indexes on the parent:
    The original indexes (ix_email_org_received, ix_email_status,
    ix_email_ingestion_source) exist on ``emails_default`` (the partition).
    PostgreSQL makes partition indexes queryable through the parent, so no
    additional indexes are strictly required.  However, creating indexes on the
    parent propagates them to future partitions automatically; we therefore
    create them here so auto_create_monthly_partition inherits them.

────────────────────────────────────────────────────────────────────────────────
DOWNGRADE
────────────────────────────────────────────────────────────────────────────────
DETACH the default partition, drop the (now empty) partitioned parent, and
rename ``emails_default`` back to ``emails``.  All data remains intact.

If monthly partitions (emails_2026_06, etc.) were created AFTER this migration
was applied, they must be dropped or re-attached before downgrading, or the
``DROP TABLE emails`` will fail because partitions still exist.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers
revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ──────────────────────────────────────────────────────────────────────────
    # OPTIONAL — comment out this entire function body (and replace with `pass`)
    # for development / CI environments where partitioning is not needed.
    # ──────────────────────────────────────────────────────────────────────────

    # Step 1: Rename existing heap table — data stays, FK refs auto-update.
    op.execute("ALTER TABLE emails RENAME TO emails_default")

    # Step 2: Create partitioned parent with matching column definitions.
    # INCLUDING DEFAULTS carries over server_default expressions only.
    # Constraints and indexes intentionally stay on emails_default (the partition).
    op.execute(
        """
        CREATE TABLE emails
            (LIKE emails_default INCLUDING DEFAULTS)
        PARTITION BY RANGE (received_at)
        """
    )

    # Step 3: Attach the renamed table as the DEFAULT partition.
    # Instant metadata operation on PG 14+ — no data movement.
    op.execute(
        "ALTER TABLE emails ATTACH PARTITION emails_default DEFAULT"
    )

    # Step 4: Create parent-level indexes so future monthly partitions inherit them.
    # These are in addition to the existing indexes on emails_default.
    op.create_index(
        "ix_email_org_received_parent",
        "emails",
        ["org_id", "received_at"],
    )
    op.create_index(
        "ix_email_status_parent",
        "emails",
        ["status"],
    )
    op.create_index(
        "ix_email_ingestion_source_parent",
        "emails",
        ["ingestion_source"],
    )


def downgrade() -> None:
    # ──────────────────────────────────────────────────────────────────────────
    # PREREQUISITE: any monthly partitions created after this migration must be
    # dropped (or moved) before downgrading, otherwise DROP TABLE emails fails.
    #
    # Example:  DROP TABLE IF EXISTS emails_2026_06;
    # ──────────────────────────────────────────────────────────────────────────

    # Drop parent-level indexes (they are separate from the partition indexes).
    op.drop_index("ix_email_ingestion_source_parent", table_name="emails")
    op.drop_index("ix_email_status_parent", table_name="emails")
    op.drop_index("ix_email_org_received_parent", table_name="emails")

    # Detach the default partition — becomes a standalone table again.
    op.execute(
        "ALTER TABLE emails DETACH PARTITION emails_default"
    )

    # Drop the now-empty partitioned parent.
    op.execute("DROP TABLE emails")

    # Restore the original table name.
    op.execute("ALTER TABLE emails_default RENAME TO emails")
