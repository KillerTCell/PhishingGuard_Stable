"""initial_schema_all_11_tables

Revision ID: a1b2c3d4e5f6
Revises:
Create Date: 2026-05-25 05:43:10.609985

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Enable pgcrypto for gen_random_uuid() ──────────────────────────
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # ── organisations ──────────────────────────────────────────────────
    # Parent of all other tenant-scoped tables — created first.
    op.create_table(
        "organisations",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("suspicious_threshold", sa.SmallInteger(), nullable=False, server_default="30"),
        sa.Column("phishing_threshold", sa.SmallInteger(), nullable=False, server_default="80"),
        sa.Column("auto_quarantine_high_risk", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("prepend_subject_warning", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("forwarding_address_slug", sa.String(100), nullable=True),
        sa.Column("imap_host", sa.String(255), nullable=True),
        sa.Column("imap_port", sa.SmallInteger(), nullable=True, server_default="993"),
        sa.Column("imap_user", sa.String(254), nullable=True),
        sa.Column("imap_password_encrypted", sa.Text(), nullable=True),
        sa.Column("connector_status", sa.String(20), nullable=False, server_default="unconfigured"),
        sa.Column("data_retention_days", sa.SmallInteger(), nullable=False, server_default="90"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        # D-01 FIX — threshold ordering enforced at DB level
        sa.CheckConstraint("suspicious_threshold < phishing_threshold", name="threshold_order"),
        sa.CheckConstraint("suspicious_threshold BETWEEN 0 AND 100", name="org_suspicious_range"),
        sa.CheckConstraint("phishing_threshold BETWEEN 0 AND 100", name="org_phishing_range"),
        sa.CheckConstraint(
            "connector_status IN ('unconfigured','active','error')",
            name="org_connector_status",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("forwarding_address_slug"),
    )
    # DB-level trigger: keep updated_at current on raw-SQL UPDATE
    op.execute("""
        CREATE OR REPLACE FUNCTION set_updated_at()
        RETURNS TRIGGER LANGUAGE plpgsql AS $$
        BEGIN
            NEW.updated_at = now();
            RETURN NEW;
        END;
        $$
    """)
    op.execute("""
        CREATE TRIGGER trg_organisations_updated_at
        BEFORE UPDATE ON organisations
        FOR EACH ROW EXECUTE FUNCTION set_updated_at()
    """)

    # ── users ──────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("full_name", sa.String(200), nullable=False),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("password_hash", sa.String(72), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("last_active_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("role IN ('admin','analyst')", name="user_role_check"),
        sa.ForeignKeyConstraint(["org_id"], ["organisations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email", name="uq_user_email"),
    )
    op.create_index("ix_user_org_id", "users", ["org_id"])

    # ── emails ─────────────────────────────────────────────────────────
    op.create_table(
        "emails",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sender", sa.String(320), nullable=True),
        sa.Column("reply_to", sa.String(320), nullable=True),
        sa.Column("recipient_address", sa.String(320), nullable=True),
        sa.Column("subject", sa.Text(), nullable=True),
        sa.Column("body_text", sa.Text(), nullable=True),
        sa.Column("html_sanitised", sa.Text(), nullable=True),
        sa.Column("links", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("attachment_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("spf", sa.String(10), nullable=True),
        sa.Column("dkim", sa.String(10), nullable=True),
        sa.Column("dmarc", sa.String(10), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("status", sa.String(25), nullable=False, server_default="pending"),
        sa.Column("ingestion_source", sa.String(10), nullable=False),
        sa.Column("added_to_training", sa.Boolean(), nullable=False, server_default="false"),
        sa.CheckConstraint(
            "status IN ('pending','delivered','flagged','quarantined','confirmed_phishing','failed')",
            name="email_status_check",
        ),
        sa.CheckConstraint(
            "ingestion_source IN ('imap','upload','paste')",
            name="email_ingestion_source_check",
        ),
        sa.CheckConstraint("spf IN ('pass','fail','none','neutral','softfail')", name="email_spf_check"),
        sa.CheckConstraint("dkim IN ('pass','fail','none')", name="email_dkim_check"),
        sa.CheckConstraint("dmarc IN ('pass','fail','none')", name="email_dmarc_check"),
        sa.ForeignKeyConstraint(["org_id"], ["organisations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_email_org_received", "emails", ["org_id", "received_at"])
    op.create_index("ix_email_status", "emails", ["status"])
    op.create_index("ix_email_ingestion_source", "emails", ["ingestion_source"])

    # ── email_features ─────────────────────────────────────────────────
    op.create_table(
        "email_features",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("email_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("feature_name", sa.String(100), nullable=False),
        sa.Column("feature_value", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("score_contribution", sa.Float(), nullable=False, server_default=sa.text("0.0")),
        sa.CheckConstraint("score_contribution BETWEEN 0.0 AND 1.0", name="email_feature_score_range"),
        sa.CheckConstraint(
            "feature_name IN ("
            "'urgency_language','credential_request','link_mismatch',"
            "'impersonation_language','auth_failure','grammar_quality',"
            "'known_bad_url')",
            name="email_feature_name_check",
        ),
        sa.ForeignKeyConstraint(["email_id"], ["emails.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_email_feature_email_id", "email_features", ["email_id"])

    # ── analysis_results ───────────────────────────────────────────────
    op.create_table(
        "analysis_results",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("email_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("classification", sa.String(20), nullable=False),
        sa.Column("risk_score", sa.SmallInteger(), nullable=False),
        sa.Column("model_version", sa.String(50), nullable=False),
        # D-05 FIX — two separate threshold snapshot columns
        sa.Column("threshold_applied_suspicious", sa.SmallInteger(), nullable=False),
        sa.Column("threshold_applied_phishing", sa.SmallInteger(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column("top_features", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("quarantined", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint(
            "classification IN ('safe','suspicious','phishing','failed')",
            name="analysis_result_classification_check",
        ),
        sa.CheckConstraint("risk_score BETWEEN 0 AND 100", name="analysis_result_risk_score_range"),
        sa.ForeignKeyConstraint(["email_id"], ["emails.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email_id", name="uq_analysis_result_email_id"),
    )
    op.create_index("ix_analysis_result_email_id", "analysis_results", ["email_id"])
    op.create_index("ix_analysis_result_risk_score", "analysis_results", ["risk_score"])

    # ── feedback ───────────────────────────────────────────────────────
    op.create_table(
        "feedback",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("email_id", postgresql.UUID(as_uuid=True), nullable=False),
        # D-06: nullable — NULL when submitted via digest link (no account)
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("label", sa.String(25), nullable=False),
        sa.Column("source", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint(
            "label IN ('phishing','safe','needs_investigation')",
            name="feedback_label_check",
        ),
        sa.CheckConstraint(
            "source IN ('dashboard','digest_link','manual_paste')",
            name="feedback_source_check",
        ),
        # D-06 FIX — deliberately NO UniqueConstraint on email_id
        sa.ForeignKeyConstraint(["email_id"], ["emails.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_feedback_email_id", "feedback", ["email_id"])
    op.create_index("ix_feedback_created_at", "feedback", ["created_at"])

    # ── digest_log ─────────────────────────────────────────────────────
    op.create_table(
        "digest_log",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("email_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("recipient_address", sa.String(320), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(10), nullable=False, server_default="pending"),
        # D-07 FIX — retry counter for Resend SDK failures
        sa.Column("retry_count", sa.SmallInteger(), nullable=False, server_default="0"),
        sa.Column("signed_token_jti", sa.String(64), nullable=False),
        sa.Column("token_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("action_taken", sa.String(25), nullable=True),
        sa.Column("action_taken_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status IN ('pending','sent','failed')", name="digest_log_status_check"),
        sa.CheckConstraint(
            "action_taken IN ('confirmed_phishing','marked_safe')",
            name="digest_log_action_taken_check",
        ),
        sa.ForeignKeyConstraint(["email_id"], ["emails.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("signed_token_jti"),
    )

    # ── audit_log ──────────────────────────────────────────────────────
    op.create_table(
        "audit_log",
        # BIGSERIAL — append-only; monotonic integer ordering
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("target_type", sa.String(50), nullable=True),
        sa.Column("target_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("detail", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        # D-08 FIX — HTTP request correlation UUID
        sa.Column("request_id", sa.String(36), nullable=True),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["org_id"], ["organisations.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_log_org_created", "audit_log", ["org_id", "created_at"])
    op.create_index("ix_audit_log_user_id", "audit_log", ["user_id"])

    # ── invite_tokens ──────────────────────────────────────────────────
    op.create_table(
        "invite_tokens",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("invited_by_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("token_hash", sa.String(72), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("role IN ('admin','analyst')", name="invite_token_role_check"),
        sa.ForeignKeyConstraint(["invited_by_user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["org_id"], ["organisations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )

    # ── password_reset_tokens (D-09 FIX) ───────────────────────────────
    op.create_table(
        "password_reset_tokens",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.String(72), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ip_requested_from", postgresql.INET(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )

    # ── export_jobs (D-10 FIX) ─────────────────────────────────────────
    op.create_table(
        "export_jobs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("requested_by_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("format", sa.String(10), nullable=False),
        # A-04 FIX — enum string not raw dates
        sa.Column("date_range", sa.String(5), nullable=False),
        sa.Column("label_filter", sa.String(25), nullable=True),
        sa.Column("status", sa.String(15), nullable=False, server_default="pending"),
        sa.Column("record_count", sa.Integer(), nullable=True),
        # A-05 FIX — four estimated scope fields
        sa.Column("estimated_scope_emails", sa.Integer(), nullable=True),
        sa.Column("estimated_scope_phishing", sa.Integer(), nullable=True),
        sa.Column("estimated_scope_safe", sa.Integer(), nullable=True),
        sa.Column("estimated_scope_review", sa.Integer(), nullable=True),
        sa.Column("file_path", sa.String(500), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("format IN ('csv','json','jsonl')", name="export_job_format_check"),
        sa.CheckConstraint("date_range IN ('7d','30d','all')", name="export_job_date_range_check"),
        sa.CheckConstraint(
            "status IN ('pending','generating','ready','failed')",
            name="export_job_status_check",
        ),
        sa.CheckConstraint(
            "label_filter IN ('all','phishing','safe','needs_investigation')",
            name="export_job_label_filter_check",
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organisations.id"]),
        sa.ForeignKeyConstraint(["requested_by_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_export_job_org_created", "export_jobs", ["org_id", "created_at"])
    op.create_index("ix_export_job_status", "export_jobs", ["status"])


def downgrade() -> None:
    # Drop in reverse FK dependency order
    op.drop_index("ix_export_job_status", table_name="export_jobs")
    op.drop_index("ix_export_job_org_created", table_name="export_jobs")
    op.drop_table("export_jobs")

    op.drop_table("password_reset_tokens")

    op.drop_table("invite_tokens")

    op.drop_index("ix_audit_log_user_id", table_name="audit_log")
    op.drop_index("ix_audit_log_org_created", table_name="audit_log")
    op.drop_table("audit_log")

    op.drop_table("digest_log")

    op.drop_index("ix_feedback_created_at", table_name="feedback")
    op.drop_index("ix_feedback_email_id", table_name="feedback")
    op.drop_table("feedback")

    op.drop_index("ix_analysis_result_risk_score", table_name="analysis_results")
    op.drop_index("ix_analysis_result_email_id", table_name="analysis_results")
    op.drop_table("analysis_results")

    op.drop_index("ix_email_feature_email_id", table_name="email_features")
    op.drop_table("email_features")

    op.drop_index("ix_email_ingestion_source", table_name="emails")
    op.drop_index("ix_email_status", table_name="emails")
    op.drop_index("ix_email_org_received", table_name="emails")
    op.drop_table("emails")

    op.drop_index("ix_user_org_id", table_name="users")
    op.drop_table("users")

    op.execute("DROP TRIGGER IF EXISTS trg_organisations_updated_at ON organisations")
    op.execute("DROP FUNCTION IF EXISTS set_updated_at")
    op.drop_table("organisations")
