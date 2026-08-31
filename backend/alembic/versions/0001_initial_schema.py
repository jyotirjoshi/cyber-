"""Initial schema.

Creates all 25 tables of the Cynux MVP schema in dependency order, then every index.

Two notes for whoever runs this:

*   **PostgreSQL 15 or newer is required.**  ``assets.unique_asset`` is declared
    ``NULLS NOT DISTINCT`` so that a host with no port dedupes against itself -- under
    the default ``NULLS DISTINCT`` every rediscovery of the same host would insert a new
    row, because in SQL ``NULL != NULL``.  The clause is a syntax error before 15, so an
    older server fails here loudly rather than silently losing deduplication.
*   LangGraph's ``checkpoints``, ``checkpoint_blobs`` and ``checkpoint_writes`` tables
    are **not** created here.  ``langgraph-checkpoint-postgres`` owns and migrates them
    itself; ``alembic/env.py`` filters them out of autogenerate for the same reason.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-08-21
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("slug", sa.String(length=80), nullable=False),
        sa.Column("max_concurrent_scanner_jobs", sa.Integer(), nullable=False),
        sa.Column("policy", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "max_concurrent_scanner_jobs BETWEEN 1 AND 64",
            name=op.f("ck_organizations_concurrency_bounds"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_organizations")),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("full_name", sa.String(length=200), nullable=True),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("is_email_verified", sa.Boolean(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_login_count", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
    )
    op.create_table(
        "agent_sessions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=True),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("is_archived", sa.Boolean(), nullable=False),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("message_count", sa.Integer(), nullable=False),
        sa.Column("context_summary", sa.Text(), nullable=True),
        sa.Column("summarized_through_seq", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_agent_sessions_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_agent_sessions_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_sessions")),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=True),
        sa.Column("actor_id", sa.UUID(), nullable=True),
        sa.Column("actor_email", sa.String(length=320), nullable=True),
        sa.Column("actor_type", sa.String(length=20), nullable=False),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("resource_type", sa.String(length=60), nullable=True),
        sa.Column("resource_id", sa.String(length=80), nullable=True),
        sa.Column("outcome", sa.String(length=20), nullable=False),
        sa.Column("detail", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column("trace_id", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "actor_type IN ('user','agent','system','worker')",
            name=op.f("ck_audit_events_valid_actor_type"),
        ),
        sa.CheckConstraint(
            "outcome IN ('success','failure','denied')", name=op.f("ck_audit_events_valid_outcome")
        ),
        sa.ForeignKeyConstraint(
            ["actor_id"],
            ["users.id"],
            name=op.f("fk_audit_events_actor_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_audit_events_organization_id_organizations"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
    )
    op.create_table(
        "integrations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False),
        sa.Column("base_url", sa.String(length=1000), nullable=True),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_error_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("created_by_id", sa.UUID(), nullable=True),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "kind IN ('defectdojo','jira','slack','email','dify','misp','nvd','github','gitlab')",
            name=op.f("ck_integrations_valid_integration_kind"),
        ),
        sa.CheckConstraint(
            "status IN ('configured','unverified','error','disabled')",
            name=op.f("ck_integrations_valid_integration_status"),
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name=op.f("fk_integrations_created_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_integrations_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_integrations")),
        sa.UniqueConstraint("organization_id", "kind", "name", name="unique_integration"),
    )
    op.create_table(
        "memberships",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("role", sa.String(length=40), nullable=False),
        sa.Column("is_default", sa.Boolean(), nullable=False),
        sa.Column("invited_by_id", sa.UUID(), nullable=True),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "role IN ('owner','admin','security_engineer','developer','viewer')",
            name=op.f("ck_memberships_valid_role"),
        ),
        sa.ForeignKeyConstraint(
            ["invited_by_id"],
            ["users.id"],
            name=op.f("fk_memberships_invited_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_memberships_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_memberships_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_memberships")),
        sa.UniqueConstraint("organization_id", "user_id", name="unique_member"),
    )
    op.create_table(
        "notifications",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("event", sa.String(length=60), nullable=False),
        sa.Column("channel", sa.String(length=30), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("recipient", sa.String(length=320), nullable=False),
        sa.Column("recipient_user_id", sa.UUID(), nullable=True),
        sa.Column("subject", sa.String(length=500), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("resource_type", sa.String(length=60), nullable=True),
        sa.Column("resource_id", sa.String(length=80), nullable=True),
        sa.Column("dedupe_key", sa.String(length=300), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("suppressed_reason", sa.String(length=200), nullable=True),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "channel IN ('slack','email','websocket')",
            name=op.f("ck_notifications_valid_notification_channel"),
        ),
        sa.CheckConstraint(
            "event IN ('assessment_started','approval_required','critical_finding',"
            "'assessment_completed','assessment_failed','ticket_created')",
            name=op.f("ck_notifications_valid_notification_event"),
        ),
        sa.CheckConstraint(
            "status IN ('pending','sent','failed','suppressed')",
            name=op.f("ck_notifications_valid_notification_status"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_notifications_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["recipient_user_id"],
            ["users.id"],
            name=op.f("fk_notifications_recipient_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notifications")),
        sa.UniqueConstraint("organization_id", "dedupe_key", name="unique_notification"),
    )
    op.create_table(
        "password_reset_tokens",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("token_hash", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requested_ip", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_password_reset_tokens_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_password_reset_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_password_reset_tokens_token_hash")),
    )
    op.create_table(
        "assessments",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("reference", sa.Integer(), nullable=False),
        sa.Column("created_by_id", sa.UUID(), nullable=True),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("scope", sa.String(length=40), nullable=False),
        sa.Column("depth", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("current_stage", sa.String(length=60), nullable=False),
        sa.Column("progress_percent", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("failure_category", sa.String(length=40), nullable=True),
        sa.Column("degradations", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("plan", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "request_interpretation", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("findings_total", sa.Integer(), nullable=False),
        sa.Column("findings_critical", sa.Integer(), nullable=False),
        sa.Column("findings_high", sa.Integer(), nullable=False),
        sa.Column("findings_medium", sa.Integer(), nullable=False),
        sa.Column("findings_low", sa.Integer(), nullable=False),
        sa.Column("findings_info", sa.Integer(), nullable=False),
        sa.Column("assets_discovered", sa.Integer(), nullable=False),
        sa.Column("assets_in_scope", sa.Integer(), nullable=False),
        sa.Column("defectdojo_product_id", sa.Integer(), nullable=True),
        sa.Column("defectdojo_engagement_id", sa.Integer(), nullable=True),
        sa.Column("agent_session_id", sa.UUID(), nullable=True),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "current_stage IN ('queued','understanding_request','validating_target',"
            "'checking_authorization','planning','reconnaissance','asset_analysis',"
            "'awaiting_approval','scanning_nmap','scanning_nuclei','scanning_zap',"
            "'importing_findings','threat_intelligence','ai_analysis','risk_prioritization',"
            "'remediation','creating_actions','report','done')",
            name=op.f("ck_assessments_valid_assessment_stage"),
        ),
        sa.CheckConstraint(
            "depth IN ('passive','standard','deep')", name=op.f("ck_assessments_valid_depth")
        ),
        sa.CheckConstraint(
            "progress_percent BETWEEN 0 AND 100", name=op.f("ck_assessments_progress_bounds")
        ),
        sa.CheckConstraint(
            "scope IN ('external','internal','application','code')",
            name=op.f("ck_assessments_valid_scope"),
        ),
        sa.CheckConstraint(
            "status IN ('CREATED','PLANNING','DISCOVERY','WAITING_FOR_APPROVAL','SCANNING',"
            "'ANALYZING','REMEDIATING','COMPLETED','FAILED','CANCELLING','CANCELLED')",
            name=op.f("ck_assessments_valid_assessment_status"),
        ),
        sa.ForeignKeyConstraint(
            ["agent_session_id"],
            ["agent_sessions.id"],
            name=op.f("fk_assessments_agent_session_id_agent_sessions"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name=op.f("fk_assessments_created_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_assessments_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_assessments")),
        sa.UniqueConstraint("organization_id", "reference", name="unique_reference"),
    )
    op.create_table(
        "integration_credentials",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("integration_id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=60), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(length=16), nullable=True),
        sa.Column("hint", sa.String(length=8), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_id", sa.UUID(), nullable=True),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name=op.f("fk_integration_credentials_created_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["integration_id"],
            ["integrations.id"],
            name=op.f("fk_integration_credentials_integration_id_integrations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_integration_credentials_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_integration_credentials")),
        sa.UniqueConstraint("integration_id", "name", name="unique_credential_name"),
    )
    op.create_table(
        "agent_runs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("session_id", sa.UUID(), nullable=True),
        sa.Column("assessment_id", sa.UUID(), nullable=True),
        sa.Column("triggered_by_id", sa.UUID(), nullable=True),
        sa.Column("thread_id", sa.String(length=120), nullable=False),
        sa.Column("graph", sa.String(length=60), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("current_node", sa.String(length=80), nullable=True),
        sa.Column("interrupt_kind", sa.String(length=40), nullable=True),
        sa.Column("pending_approval_id", sa.UUID(), nullable=True),
        sa.Column("queue_message_id", sa.String(length=64), nullable=True),
        sa.Column("worker_id", sa.String(length=64), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resumed_count", sa.Integer(), nullable=False),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("failure_category", sa.String(length=40), nullable=True),
        sa.Column("trace_id", sa.String(length=120), nullable=True),
        sa.Column("trace_url", sa.String(length=1000), nullable=True),
        sa.Column("total_input_tokens", sa.Integer(), nullable=False),
        sa.Column("total_output_tokens", sa.Integer(), nullable=False),
        sa.Column("tool_call_count", sa.Integer(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('queued','running','interrupted','completed','failed','cancelled')",
            name=op.f("ck_agent_runs_valid_run_status"),
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessments.id"],
            name=op.f("fk_agent_runs_assessment_id_assessments"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_agent_runs_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["agent_sessions.id"],
            name=op.f("fk_agent_runs_session_id_agent_sessions"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["triggered_by_id"],
            ["users.id"],
            name=op.f("fk_agent_runs_triggered_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_runs")),
    )
    op.create_table(
        "assessment_targets",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("assessment_id", sa.UUID(), nullable=False),
        sa.Column("raw_value", sa.String(length=2048), nullable=False),
        sa.Column("canonical_value", sa.String(length=2048), nullable=False),
        sa.Column("target_type", sa.String(length=40), nullable=False),
        sa.Column("host", sa.String(length=512), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("host_count", sa.Integer(), nullable=False),
        sa.Column("target_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessments.id"],
            name=op.f("fk_assessment_targets_assessment_id_assessments"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_assessment_targets_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_assessment_targets")),
        sa.UniqueConstraint("assessment_id", "canonical_value", name="unique_target"),
    )
    op.create_table(
        "assets",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("assessment_id", sa.UUID(), nullable=True),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("asset_type", sa.String(length=40), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=20), nullable=True),
        sa.Column("service", sa.String(length=120), nullable=True),
        sa.Column("technology", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("internet_exposed", sa.Boolean(), nullable=False),
        sa.Column("http_title", sa.String(length=512), nullable=True),
        sa.Column("http_status_code", sa.Integer(), nullable=True),
        sa.Column("tls_subject", sa.String(length=512), nullable=True),
        sa.Column("criticality", sa.String(length=20), nullable=False),
        sa.Column("criticality_source", sa.String(length=30), nullable=False),
        sa.Column("criticality_rationale", sa.Text(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("selection_rationale", sa.Text(), nullable=True),
        sa.Column("selected_for_scanning", sa.Boolean(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("seen_in_assessments", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "criticality IN ('critical','high','normal','low','unknown')",
            name=op.f("ck_assets_valid_criticality"),
        ),
        sa.CheckConstraint(
            "port IS NULL OR port BETWEEN 0 AND 65535", name=op.f("ck_assets_valid_port")
        ),
        sa.CheckConstraint(
            "status IN ('active','inactive','unreachable','out_of_scope')",
            name=op.f("ck_assets_valid_asset_status"),
        ),
        sa.CheckConstraint(
            "criticality_source IN ('operator_tag','inferred_keyword','inferred_exposure',"
            "'default')",
            name=op.f("ck_assets_valid_criticality_source"),
        ),
        sa.CheckConstraint("risk_score BETWEEN 0 AND 1", name=op.f("ck_assets_risk_score_bounds")),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessments.id"],
            name=op.f("fk_assets_assessment_id_assessments"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_assets_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_assets")),
        sa.UniqueConstraint(
            "organization_id",
            "name",
            "port",
            "protocol",
            name="unique_asset",
            postgresql_nulls_not_distinct=True,
        ),
    )
    op.create_table(
        "authorization_records",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("assessment_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=True),
        sa.Column("target", sa.String(length=2048), nullable=False),
        sa.Column("confirmed", sa.Boolean(), nullable=False),
        sa.Column("attestation_text", sa.Text(), nullable=False),
        sa.Column("method", sa.String(length=40), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_reference", sa.String(length=1024), nullable=True),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessments.id"],
            name=op.f("fk_authorization_records_assessment_id_assessments"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_authorization_records_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_authorization_records_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_authorization_records")),
    )
    op.create_table(
        "reports",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("assessment_id", sa.UUID(), nullable=False),
        sa.Column("requested_by_id", sa.UUID(), nullable=True),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("format", sa.String(length=20), nullable=False),
        sa.Column("audience", sa.String(length=30), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("storage_key", sa.String(length=1000), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("content_digest", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("degradations", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("executive_summary", sa.Text(), nullable=True),
        sa.Column("summary_ai_generated", sa.Boolean(), nullable=False),
        sa.Column("ai_model", sa.String(length=120), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "audience IN ('executive','technical')", name=op.f("ck_reports_valid_report_audience")
        ),
        sa.CheckConstraint(
            "format IN ('html','pdf','json')", name=op.f("ck_reports_valid_report_format")
        ),
        sa.CheckConstraint(
            "status IN ('pending','generating','ready','failed')",
            name=op.f("ck_reports_valid_report_status"),
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessments.id"],
            name=op.f("fk_reports_assessment_id_assessments"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_reports_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_id"],
            ["users.id"],
            name=op.f("fk_reports_requested_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_reports")),
    )
    op.create_table(
        "scanner_jobs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("assessment_id", sa.UUID(), nullable=False),
        sa.Column("scanner", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("targets", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("argv", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("image", sa.String(length=500), nullable=True),
        sa.Column("container_id", sa.String(length=128), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("sandbox", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("failure_code", sa.String(length=60), nullable=True),
        sa.Column("failure_detail", sa.Text(), nullable=True),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.Column("worker_id", sa.String(length=64), nullable=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_requested_by_id", sa.UUID(), nullable=True),
        sa.Column("artifacts_archived", sa.Boolean(), nullable=False),
        sa.Column("imported_finding_count", sa.Integer(), nullable=False),
        sa.Column("defectdojo_test_id", sa.Integer(), nullable=True),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('QUEUED','RUNNING','COMPLETED','FAILED','CANCELLED','TIMEOUT')",
            name=op.f("ck_scanner_jobs_valid_job_status"),
        ),
        sa.CheckConstraint(
            "timeout_seconds BETWEEN 1 AND 86400", name=op.f("ck_scanner_jobs_timeout_bounds")
        ),
        sa.CheckConstraint(
            "scanner IN ('reconftw','nmap','nuclei','zap')",
            name=op.f("ck_scanner_jobs_valid_scanner_name"),
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessments.id"],
            name=op.f("fk_scanner_jobs_assessment_id_assessments"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["cancel_requested_by_id"],
            ["users.id"],
            name=op.f("fk_scanner_jobs_cancel_requested_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_scanner_jobs_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scanner_jobs")),
    )
    op.create_table(
        "agent_messages",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("session_id", sa.UUID(), nullable=False),
        sa.Column("run_id", sa.UUID(), nullable=True),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("tool_calls", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("tool_name", sa.String(length=80), nullable=True),
        sa.Column("tool_call_id", sa.String(length=120), nullable=True),
        sa.Column("tool_status", sa.String(length=30), nullable=True),
        sa.Column("citations", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("model", sa.String(length=120), nullable=True),
        sa.Column("provider", sa.String(length=40), nullable=True),
        sa.Column("input_tokens", sa.Integer(), nullable=True),
        sa.Column("output_tokens", sa.Integer(), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("guardrail_applied", sa.String(length=60), nullable=True),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "role IN ('user','assistant','system','tool')",
            name=op.f("ck_agent_messages_valid_message_role"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_agent_messages_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["agent_runs.id"],
            name=op.f("fk_agent_messages_run_id_agent_runs"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["agent_sessions.id"],
            name=op.f("fk_agent_messages_session_id_agent_sessions"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_messages")),
        sa.UniqueConstraint("session_id", "seq", name="unique_message_seq"),
    )
    op.create_table(
        "agent_steps",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("run_id", sa.UUID(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("node", sa.String(length=80), nullable=False),
        sa.Column("stage", sa.String(length=60), nullable=True),
        sa.Column("tool_name", sa.String(length=80), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("label", sa.String(length=300), nullable=True),
        sa.Column("input_digest", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("output_digest", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("output_truncated", sa.Boolean(), nullable=False),
        sa.Column("artifact_reference", sa.String(length=1000), nullable=True),
        sa.Column("failure_code", sa.String(length=60), nullable=True),
        sa.Column("failure_detail", sa.Text(), nullable=True),
        sa.Column("degradation_note", sa.Text(), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('pending','running','completed','failed','skipped','degraded')",
            name=op.f("ck_agent_steps_valid_step_status"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_agent_steps_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["agent_runs.id"],
            name=op.f("fk_agent_steps_run_id_agent_runs"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_steps")),
        sa.UniqueConstraint("run_id", "seq", name="unique_step_seq"),
    )
    op.create_table(
        "approvals",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("assessment_id", sa.UUID(), nullable=False),
        sa.Column("agent_run_id", sa.UUID(), nullable=True),
        sa.Column("kind", sa.String(length=40), nullable=False),
        sa.Column("decision", sa.String(length=40), nullable=False),
        sa.Column("prompt", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("requested_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("approved_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("risk_level", sa.String(length=20), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by_id", sa.UUID(), nullable=True),
        sa.Column("resolution_note", sa.Text(), nullable=True),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "decision = 'pending' OR decision = 'expired' OR resolved_by_id IS NOT NULL",
            name=op.f("ck_approvals_resolved_requires_actor"),
        ),
        sa.CheckConstraint(
            "decision IN ('pending','approved','approved_all','customized','rejected','expired')",
            name=op.f("ck_approvals_valid_decision"),
        ),
        sa.CheckConstraint(
            "kind IN ('scan_scope','high_risk_tool','remediation_apply','ticket_bulk_create')",
            name=op.f("ck_approvals_valid_approval_kind"),
        ),
        sa.CheckConstraint(
            "risk_level IN ('low','medium','high')",
            name=op.f("ck_approvals_valid_approval_risk"),
        ),
        sa.ForeignKeyConstraint(
            ["agent_run_id"],
            ["agent_runs.id"],
            name=op.f("fk_approvals_agent_run_id_agent_runs"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessments.id"],
            name=op.f("fk_approvals_assessment_id_assessments"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_approvals_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["resolved_by_id"],
            ["users.id"],
            name=op.f("fk_approvals_resolved_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_approvals")),
    )
    op.create_table(
        "asset_tags",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("key", sa.String(length=60), nullable=False),
        sa.Column("value", sa.String(length=200), nullable=True),
        sa.Column("applied_by_id", sa.UUID(), nullable=True),
        sa.Column("is_operator_applied", sa.Boolean(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["applied_by_id"],
            ["users.id"],
            name=op.f("fk_asset_tags_applied_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_asset_tags_asset_id_assets"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_asset_tags_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_asset_tags")),
        sa.UniqueConstraint("asset_id", "key", name="unique_tag"),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("assessment_id", sa.UUID(), nullable=True),
        sa.Column("asset_id", sa.UUID(), nullable=True),
        sa.Column("scanner_job_id", sa.UUID(), nullable=True),
        sa.Column("defectdojo_finding_id", sa.Integer(), nullable=False),
        sa.Column("defectdojo_test_id", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(length=1000), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("severity_raw", sa.String(length=40), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("scanner", sa.String(length=40), nullable=True),
        sa.Column("endpoint", sa.String(length=1000), nullable=True),
        sa.Column("component", sa.String(length=300), nullable=True),
        sa.Column("component_version", sa.String(length=80), nullable=True),
        sa.Column("cve_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("cwe", sa.Integer(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(length=200), nullable=True),
        sa.Column("is_duplicate", sa.Boolean(), nullable=False),
        sa.Column("is_false_positive", sa.Boolean(), nullable=False),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("priority", sa.String(length=4), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("risk_factors", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("ai_explanation", sa.Text(), nullable=True),
        sa.Column("ai_business_impact", sa.Text(), nullable=True),
        sa.Column("ai_attack_scenario", sa.Text(), nullable=True),
        sa.Column("ai_evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("ai_model", sa.String(length=120), nullable=True),
        sa.Column("ai_analyzed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ai_skipped_reason", sa.String(length=200), nullable=True),
        sa.Column("asset_criticality", sa.String(length=20), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "priority IS NULL OR priority IN ('P1','P2','P3','P4','P5')",
            name=op.f("ck_findings_valid_priority"),
        ),
        sa.CheckConstraint(
            "severity IN ('critical','high','medium','low','info')",
            name=op.f("ck_findings_valid_severity"),
        ),
        sa.CheckConstraint(
            "cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10", name=op.f("ck_findings_valid_cvss")
        ),
        sa.CheckConstraint(
            "risk_score IS NULL OR risk_score BETWEEN 0 AND 100",
            name=op.f("ck_findings_finding_risk_bounds"),
        ),
        sa.CheckConstraint(
            "status IN ('active','verified','false_positive','risk_accepted','out_of_scope',"
            "'mitigated','duplicate')",
            name=op.f("ck_findings_valid_finding_status"),
        ),
        sa.CheckConstraint(
            "asset_criticality IS NULL OR asset_criticality IN ('critical','high','normal',"
            "'low','unknown')",
            name=op.f("ck_findings_valid_asset_criticality"),
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessments.id"],
            name=op.f("fk_findings_assessment_id_assessments"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            name=op.f("fk_findings_asset_id_assets"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_findings_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["scanner_job_id"],
            ["scanner_jobs.id"],
            name=op.f("fk_findings_scanner_job_id_scanner_jobs"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
        sa.UniqueConstraint(
            "organization_id", "defectdojo_finding_id", name="unique_defectdojo_finding"
        ),
    )
    op.create_table(
        "scanner_artifacts",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("job_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=30), nullable=False),
        sa.Column("filename", sa.String(length=500), nullable=False),
        sa.Column("storage_key", sa.String(length=1000), nullable=False),
        sa.Column("content_type", sa.String(length=120), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "kind IN ('raw_output','stdout','stderr','report')",
            name=op.f("ck_scanner_artifacts_valid_artifact_kind"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["scanner_jobs.id"],
            name=op.f("fk_scanner_artifacts_job_id_scanner_jobs"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_scanner_artifacts_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scanner_artifacts")),
        sa.UniqueConstraint("job_id", "filename", name="unique_artifact_filename"),
    )
    op.create_table(
        "finding_enrichments",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("nvd_status", sa.String(length=30), nullable=False),
        sa.Column("nvd_published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("nvd_last_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("nvd_description", sa.Text(), nullable=True),
        sa.Column("nvd_cvss_v31_score", sa.Float(), nullable=True),
        sa.Column("nvd_cvss_v31_vector", sa.String(length=200), nullable=True),
        sa.Column("nvd_cwe_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("nvd_references", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("kev_status", sa.String(length=30), nullable=False),
        sa.Column("in_kev", sa.Boolean(), nullable=True),
        sa.Column("kev_date_added", sa.Date(), nullable=True),
        sa.Column("kev_due_date", sa.Date(), nullable=True),
        sa.Column("kev_ransomware_use", sa.String(length=40), nullable=True),
        sa.Column("kev_required_action", sa.Text(), nullable=True),
        sa.Column("epss_status", sa.String(length=30), nullable=False),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("misp_status", sa.String(length=30), nullable=False),
        sa.Column("misp_event_count", sa.Integer(), nullable=True),
        sa.Column("misp_attributes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("provider_errors", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("enriched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "epss_score IS NULL OR epss_score BETWEEN 0 AND 1",
            name=op.f("ck_finding_enrichments_valid_epss_score"),
        ),
        sa.CheckConstraint(
            "status IN ('pending','complete','partial','unavailable','not_applicable')",
            name=op.f("ck_finding_enrichments_valid_enrichment_status"),
        ),
        sa.CheckConstraint(
            "nvd_status IN ('pending','complete','partial','unavailable','not_applicable')",
            name=op.f("ck_finding_enrichments_valid_nvd_status"),
        ),
        sa.CheckConstraint(
            "kev_status IN ('pending','complete','partial','unavailable','not_applicable')",
            name=op.f("ck_finding_enrichments_valid_kev_status"),
        ),
        sa.CheckConstraint(
            "epss_status IN ('pending','complete','partial','unavailable','not_applicable')",
            name=op.f("ck_finding_enrichments_valid_epss_status"),
        ),
        sa.CheckConstraint(
            "misp_status IN ('pending','complete','partial','unavailable','not_applicable')",
            name=op.f("ck_finding_enrichments_valid_misp_status"),
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_finding_enrichments_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_finding_enrichments_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_finding_enrichments")),
        sa.UniqueConstraint("finding_id", name="unique_finding_enrichment"),
    )
    op.create_table(
        "remediations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("approach", sa.String(length=60), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("steps", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("code_patch", sa.Text(), nullable=True),
        sa.Column("patch_language", sa.String(length=40), nullable=True),
        sa.Column("configuration_change", sa.Text(), nullable=True),
        sa.Column("verification", sa.Text(), nullable=True),
        sa.Column("side_effects", sa.Text(), nullable=True),
        sa.Column("effort", sa.String(length=30), nullable=True),
        sa.Column("references", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("ai_model", sa.String(length=120), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by_id", sa.UUID(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_remediations_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_remediations_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["reviewed_by_id"],
            ["users.id"],
            name=op.f("fk_remediations_reviewed_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_remediations")),
    )
    op.create_table(
        "ticket_links",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=False),
        sa.Column("provider", sa.String(length=30), nullable=False),
        sa.Column("external_key", sa.String(length=80), nullable=False),
        sa.Column("external_id", sa.String(length=80), nullable=True),
        sa.Column("url", sa.String(length=1000), nullable=True),
        sa.Column("project_key", sa.String(length=40), nullable=True),
        sa.Column("issue_type", sa.String(length=60), nullable=True),
        sa.Column("external_status", sa.String(length=80), nullable=True),
        sa.Column("created_by_id", sa.UUID(), nullable=True),
        sa.Column("created_by_agent", sa.Boolean(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "provider IN ('jira','github','gitlab')",
            name=op.f("ck_ticket_links_valid_ticket_provider"),
        ),
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name=op.f("fk_ticket_links_created_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_ticket_links_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name=op.f("fk_ticket_links_organization_id_organizations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ticket_links")),
        sa.UniqueConstraint("finding_id", "provider", name="unique_ticket_per_finding"),
    )
    op.create_index(
        op.f("ix_organizations_created_at"), "organizations", ["created_at"], unique=False
    )
    op.create_index(op.f("ix_organizations_slug"), "organizations", ["slug"], unique=True)
    op.create_index(op.f("ix_users_created_at"), "users", ["created_at"], unique=False)
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
    op.create_index(
        op.f("ix_agent_sessions_created_at"), "agent_sessions", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_agent_sessions_last_activity_at"),
        "agent_sessions",
        ["last_activity_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_agent_sessions_organization_id"),
        "agent_sessions",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_agent_sessions_organization_id_last_activity_at",
        "agent_sessions",
        ["organization_id", "last_activity_at"],
        unique=False,
    )
    op.create_index(
        "ix_agent_sessions_organization_id_user_id",
        "agent_sessions",
        ["organization_id", "user_id"],
        unique=False,
    )
    op.create_index(op.f("ix_audit_events_action"), "audit_events", ["action"], unique=False)
    op.create_index(
        op.f("ix_audit_events_created_at"), "audit_events", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_audit_events_organization_id"), "audit_events", ["organization_id"], unique=False
    )
    op.create_index(
        "ix_audit_events_organization_id_action",
        "audit_events",
        ["organization_id", "action"],
        unique=False,
    )
    op.create_index(
        "ix_audit_events_organization_id_created_at",
        "audit_events",
        ["organization_id", "created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_audit_events_request_id"), "audit_events", ["request_id"], unique=False
    )
    op.create_index(
        "ix_audit_events_resource_type_resource_id",
        "audit_events",
        ["resource_type", "resource_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_integrations_created_at"), "integrations", ["created_at"], unique=False
    )
    op.create_index(op.f("ix_integrations_kind"), "integrations", ["kind"], unique=False)
    op.create_index(
        op.f("ix_integrations_organization_id"), "integrations", ["organization_id"], unique=False
    )
    op.create_index(
        "ix_integrations_organization_id_kind",
        "integrations",
        ["organization_id", "kind"],
        unique=False,
    )
    op.create_index(op.f("ix_memberships_created_at"), "memberships", ["created_at"], unique=False)
    op.create_index(
        "ix_memberships_user_id_organization_id",
        "memberships",
        ["user_id", "organization_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_notifications_created_at"), "notifications", ["created_at"], unique=False
    )
    op.create_index(op.f("ix_notifications_event"), "notifications", ["event"], unique=False)
    op.create_index(
        op.f("ix_notifications_organization_id"), "notifications", ["organization_id"], unique=False
    )
    op.create_index(
        "ix_notifications_organization_id_status",
        "notifications",
        ["organization_id", "status"],
        unique=False,
    )
    op.create_index(
        "ix_notifications_resource_type_resource_id",
        "notifications",
        ["resource_type", "resource_id"],
        unique=False,
    )
    op.create_index(op.f("ix_notifications_status"), "notifications", ["status"], unique=False)
    op.create_index(
        op.f("ix_password_reset_tokens_created_at"),
        "password_reset_tokens",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_password_reset_tokens_user_id"), "password_reset_tokens", ["user_id"], unique=False
    )
    op.create_index(op.f("ix_assessments_created_at"), "assessments", ["created_at"], unique=False)
    op.create_index(
        op.f("ix_assessments_organization_id"), "assessments", ["organization_id"], unique=False
    )
    op.create_index(
        "ix_assessments_organization_id_created_at",
        "assessments",
        ["organization_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_assessments_organization_id_status",
        "assessments",
        ["organization_id", "status"],
        unique=False,
    )
    op.create_index(op.f("ix_assessments_status"), "assessments", ["status"], unique=False)
    op.create_index(
        op.f("ix_integration_credentials_created_at"),
        "integration_credentials",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_integration_credentials_organization_id"),
        "integration_credentials",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_agent_runs_assessment_id_created_at",
        "agent_runs",
        ["assessment_id", "created_at"],
        unique=False,
    )
    op.create_index(op.f("ix_agent_runs_created_at"), "agent_runs", ["created_at"], unique=False)
    op.create_index(
        op.f("ix_agent_runs_organization_id"), "agent_runs", ["organization_id"], unique=False
    )
    op.create_index(
        "ix_agent_runs_organization_id_status",
        "agent_runs",
        ["organization_id", "status"],
        unique=False,
    )
    op.create_index(op.f("ix_agent_runs_status"), "agent_runs", ["status"], unique=False)
    op.create_index(op.f("ix_agent_runs_thread_id"), "agent_runs", ["thread_id"], unique=True)
    op.create_index(
        op.f("ix_assessment_targets_created_at"), "assessment_targets", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_assessment_targets_host"), "assessment_targets", ["host"], unique=False
    )
    op.create_index(
        op.f("ix_assessment_targets_organization_id"),
        "assessment_targets",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_assets_assessment_id_selected_for_scanning",
        "assets",
        ["assessment_id", "selected_for_scanning"],
        unique=False,
    )
    op.create_index(op.f("ix_assets_created_at"), "assets", ["created_at"], unique=False)
    op.create_index(op.f("ix_assets_criticality"), "assets", ["criticality"], unique=False)
    op.create_index(op.f("ix_assets_ip_address"), "assets", ["ip_address"], unique=False)
    op.create_index(op.f("ix_assets_last_seen_at"), "assets", ["last_seen_at"], unique=False)
    op.create_index(op.f("ix_assets_name"), "assets", ["name"], unique=False)
    op.create_index(op.f("ix_assets_organization_id"), "assets", ["organization_id"], unique=False)
    op.create_index(
        "ix_assets_organization_id_criticality",
        "assets",
        ["organization_id", "criticality"],
        unique=False,
    )
    op.create_index(op.f("ix_assets_status"), "assets", ["status"], unique=False)
    op.create_index(
        op.f("ix_authorization_records_created_at"),
        "authorization_records",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_authorization_records_organization_id"),
        "authorization_records",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_authorization_records_organization_id_target",
        "authorization_records",
        ["organization_id", "target"],
        unique=False,
    )
    op.create_index(
        op.f("ix_authorization_records_target"), "authorization_records", ["target"], unique=False
    )
    op.create_index(
        "ix_reports_assessment_id_created_at",
        "reports",
        ["assessment_id", "created_at"],
        unique=False,
    )
    op.create_index(op.f("ix_reports_created_at"), "reports", ["created_at"], unique=False)
    op.create_index(
        op.f("ix_reports_organization_id"), "reports", ["organization_id"], unique=False
    )
    op.create_index(
        "ix_reports_organization_id_status", "reports", ["organization_id", "status"], unique=False
    )
    op.create_index(op.f("ix_reports_status"), "reports", ["status"], unique=False)
    op.create_index(
        "ix_scanner_jobs_assessment_id_scanner",
        "scanner_jobs",
        ["assessment_id", "scanner"],
        unique=False,
    )
    op.create_index(
        op.f("ix_scanner_jobs_created_at"), "scanner_jobs", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_scanner_jobs_organization_id"), "scanner_jobs", ["organization_id"], unique=False
    )
    op.create_index(
        "ix_scanner_jobs_organization_id_status",
        "scanner_jobs",
        ["organization_id", "status"],
        unique=False,
    )
    op.create_index(op.f("ix_scanner_jobs_scanner"), "scanner_jobs", ["scanner"], unique=False)
    op.create_index(op.f("ix_scanner_jobs_status"), "scanner_jobs", ["status"], unique=False)
    op.create_index(
        "ix_scanner_jobs_worker_id_status", "scanner_jobs", ["worker_id", "status"], unique=False
    )
    op.create_index(
        op.f("ix_agent_messages_created_at"), "agent_messages", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_agent_messages_organization_id"),
        "agent_messages",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_agent_messages_session_id_seq", "agent_messages", ["session_id", "seq"], unique=False
    )
    op.create_index(op.f("ix_agent_steps_created_at"), "agent_steps", ["created_at"], unique=False)
    op.create_index(
        op.f("ix_agent_steps_organization_id"), "agent_steps", ["organization_id"], unique=False
    )
    op.create_index("ix_agent_steps_run_id_seq", "agent_steps", ["run_id", "seq"], unique=False)
    op.create_index(
        "ix_approvals_assessment_id_decision",
        "approvals",
        ["assessment_id", "decision"],
        unique=False,
    )
    op.create_index(op.f("ix_approvals_created_at"), "approvals", ["created_at"], unique=False)
    op.create_index(op.f("ix_approvals_decision"), "approvals", ["decision"], unique=False)
    op.create_index(
        op.f("ix_approvals_organization_id"), "approvals", ["organization_id"], unique=False
    )
    op.create_index(op.f("ix_asset_tags_created_at"), "asset_tags", ["created_at"], unique=False)
    op.create_index(
        op.f("ix_asset_tags_organization_id"), "asset_tags", ["organization_id"], unique=False
    )
    op.create_index(
        "ix_asset_tags_organization_id_key", "asset_tags", ["organization_id", "key"], unique=False
    )
    op.create_index(
        "ix_findings_assessment_id_severity",
        "findings",
        ["assessment_id", "severity"],
        unique=False,
    )
    op.create_index(op.f("ix_findings_created_at"), "findings", ["created_at"], unique=False)
    op.create_index(
        op.f("ix_findings_defectdojo_finding_id"),
        "findings",
        ["defectdojo_finding_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_findings_organization_id"), "findings", ["organization_id"], unique=False
    )
    op.create_index(
        "ix_findings_organization_id_priority",
        "findings",
        ["organization_id", "priority"],
        unique=False,
    )
    op.create_index(
        "ix_findings_organization_id_severity",
        "findings",
        ["organization_id", "severity"],
        unique=False,
    )
    op.create_index(op.f("ix_findings_priority"), "findings", ["priority"], unique=False)
    op.create_index(op.f("ix_findings_scanner"), "findings", ["scanner"], unique=False)
    op.create_index(op.f("ix_findings_severity"), "findings", ["severity"], unique=False)
    op.create_index(op.f("ix_findings_status"), "findings", ["status"], unique=False)
    op.create_index(
        op.f("ix_scanner_artifacts_created_at"), "scanner_artifacts", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_scanner_artifacts_organization_id"),
        "scanner_artifacts",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        "ix_scanner_artifacts_organization_id_kind",
        "scanner_artifacts",
        ["organization_id", "kind"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_enrichments_created_at"),
        "finding_enrichments",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_finding_enrichments_organization_id"),
        "finding_enrichments",
        ["organization_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_remediations_created_at"), "remediations", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_remediations_organization_id"), "remediations", ["organization_id"], unique=False
    )
    op.create_index(
        "ix_remediations_organization_id_finding_id",
        "remediations",
        ["organization_id", "finding_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_ticket_links_created_at"), "ticket_links", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_ticket_links_organization_id"), "ticket_links", ["organization_id"], unique=False
    )
    op.create_index(
        "ix_ticket_links_organization_id_provider",
        "ticket_links",
        ["organization_id", "provider"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_ticket_links_organization_id_provider", table_name="ticket_links")
    op.drop_index(op.f("ix_ticket_links_organization_id"), table_name="ticket_links")
    op.drop_index(op.f("ix_ticket_links_created_at"), table_name="ticket_links")
    op.drop_index("ix_remediations_organization_id_finding_id", table_name="remediations")
    op.drop_index(op.f("ix_remediations_organization_id"), table_name="remediations")
    op.drop_index(op.f("ix_remediations_created_at"), table_name="remediations")
    op.drop_index(op.f("ix_finding_enrichments_organization_id"), table_name="finding_enrichments")
    op.drop_index(op.f("ix_finding_enrichments_created_at"), table_name="finding_enrichments")
    op.drop_index("ix_scanner_artifacts_organization_id_kind", table_name="scanner_artifacts")
    op.drop_index(op.f("ix_scanner_artifacts_organization_id"), table_name="scanner_artifacts")
    op.drop_index(op.f("ix_scanner_artifacts_created_at"), table_name="scanner_artifacts")
    op.drop_index(op.f("ix_findings_status"), table_name="findings")
    op.drop_index(op.f("ix_findings_severity"), table_name="findings")
    op.drop_index(op.f("ix_findings_scanner"), table_name="findings")
    op.drop_index(op.f("ix_findings_priority"), table_name="findings")
    op.drop_index("ix_findings_organization_id_severity", table_name="findings")
    op.drop_index("ix_findings_organization_id_priority", table_name="findings")
    op.drop_index(op.f("ix_findings_organization_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_defectdojo_finding_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_created_at"), table_name="findings")
    op.drop_index("ix_findings_assessment_id_severity", table_name="findings")
    op.drop_index("ix_asset_tags_organization_id_key", table_name="asset_tags")
    op.drop_index(op.f("ix_asset_tags_organization_id"), table_name="asset_tags")
    op.drop_index(op.f("ix_asset_tags_created_at"), table_name="asset_tags")
    op.drop_index(op.f("ix_approvals_organization_id"), table_name="approvals")
    op.drop_index(op.f("ix_approvals_decision"), table_name="approvals")
    op.drop_index(op.f("ix_approvals_created_at"), table_name="approvals")
    op.drop_index("ix_approvals_assessment_id_decision", table_name="approvals")
    op.drop_index("ix_agent_steps_run_id_seq", table_name="agent_steps")
    op.drop_index(op.f("ix_agent_steps_organization_id"), table_name="agent_steps")
    op.drop_index(op.f("ix_agent_steps_created_at"), table_name="agent_steps")
    op.drop_index("ix_agent_messages_session_id_seq", table_name="agent_messages")
    op.drop_index(op.f("ix_agent_messages_organization_id"), table_name="agent_messages")
    op.drop_index(op.f("ix_agent_messages_created_at"), table_name="agent_messages")
    op.drop_index("ix_scanner_jobs_worker_id_status", table_name="scanner_jobs")
    op.drop_index(op.f("ix_scanner_jobs_status"), table_name="scanner_jobs")
    op.drop_index(op.f("ix_scanner_jobs_scanner"), table_name="scanner_jobs")
    op.drop_index("ix_scanner_jobs_organization_id_status", table_name="scanner_jobs")
    op.drop_index(op.f("ix_scanner_jobs_organization_id"), table_name="scanner_jobs")
    op.drop_index(op.f("ix_scanner_jobs_created_at"), table_name="scanner_jobs")
    op.drop_index("ix_scanner_jobs_assessment_id_scanner", table_name="scanner_jobs")
    op.drop_index(op.f("ix_reports_status"), table_name="reports")
    op.drop_index("ix_reports_organization_id_status", table_name="reports")
    op.drop_index(op.f("ix_reports_organization_id"), table_name="reports")
    op.drop_index(op.f("ix_reports_created_at"), table_name="reports")
    op.drop_index("ix_reports_assessment_id_created_at", table_name="reports")
    op.drop_index(op.f("ix_authorization_records_target"), table_name="authorization_records")
    op.drop_index(
        "ix_authorization_records_organization_id_target", table_name="authorization_records"
    )
    op.drop_index(
        op.f("ix_authorization_records_organization_id"), table_name="authorization_records"
    )
    op.drop_index(op.f("ix_authorization_records_created_at"), table_name="authorization_records")
    op.drop_index(op.f("ix_assets_status"), table_name="assets")
    op.drop_index("ix_assets_organization_id_criticality", table_name="assets")
    op.drop_index(op.f("ix_assets_organization_id"), table_name="assets")
    op.drop_index(op.f("ix_assets_name"), table_name="assets")
    op.drop_index(op.f("ix_assets_last_seen_at"), table_name="assets")
    op.drop_index(op.f("ix_assets_ip_address"), table_name="assets")
    op.drop_index(op.f("ix_assets_criticality"), table_name="assets")
    op.drop_index(op.f("ix_assets_created_at"), table_name="assets")
    op.drop_index("ix_assets_assessment_id_selected_for_scanning", table_name="assets")
    op.drop_index(
        op.f("ix_assessment_targets_organization_id"), table_name="assessment_targets"
    )
    op.drop_index(op.f("ix_assessment_targets_host"), table_name="assessment_targets")
    op.drop_index(op.f("ix_assessment_targets_created_at"), table_name="assessment_targets")
    op.drop_index(op.f("ix_agent_runs_thread_id"), table_name="agent_runs")
    op.drop_index(op.f("ix_agent_runs_status"), table_name="agent_runs")
    op.drop_index("ix_agent_runs_organization_id_status", table_name="agent_runs")
    op.drop_index(op.f("ix_agent_runs_organization_id"), table_name="agent_runs")
    op.drop_index(op.f("ix_agent_runs_created_at"), table_name="agent_runs")
    op.drop_index("ix_agent_runs_assessment_id_created_at", table_name="agent_runs")
    op.drop_index(
        op.f("ix_integration_credentials_organization_id"), table_name="integration_credentials"
    )
    op.drop_index(
        op.f("ix_integration_credentials_created_at"), table_name="integration_credentials"
    )
    op.drop_index(op.f("ix_assessments_status"), table_name="assessments")
    op.drop_index("ix_assessments_organization_id_status", table_name="assessments")
    op.drop_index("ix_assessments_organization_id_created_at", table_name="assessments")
    op.drop_index(op.f("ix_assessments_organization_id"), table_name="assessments")
    op.drop_index(op.f("ix_assessments_created_at"), table_name="assessments")
    op.drop_index(op.f("ix_password_reset_tokens_user_id"), table_name="password_reset_tokens")
    op.drop_index(op.f("ix_password_reset_tokens_created_at"), table_name="password_reset_tokens")
    op.drop_index(op.f("ix_notifications_status"), table_name="notifications")
    op.drop_index("ix_notifications_resource_type_resource_id", table_name="notifications")
    op.drop_index("ix_notifications_organization_id_status", table_name="notifications")
    op.drop_index(op.f("ix_notifications_organization_id"), table_name="notifications")
    op.drop_index(op.f("ix_notifications_event"), table_name="notifications")
    op.drop_index(op.f("ix_notifications_created_at"), table_name="notifications")
    op.drop_index("ix_memberships_user_id_organization_id", table_name="memberships")
    op.drop_index(op.f("ix_memberships_created_at"), table_name="memberships")
    op.drop_index("ix_integrations_organization_id_kind", table_name="integrations")
    op.drop_index(op.f("ix_integrations_organization_id"), table_name="integrations")
    op.drop_index(op.f("ix_integrations_kind"), table_name="integrations")
    op.drop_index(op.f("ix_integrations_created_at"), table_name="integrations")
    op.drop_index("ix_audit_events_resource_type_resource_id", table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_request_id"), table_name="audit_events")
    op.drop_index("ix_audit_events_organization_id_created_at", table_name="audit_events")
    op.drop_index("ix_audit_events_organization_id_action", table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_organization_id"), table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_created_at"), table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_action"), table_name="audit_events")
    op.drop_index("ix_agent_sessions_organization_id_user_id", table_name="agent_sessions")
    op.drop_index("ix_agent_sessions_organization_id_last_activity_at", table_name="agent_sessions")
    op.drop_index(op.f("ix_agent_sessions_organization_id"), table_name="agent_sessions")
    op.drop_index(op.f("ix_agent_sessions_last_activity_at"), table_name="agent_sessions")
    op.drop_index(op.f("ix_agent_sessions_created_at"), table_name="agent_sessions")
    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_index(op.f("ix_users_created_at"), table_name="users")
    op.drop_index(op.f("ix_organizations_slug"), table_name="organizations")
    op.drop_index(op.f("ix_organizations_created_at"), table_name="organizations")
    op.drop_table("ticket_links")
    op.drop_table("remediations")
    op.drop_table("finding_enrichments")
    op.drop_table("scanner_artifacts")
    op.drop_table("findings")
    op.drop_table("asset_tags")
    op.drop_table("approvals")
    op.drop_table("agent_steps")
    op.drop_table("agent_messages")
    op.drop_table("scanner_jobs")
    op.drop_table("reports")
    op.drop_table("authorization_records")
    op.drop_table("assets")
    op.drop_table("assessment_targets")
    op.drop_table("agent_runs")
    op.drop_table("integration_credentials")
    op.drop_table("assessments")
    op.drop_table("password_reset_tokens")
    op.drop_table("notifications")
    op.drop_table("memberships")
    op.drop_table("integrations")
    op.drop_table("audit_events")
    op.drop_table("agent_sessions")
    op.drop_table("users")
    op.drop_table("organizations")
