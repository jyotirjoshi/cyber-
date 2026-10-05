"""Add durable run dispatch and recurring scan records.

Revision ID: 0024_m1_worker_core
Revises: 0023_canonical_tickets
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0024_m1_worker_core"
down_revision = "0023_canonical_tickets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scanner_jobs", sa.Column("idempotency_key", sa.String(length=160)))
    op.create_unique_constraint(
        op.f("uq_scanner_jobs_unique_scanner_job_idempotency_key"),
        "scanner_jobs", ["organization_id", "idempotency_key"],
    )
    op.create_table(
        "run_dispatches",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action", sa.String(length=10), nullable=False),
        sa.Column("dispatch_key", sa.String(length=160), nullable=False),
        sa.Column("principal", postgresql.JSONB()),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("stream_message_id", sa.String(length=64)),
        sa.Column("last_error_code", sa.String(length=80)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("organization_id", "dispatch_key", name=op.f("uq_run_dispatches_unique_run_dispatch_key")),
        sa.CheckConstraint("action IN ('start','resume')", name=op.f("ck_run_dispatches_valid_run_dispatch_action")),
        sa.CheckConstraint("status IN ('pending','sent')", name=op.f("ck_run_dispatches_valid_run_dispatch_status")),
    )
    op.create_index("ix_run_dispatches_organization_id", "run_dispatches", ["organization_id"])
    op.create_index("ix_run_dispatches_created_at", "run_dispatches", ["created_at"])
    op.create_index("ix_run_dispatches_status_available_at", "run_dispatches", ["status", "available_at"])

    op.create_table(
        "scan_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("config", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("organization_id", "name", name=op.f("uq_scan_profiles_unique_scan_profile_name")),
    )
    op.create_index("ix_scan_profiles_organization_id", "scan_profiles", ["organization_id"])
    op.create_index("ix_scan_profiles_created_at", "scan_profiles", ["created_at"])

    op.create_table(
        "recurring_scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("profile_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_profiles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("targets", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("cron_expression", sa.String(length=120), nullable=False),
        sa.Column("timezone", sa.String(length=100), nullable=False, server_default="UTC"),
        sa.Column("authorization_text", sa.Text(), nullable=False),
        sa.Column("authorization_evidence", sa.String(length=1024)),
        sa.Column("authorization_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_assessment_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("assessments.id", ondelete="SET NULL")),
        sa.Column("last_error_code", sa.String(length=80)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("organization_id", "name", name=op.f("uq_recurring_scans_unique_recurring_scan_name")),
    )
    op.create_index("ix_recurring_scans_organization_id", "recurring_scans", ["organization_id"])
    op.create_index("ix_recurring_scans_created_at", "recurring_scans", ["created_at"])
    op.create_index("ix_recurring_scans_due", "recurring_scans", ["enabled", "next_run_at"])

    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(
        op.f("ck_agent_actions_valid_agent_action"), "agent_actions",
        "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts','sync_sonarqube_alerts','sync_snyk_issues','sync_tenable_vulnerabilities','update_github_alert','create_jira_ticket','update_canonical_work')",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("uq_scanner_jobs_unique_scanner_job_idempotency_key"),
        "scanner_jobs", type_="unique",
    )
    op.drop_column("scanner_jobs", "idempotency_key")
    op.drop_constraint(op.f("ck_agent_actions_valid_agent_action"), "agent_actions", type_="check")
    op.create_check_constraint(
        op.f("ck_agent_actions_valid_agent_action"), "agent_actions",
        "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts','sync_sonarqube_alerts','sync_snyk_issues','update_github_alert','create_jira_ticket','update_canonical_work')",
    )
    op.drop_index("ix_recurring_scans_due", table_name="recurring_scans")
    op.drop_index("ix_recurring_scans_created_at", table_name="recurring_scans")
    op.drop_index("ix_recurring_scans_organization_id", table_name="recurring_scans")
    op.drop_table("recurring_scans")
    op.drop_index("ix_scan_profiles_created_at", table_name="scan_profiles")
    op.drop_index("ix_scan_profiles_organization_id", table_name="scan_profiles")
    op.drop_table("scan_profiles")
    op.drop_index("ix_run_dispatches_status_available_at", table_name="run_dispatches")
    op.drop_index("ix_run_dispatches_created_at", table_name="run_dispatches")
    op.drop_index("ix_run_dispatches_organization_id", table_name="run_dispatches")
    op.drop_table("run_dispatches")
