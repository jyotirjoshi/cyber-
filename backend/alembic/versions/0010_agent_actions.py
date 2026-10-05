"""Add individual approval records for agent actions.

Revision ID: 0010_agent_actions
Revises: 0009_external_alert_triage
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0010_agent_actions"
down_revision = "0009_external_alert_triage"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_actions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agent_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("agent_runs.id", ondelete="SET NULL")),
        sa.Column("requested_by_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("approved_by_user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("label", sa.String(length=300), nullable=False),
        sa.Column("rationale", sa.Text()),
        sa.Column("payload", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("payload_digest", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="pending"),
        sa.Column("resolved_at", sa.DateTime(timezone=True)),
        sa.Column("resolution_note", sa.Text()),
        sa.Column("executed_at", sa.DateTime(timezone=True)),
        sa.Column("result_summary", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts','create_jira_ticket')", name=op.f("ck_agent_actions_valid_agent_action")),
        sa.CheckConstraint("status IN ('pending','approved','rejected','executed','failed')", name=op.f("ck_agent_actions_valid_agent_action_status")),
        sa.CheckConstraint("status = 'pending' OR approved_by_user_id IS NOT NULL", name=op.f("ck_agent_actions_agent_action_resolution_requires_actor")),
    )
    op.create_index("ix_agent_actions_organization_id", "agent_actions", ["organization_id"])
    op.create_index("ix_agent_actions_status", "agent_actions", ["status"])
    op.create_index("ix_agent_actions_created_at", "agent_actions", ["created_at"])
    op.create_index("ix_agent_actions_org_session_status", "agent_actions", ["organization_id", "session_id", "status"])


def downgrade() -> None:
    op.drop_index("ix_agent_actions_org_session_status", table_name="agent_actions")
    op.drop_index("ix_agent_actions_created_at", table_name="agent_actions")
    op.drop_index("ix_agent_actions_status", table_name="agent_actions")
    op.drop_index("ix_agent_actions_organization_id", table_name="agent_actions")
    op.drop_table("agent_actions")
