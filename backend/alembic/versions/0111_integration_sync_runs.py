"""Add append-only integration sync execution receipts.

Revision ID: 0111_integration_sync_runs
Revises: 0110_agent_run_outcomes
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0111_integration_sync_runs"
down_revision = "0110_agent_run_outcomes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "integration_sync_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("integration_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_key", sa.String(160), nullable=False),
        sa.Column("mode", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("duration_ms", sa.Integer()),
        sa.Column("items_seen", sa.Integer(), nullable=False),
        sa.Column("items_staged", sa.Integer(), nullable=False),
        sa.Column("absence_candidates", sa.Integer(), nullable=False),
        sa.Column("checkpoint_before", postgresql.JSONB(), nullable=False),
        sa.Column("checkpoint_after", postgresql.JSONB(), nullable=False),
        sa.Column("error_code", sa.String(80)),
        sa.Column("error_summary", sa.String(500)),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("mode IN ('scheduled','manual','contract')", name=op.f("ck_integration_sync_runs_valid_sync_run_mode")),
        sa.CheckConstraint("status IN ('running','succeeded','failed')", name=op.f("ck_integration_sync_runs_valid_sync_run_status")),
        sa.CheckConstraint("items_seen >= 0 AND items_staged >= 0 AND absence_candidates >= 0", name=op.f("ck_integration_sync_runs_valid_sync_run_counts")),
        sa.CheckConstraint("duration_ms IS NULL OR duration_ms >= 0", name=op.f("ck_integration_sync_runs_valid_sync_run_duration")),
        sa.ForeignKeyConstraint(["integration_id"], ["integrations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_integration_sync_runs")),
        sa.UniqueConstraint("organization_id", "run_key", name="unique_integration_sync_run_key"),
    )
    op.create_index(op.f("ix_integration_sync_runs_organization_id"), "integration_sync_runs", ["organization_id"])
    op.create_index(op.f("ix_integration_sync_runs_created_at"), "integration_sync_runs", ["created_at"])
    op.create_index("ix_integration_sync_runs_org_started", "integration_sync_runs", ["organization_id", "started_at"])
    op.create_index("ix_integration_sync_runs_integration", "integration_sync_runs", ["integration_id", "started_at"])


def downgrade() -> None:
    op.drop_index("ix_integration_sync_runs_integration", table_name="integration_sync_runs")
    op.drop_index("ix_integration_sync_runs_org_started", table_name="integration_sync_runs")
    op.drop_index(op.f("ix_integration_sync_runs_created_at"), table_name="integration_sync_runs")
    op.drop_index(op.f("ix_integration_sync_runs_organization_id"), table_name="integration_sync_runs")
    op.drop_table("integration_sync_runs")
