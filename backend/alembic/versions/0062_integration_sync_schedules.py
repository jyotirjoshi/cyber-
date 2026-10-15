"""Add durable continuous synchronization state to integrations.

Revision ID: 0062_integration_sync_schedules
Revises: 0061_agent_wiz_sync
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0062_integration_sync_schedules"
down_revision = "0061_agent_wiz_sync"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("integrations", sa.Column("sync_interval_minutes", sa.Integer(), nullable=True))
    op.add_column(
        "integrations", sa.Column("next_sync_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "integrations", sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("integrations", sa.Column("last_sync_status", sa.String(20), nullable=True))
    op.add_column("integrations", sa.Column("last_sync_error", sa.Text(), nullable=True))
    op.add_column(
        "integrations",
        sa.Column("sync_failure_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_check_constraint(
        "valid_integration_sync_interval",
        "integrations",
        "sync_interval_minutes IS NULL OR sync_interval_minutes BETWEEN 5 AND 10080",
    )
    op.create_check_constraint(
        "valid_integration_sync_status",
        "integrations",
        "last_sync_status IS NULL OR last_sync_status IN ('succeeded','failed')",
    )
    op.create_index(
        "ix_integrations_due_sync",
        "integrations",
        ["next_sync_at", "id"],
        postgresql_where=sa.text(
            "is_enabled AND sync_interval_minutes IS NOT NULL AND next_sync_at IS NOT NULL"
        ),
    )


def downgrade() -> None:
    op.drop_index("ix_integrations_due_sync", table_name="integrations")
    op.drop_constraint("valid_integration_sync_status", "integrations", type_="check")
    op.drop_constraint("valid_integration_sync_interval", "integrations", type_="check")
    op.drop_column("integrations", "sync_failure_count")
    op.drop_column("integrations", "last_sync_error")
    op.drop_column("integrations", "last_sync_status")
    op.drop_column("integrations", "last_sync_at")
    op.drop_column("integrations", "next_sync_at")
    op.drop_column("integrations", "sync_interval_minutes")
