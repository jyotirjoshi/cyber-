"""Add bounded retry state to durable automation executions.

Revision ID: 0048_automation_execution_retries
Revises: 0047_ticket_closure_generations
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0048_automation_execution_retries"
down_revision = "0047_ticket_closure_generations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "automation_executions",
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )
    op.add_column(
        "automation_executions",
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.alter_column("automation_executions", "attempts", server_default=None)
    op.create_check_constraint(
        "valid_automation_execution_attempts",
        "automation_executions",
        "attempts >= 0",
    )
    op.create_index(
        "ix_automation_executions_due",
        "automation_executions",
        ["status", "next_retry_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_automation_executions_due", table_name="automation_executions")
    op.drop_constraint(
        "valid_automation_execution_attempts",
        "automation_executions",
        type_="check",
    )
    op.drop_column("automation_executions", "next_retry_at")
    op.drop_column("automation_executions", "attempts")
