"""Add exact terminal outcomes for durable AI runs.

Revision ID: 0110_agent_run_outcomes
Revises: 0109_soc_case_detection
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0110_agent_run_outcomes"
down_revision = "0109_soc_case_detection"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(op.f("ck_agent_runs_valid_run_status"), "agent_runs", type_="check")
    op.create_check_constraint(
        op.f("ck_agent_runs_valid_run_status"),
        "agent_runs",
        "status IN ('queued','running','interrupted','completed','partially_completed',"
        "'blocked','failed','cancelled')",
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE agent_runs SET status = CASE "
            "WHEN status = 'partially_completed' THEN 'completed' "
            "WHEN status = 'blocked' THEN 'failed' ELSE status END"
        )
    )
    op.drop_constraint(op.f("ck_agent_runs_valid_run_status"), "agent_runs", type_="check")
    op.create_check_constraint(
        op.f("ck_agent_runs_valid_run_status"),
        "agent_runs",
        "status IN ('queued','running','interrupted','completed','failed','cancelled')",
    )
