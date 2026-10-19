"""Make custom connector runs queueable and idempotent."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0094_custom_connector_execution"
down_revision = "0093_generic_agent_tasks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "custom_connector_runs", sa.Column("idempotency_key", sa.String(160), nullable=True)
    )
    op.add_column(
        "custom_connector_runs", sa.Column("request_digest", sa.String(64), nullable=True)
    )
    op.drop_constraint(
        op.f("ck_custom_connector_runs_valid_custom_connector_run_status"),
        "custom_connector_runs",
        type_="check",
    )
    op.create_check_constraint(
        "valid_custom_connector_run_status",
        "custom_connector_runs",
        "status IN ('pending','running','completed','failed')",
    )
    op.create_unique_constraint(
        "unique_custom_connector_run_idempotency",
        "custom_connector_runs",
        ["organization_id", "connector_id", "idempotency_key"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "unique_custom_connector_run_idempotency",
        "custom_connector_runs",
        type_="unique",
    )
    op.drop_constraint(
        op.f("ck_custom_connector_runs_valid_custom_connector_run_status"),
        "custom_connector_runs",
        type_="check",
    )
    op.create_check_constraint(
        "valid_custom_connector_run_status",
        "custom_connector_runs",
        "status IN ('running','completed','failed')",
    )
    op.drop_column("custom_connector_runs", "request_digest")
    op.drop_column("custom_connector_runs", "idempotency_key")

