"""Add attributable compliance evidence-request workflow fields.

Revision ID: 0107_compliance_evidence_workflow
Revises: 0106_agent_evaluation_suites
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0107_compliance_evidence_workflow"
down_revision = "0106_agent_evaluation_suites"
branch_labels = None
depends_on = None


def upgrade() -> None:
    table = "compliance_evidence_requests"
    for column in ("requested_by_id", "submitted_by_id", "reviewed_by_id"):
        op.add_column(table, sa.Column(column, sa.UUID(), nullable=True))
        op.create_foreign_key(
            op.f(f"fk_{table}_{column}_users"),
            table,
            "users",
            [column],
            ["id"],
            ondelete="SET NULL",
        )
    op.add_column(table, sa.Column("review_note", sa.Text(), nullable=True))
    op.add_column(
        table,
        sa.Column(
            "status_changed_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.add_column(table, sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    table = "compliance_evidence_requests"
    op.drop_column(table, "submitted_at")
    op.drop_column(table, "status_changed_at")
    op.drop_column(table, "review_note")
    for column in ("reviewed_by_id", "submitted_by_id", "requested_by_id"):
        op.drop_constraint(op.f(f"fk_{table}_{column}_users"), table, type_="foreignkey")
        op.drop_column(table, column)
