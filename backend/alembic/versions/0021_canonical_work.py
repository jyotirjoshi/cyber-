"""Add remediation ownership and due dates to canonical findings.

Revision ID: 0021_canonical_work
Revises: 0020_canonical_risk_refresh
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0021_canonical_work"
down_revision = "0020_canonical_risk_refresh"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("canonical_findings", sa.Column(
        "assignee_user_id", postgresql.UUID(as_uuid=True), nullable=True,
    ))
    op.add_column("canonical_findings", sa.Column(
        "due_at", sa.DateTime(timezone=True), nullable=True,
    ))
    op.add_column("canonical_findings", sa.Column(
        "remediation_plan", sa.Text(), nullable=True,
    ))
    op.create_foreign_key(
        op.f("fk_canonical_findings_assignee_user_id_users"),
        "canonical_findings", "users", ["assignee_user_id"], ["id"], ondelete="SET NULL",
    )
    op.create_index(
        "ix_canonical_findings_org_assignee_due", "canonical_findings",
        ["organization_id", "assignee_user_id", "due_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_canonical_findings_org_assignee_due", table_name="canonical_findings")
    op.drop_constraint(
        op.f("fk_canonical_findings_assignee_user_id_users"),
        "canonical_findings", type_="foreignkey",
    )
    op.drop_column("canonical_findings", "remediation_plan")
    op.drop_column("canonical_findings", "due_at")
    op.drop_column("canonical_findings", "assignee_user_id")
