"""Add durable remediation grouping to canonical findings.

Revision ID: 0053_canonical_remediation_groups
Revises: 0052_retest_automation_triggers
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0053_canonical_remediation_groups"
down_revision = "0052_retest_automation_triggers"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "canonical_findings",
        sa.Column("remediation_group", sa.String(length=160), nullable=True),
    )
    op.create_index(
        "ix_canonical_findings_org_remediation_group",
        "canonical_findings",
        ["organization_id", "remediation_group"],
    )


def downgrade() -> None:
    op.drop_index("ix_canonical_findings_org_remediation_group", table_name="canonical_findings")
    op.drop_column("canonical_findings", "remediation_group")
