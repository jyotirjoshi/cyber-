"""Normalize remediation group matching without changing display labels.

Revision ID: 0055_canonical_remediation_group_keys
Revises: 0054_agent_remediation_group_retests
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0055_canonical_remediation_group_keys"
down_revision = "0054_agent_remediation_group_retests"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "canonical_findings",
        sa.Column("remediation_group_key", sa.String(length=160), nullable=True),
    )
    op.execute(
        sa.text(
            """
            UPDATE canonical_findings
            SET remediation_group_key = lower(btrim(remediation_group))
            WHERE remediation_group IS NOT NULL
              AND btrim(remediation_group) <> ''
            """
        )
    )
    op.drop_index("ix_canonical_findings_org_remediation_group", table_name="canonical_findings")
    op.create_index(
        "ix_canonical_findings_org_remediation_group",
        "canonical_findings",
        ["organization_id", "remediation_group_key"],
    )


def downgrade() -> None:
    op.drop_index("ix_canonical_findings_org_remediation_group", table_name="canonical_findings")
    op.create_index(
        "ix_canonical_findings_org_remediation_group",
        "canonical_findings",
        ["organization_id", "remediation_group"],
    )
    op.drop_column("canonical_findings", "remediation_group_key")
