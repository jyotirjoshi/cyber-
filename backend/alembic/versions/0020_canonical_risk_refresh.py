"""Version tenant risk policies so workers can refresh stale scores.

Revision ID: 0020_canonical_risk_refresh
Revises: 0019_canonical_risk
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0020_canonical_risk_refresh"
down_revision = "0019_canonical_risk"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column("risk_policy_version", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "canonical_findings",
        sa.Column("risk_policy_version", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_check_constraint(
        op.f("ck_organizations_valid_risk_policy_version"),
        "organizations", "risk_policy_version >= 0",
    )
    op.create_check_constraint(
        op.f("ck_canonical_findings_valid_canonical_risk_policy_version"),
        "canonical_findings", "risk_policy_version >= 0",
    )
    op.create_index(
        "ix_canonical_findings_org_risk_policy_version", "canonical_findings",
        ["organization_id", "risk_policy_version"],
    )


def downgrade() -> None:
    op.drop_index("ix_canonical_findings_org_risk_policy_version", table_name="canonical_findings")
    op.drop_constraint(
        op.f("ck_canonical_findings_valid_canonical_risk_policy_version"),
        "canonical_findings", type_="check",
    )
    op.drop_constraint(
        op.f("ck_organizations_valid_risk_policy_version"),
        "organizations", type_="check",
    )
    op.drop_column("canonical_findings", "risk_policy_version")
    op.drop_column("organizations", "risk_policy_version")
