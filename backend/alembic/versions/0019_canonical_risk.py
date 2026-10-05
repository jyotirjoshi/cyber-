"""Persist reproducible canonical risk scores.

Revision ID: 0019_canonical_risk
Revises: 0018_asset_business_context
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0019_canonical_risk"
down_revision = "0018_asset_business_context"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "canonical_findings",
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
    )
    op.add_column(
        "canonical_findings",
        sa.Column(
            "risk_factors", postgresql.JSONB(), nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.create_check_constraint(
        op.f("ck_canonical_findings_valid_canonical_risk_score"),
        "canonical_findings", "risk_score BETWEEN 0 AND 100",
    )
    op.create_index(
        "ix_canonical_findings_org_status_risk", "canonical_findings",
        ["organization_id", "status", "risk_score"],
    )


def downgrade() -> None:
    op.drop_index("ix_canonical_findings_org_status_risk", table_name="canonical_findings")
    op.drop_constraint(
        op.f("ck_canonical_findings_valid_canonical_risk_score"),
        "canonical_findings", type_="check",
    )
    op.drop_column("canonical_findings", "risk_factors")
    op.drop_column("canonical_findings", "risk_score")
