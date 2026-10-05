"""Add tenant asset ownership, environment, and grouping metadata.

Revision ID: 0018_asset_business_context
Revises: 0017_canonical_findings
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0018_asset_business_context"
down_revision = "0017_canonical_findings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column(
            "owner_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
    )
    op.add_column("assets", sa.Column("owner_team", sa.String(length=120)))
    op.add_column(
        "assets",
        sa.Column("environment", sa.String(length=20), nullable=False, server_default="unknown"),
    )
    op.add_column(
        "assets",
        sa.Column("groups", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
    )
    op.create_check_constraint(
        op.f("ck_assets_valid_asset_environment"),
        "assets",
        "environment IN ('unknown','production','staging','development','test')",
    )
    op.create_index("ix_assets_organization_id_environment", "assets", ["organization_id", "environment"])


def downgrade() -> None:
    op.drop_index("ix_assets_organization_id_environment", table_name="assets")
    op.drop_constraint(op.f("ck_assets_valid_asset_environment"), "assets", type_="check")
    op.drop_column("assets", "groups")
    op.drop_column("assets", "environment")
    op.drop_column("assets", "owner_team")
    op.drop_column("assets", "owner_user_id")
