"""Add allowlisted custom dashboard layouts.

Revision ID: 0042_dashboard_layouts
Revises: 0041_usage_metering
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg
from alembic import op

revision = "0042_dashboard_layouts"
down_revision = "0041_usage_metering"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dashboard_layouts",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("audience", sa.String(20), nullable=False, server_default="technical"),
        sa.Column("widgets", pg.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by_id", pg.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name", name="unique_dashboard_layout_name"),
        sa.CheckConstraint("audience IN ('executive','technical','team')", name="valid_dashboard_layout_audience"),
    )
    op.create_index("ix_dashboard_layouts_org_audience", "dashboard_layouts", ["organization_id", "audience"])


def downgrade() -> None:
    op.drop_index("ix_dashboard_layouts_org_audience", table_name="dashboard_layouts")
    op.drop_table("dashboard_layouts")
