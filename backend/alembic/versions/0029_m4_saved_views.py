"""Add tenant-scoped saved query views.

Revision ID: 0029_m4_saved_views
Revises: 0028_m4_platform_api_key_audit_actor
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0029_m4_saved_views"
down_revision = "0028_m4_platform_api_key_audit_actor"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "saved_views",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("resource", sa.String(20), nullable=False),
        sa.Column("filters", pg.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_by_id", pg.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "resource IN ('findings','assets')",
            name=op.f("ck_saved_views_valid_saved_view_resource"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "resource", "name", name="unique_saved_view_name"),
    )
    op.create_index(op.f("ix_saved_views_organization_id"), "saved_views", ["organization_id"])
    op.create_index(op.f("ix_saved_views_created_at"), "saved_views", ["created_at"])
    op.create_index("ix_saved_views_org_resource", "saved_views", ["organization_id", "resource"])


def downgrade() -> None:
    op.drop_index("ix_saved_views_org_resource", table_name="saved_views")
    op.drop_index(op.f("ix_saved_views_created_at"), table_name="saved_views")
    op.drop_index(op.f("ix_saved_views_organization_id"), table_name="saved_views")
    op.drop_table("saved_views")
