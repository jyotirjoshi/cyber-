"""Add opaque expiring report share links.

Revision ID: 0035_m4_report_share_links
Revises: 0034_m4_report_schedules
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0035_m4_report_share_links"
down_revision = "0034_m4_report_schedules"
branch_labels = None
depends_on = None
def upgrade() -> None:
    op.create_table("report_share_links", sa.Column("id", pg.UUID(as_uuid=True), nullable=False), sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False), sa.Column("report_id", pg.UUID(as_uuid=True), nullable=False), sa.Column("token_prefix", sa.String(32), nullable=False), sa.Column("token_hash", sa.String(255), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("revoked_at", sa.DateTime(timezone=True)), sa.Column("created_by_id", pg.UUID(as_uuid=True)), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()), sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"), sa.ForeignKeyConstraint(["report_id"], ["reports.id"], ondelete="CASCADE"), sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"), sa.PrimaryKeyConstraint("id"), sa.UniqueConstraint("token_hash"), sa.UniqueConstraint("token_prefix"))
    op.create_index("ix_report_share_links_organization_id", "report_share_links", ["organization_id"])
    op.create_index("ix_report_share_links_created_at", "report_share_links", ["created_at"])
    op.create_index("ix_report_share_links_token_prefix", "report_share_links", ["token_prefix"])
    op.create_index("ix_report_share_links_org_report", "report_share_links", ["organization_id", "report_id"])
def downgrade() -> None:
    op.drop_index("ix_report_share_links_org_report", table_name="report_share_links")
    op.drop_index("ix_report_share_links_created_at", table_name="report_share_links")
    op.drop_index("ix_report_share_links_token_prefix", table_name="report_share_links")
    op.drop_index("ix_report_share_links_organization_id", table_name="report_share_links")
    op.drop_table("report_share_links")
