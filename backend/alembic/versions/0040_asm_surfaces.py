"""Add asm_surfaces table for continuous Attack Surface Management discovery.

Revision ID: 0040_asm_surfaces
Revises: 0039_agent_memory
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0040_asm_surfaces"
down_revision = "0039_agent_memory"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "asm_surfaces",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("seeds", pg.JSONB(), nullable=False, server_default="[]"),
        sa.Column("cron_expression", sa.String(120), nullable=False),
        sa.Column("timezone", sa.String(100), nullable=False, server_default="UTC"),
        sa.Column("authorization_text", sa.Text(), nullable=False),
        sa.Column("authorization_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_asset_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_new_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error_code", sa.String(80), nullable=True),
        sa.Column("created_by_id", pg.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name", name="unique_asm_surface_name"),
    )
    op.create_index("ix_asm_surfaces_org_enabled", "asm_surfaces", ["organization_id", "enabled"])
    op.create_index("ix_asm_surfaces_due", "asm_surfaces", ["enabled", "next_run_at"])
    op.create_index("ix_asm_surfaces_created_at", "asm_surfaces", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_asm_surfaces_created_at", table_name="asm_surfaces")
    op.drop_index("ix_asm_surfaces_due", table_name="asm_surfaces")
    op.drop_index("ix_asm_surfaces_org_enabled", table_name="asm_surfaces")
    op.drop_table("asm_surfaces")
