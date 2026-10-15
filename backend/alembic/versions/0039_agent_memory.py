"""Add curated tenant memory for the AI worker.

Revision ID: 0039_agent_memory
Revises: 0038_ptaas_finding_collaboration
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0039_agent_memory"
down_revision = "0038_ptaas_finding_collaboration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_memories",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("key", sa.String(120), nullable=False),
        sa.Column("category", sa.String(40), nullable=False, server_default="operational"),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("source", sa.String(40), nullable=False, server_default="manual"),
        sa.Column("created_by_id", pg.UUID(as_uuid=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "key", name="unique_agent_memory_key"),
        sa.CheckConstraint("category IN ('operational','architecture','remediation','scope','preference')", name="valid_agent_memory_category"),
        sa.CheckConstraint("source IN ('manual','approved_agent')", name="valid_agent_memory_source"),
    )
    op.create_index("ix_agent_memories_org_active_expiry", "agent_memories", ["organization_id", "is_active", "expires_at"])


def downgrade() -> None:
    op.drop_index("ix_agent_memories_org_active_expiry", table_name="agent_memories")
    op.drop_table("agent_memories")
