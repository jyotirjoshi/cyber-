"""Add tenant-scoped public platform API keys.

Revision ID: 0027_m4_platform_api_keys
Revises: 0026_m3_remediation_governance
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0027_m4_platform_api_keys"
down_revision = "0026_m3_remediation_governance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "platform_api_keys",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("key_prefix", sa.String(32), nullable=False),
        sa.Column("secret_hash", sa.String(255), nullable=False),
        sa.Column("scopes", pg.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("created_by_id", pg.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "key_prefix", name="unique_platform_api_key_prefix"),
    )
    op.create_index(op.f("ix_platform_api_keys_organization_id"), "platform_api_keys", ["organization_id"])
    op.create_index(op.f("ix_platform_api_keys_created_at"), "platform_api_keys", ["created_at"])
    op.create_index("ix_platform_api_keys_org_active", "platform_api_keys", ["organization_id", "revoked_at", "expires_at"])


def downgrade() -> None:
    op.drop_index("ix_platform_api_keys_org_active", table_name="platform_api_keys")
    op.drop_index(op.f("ix_platform_api_keys_created_at"), table_name="platform_api_keys")
    op.drop_index(op.f("ix_platform_api_keys_organization_id"), table_name="platform_api_keys")
    op.drop_table("platform_api_keys")
