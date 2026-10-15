"""Add tenant-scoped SCIM provisioning credentials.

Revision ID: 0032_m4_scim_provisioning_tokens
Revises: 0031_m4_webhook_notification_channel
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0032_m4_scim_provisioning_tokens"
down_revision = "0031_m4_webhook_notification_channel"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scim_provisioning_tokens",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("key_prefix", sa.String(32), nullable=False),
        sa.Column("secret_hash", sa.String(255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("created_by_id", pg.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "key_prefix", name="unique_scim_provisioning_key_prefix"),
    )
    op.create_index(
        "ix_scim_provisioning_tokens_organization_id",
        "scim_provisioning_tokens",
        ["organization_id"],
    )
    op.create_index(
        "ix_scim_provisioning_tokens_created_at", "scim_provisioning_tokens", ["created_at"]
    )
    op.create_index(
        "ix_scim_provisioning_tokens_org_active",
        "scim_provisioning_tokens",
        ["organization_id", "revoked_at", "expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_scim_provisioning_tokens_org_active", table_name="scim_provisioning_tokens")
    op.drop_index("ix_scim_provisioning_tokens_created_at", table_name="scim_provisioning_tokens")
    op.drop_index("ix_scim_provisioning_tokens_organization_id", table_name="scim_provisioning_tokens")
    op.drop_table("scim_provisioning_tokens")
