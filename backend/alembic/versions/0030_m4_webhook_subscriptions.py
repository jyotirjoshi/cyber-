"""Add signed tenant-owned outbound webhook subscriptions.

Revision ID: 0030_m4_webhook_subscriptions
Revises: 0029_m4_saved_views
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0030_m4_webhook_subscriptions"
down_revision = "0029_m4_saved_views"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "webhook_subscriptions",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("event_types", pg.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("secret_ciphertext", sa.Text(), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
        sa.Column("created_by_id", pg.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name", name="unique_webhook_subscription_name"),
    )
    op.create_index(op.f("ix_webhook_subscriptions_organization_id"), "webhook_subscriptions", ["organization_id"])
    op.create_index(op.f("ix_webhook_subscriptions_created_at"), "webhook_subscriptions", ["created_at"])
    op.create_index("ix_webhook_subscriptions_org_enabled", "webhook_subscriptions", ["organization_id", "is_enabled"])


def downgrade() -> None:
    op.drop_index("ix_webhook_subscriptions_org_enabled", table_name="webhook_subscriptions")
    op.drop_index(op.f("ix_webhook_subscriptions_created_at"), table_name="webhook_subscriptions")
    op.drop_index(op.f("ix_webhook_subscriptions_organization_id"), table_name="webhook_subscriptions")
    op.drop_table("webhook_subscriptions")
