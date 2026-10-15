"""Add tenant-scoped encrypted OIDC connections.

Revision ID: 0033_m4_oidc_connections
Revises: 0032_m4_scim_provisioning_tokens
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0033_m4_oidc_connections"
down_revision = "0032_m4_scim_provisioning_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "oidc_connections",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("issuer_url", sa.String(2048), nullable=False),
        sa.Column("client_id", sa.String(512), nullable=False),
        sa.Column("client_secret_ciphertext", sa.Text(), nullable=False),
        sa.Column("redirect_uri", sa.String(2048), nullable=False),
        sa.Column(
            "allowed_email_domains",
            pg.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by_id", pg.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", name="unique_oidc_connection_org"),
    )
    op.create_index("ix_oidc_connections_organization_id", "oidc_connections", ["organization_id"])
    op.create_index("ix_oidc_connections_created_at", "oidc_connections", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_oidc_connections_created_at", table_name="oidc_connections")
    op.drop_index("ix_oidc_connections_organization_id", table_name="oidc_connections")
    op.drop_table("oidc_connections")
