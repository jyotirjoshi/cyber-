"""Add tenant-scoped SAML 2.0 trust connections.

Revision ID: 0036_m4_saml_connections
Revises: 0035_m4_report_share_links
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0036_m4_saml_connections"
down_revision = "0035_m4_report_share_links"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "saml_connections",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("sp_entity_id", sa.String(2048), nullable=False),
        sa.Column("idp_entity_id", sa.String(2048), nullable=False),
        sa.Column("idp_sso_url", sa.String(2048), nullable=False),
        sa.Column("idp_certificate_pem", sa.Text(), nullable=False),
        sa.Column("acs_url", sa.String(2048), nullable=False),
        sa.Column("allowed_email_domains", pg.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by_id", pg.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", name="unique_saml_connection_org"),
    )
    op.create_index("ix_saml_connections_organization_id", "saml_connections", ["organization_id"])
    op.create_index("ix_saml_connections_created_at", "saml_connections", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_saml_connections_created_at", table_name="saml_connections")
    op.drop_index("ix_saml_connections_organization_id", table_name="saml_connections")
    op.drop_table("saml_connections")
