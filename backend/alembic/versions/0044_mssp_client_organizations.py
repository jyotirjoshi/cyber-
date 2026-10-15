"""Add parent-to-client organization relationships for MSSP portfolios.

Revision ID: 0044_mssp_client_organizations
Revises: 0043_agent_multi_provider_tickets
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0044_mssp_client_organizations"
down_revision = "0043_agent_multi_provider_tickets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column("parent_organization_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_organizations_parent_organization_id",
        "organizations",
        "organizations",
        ["parent_organization_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_organizations_parent_organization_id",
        "organizations",
        ["parent_organization_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_organizations_parent_organization_id", table_name="organizations")
    op.drop_constraint(
        "fk_organizations_parent_organization_id",
        "organizations",
        type_="foreignkey",
    )
    op.drop_column("organizations", "parent_organization_id")
