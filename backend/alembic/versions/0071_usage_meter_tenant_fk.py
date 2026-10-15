"""Enforce tenant ownership for usage meter buckets.

Revision ID: 0071_usage_meter_tenant_fk
Revises: 0070_direct_connector_agent_actions
"""

from __future__ import annotations

from alembic import op

revision = "0071_usage_meter_tenant_fk"
down_revision = "0070_direct_connector_agent_actions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_foreign_key(
        op.f("fk_usage_meter_buckets_organization_id_organizations"),
        "usage_meter_buckets",
        "organizations",
        ["organization_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("fk_usage_meter_buckets_organization_id_organizations"),
        "usage_meter_buckets",
        type_="foreignkey",
    )
