"""Align tenant and timestamp indexes with the ORM model contract.

Revision ID: 0073_tenant_model_indexes
Revises: 0072_asm_surface_tenant_fk
"""

from __future__ import annotations

from alembic import op

revision = "0073_tenant_model_indexes"
down_revision = "0072_asm_surface_tenant_fk"
branch_labels = None
depends_on = None


_INDEXES = (
    ("ix_agent_memories_created_at", "agent_memories", ["created_at"]),
    ("ix_agent_memories_organization_id", "agent_memories", ["organization_id"]),
    ("ix_asm_surfaces_organization_id", "asm_surfaces", ["organization_id"]),
    ("ix_dashboard_layouts_created_at", "dashboard_layouts", ["created_at"]),
    ("ix_dashboard_layouts_organization_id", "dashboard_layouts", ["organization_id"]),
    (
        "ix_finding_collaboration_comments_created_at",
        "finding_collaboration_comments",
        ["created_at"],
    ),
    (
        "ix_finding_collaboration_comments_organization_id",
        "finding_collaboration_comments",
        ["organization_id"],
    ),
    ("ix_usage_meter_buckets_organization_id", "usage_meter_buckets", ["organization_id"]),
)


def upgrade() -> None:
    for name, table, columns in _INDEXES:
        op.create_index(name, table, columns)


def downgrade() -> None:
    for name, table, _columns in reversed(_INDEXES):
        op.drop_index(name, table_name=table)
