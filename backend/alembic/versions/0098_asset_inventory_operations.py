"""Add canonical asset merge history, aliases and topology relationships."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0098_asset_inventory_operations"
down_revision = "0097_automation_platform"
branch_labels = None
depends_on = None


def _tenant_columns() -> list[sa.Column]:
    return [
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    ]


def _tenant_constraints(table: str):
    return (
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{table}")),
    )


def _tenant_indexes(table: str) -> None:
    op.create_index(op.f(f"ix_{table}_organization_id"), table, ["organization_id"])
    op.create_index(op.f(f"ix_{table}_created_at"), table, ["created_at"])


def upgrade() -> None:
    op.add_column("assets", sa.Column("version", sa.Integer(), server_default="1", nullable=False))
    op.add_column("assets", sa.Column("merged_into_id", postgresql.UUID(as_uuid=True)))
    op.create_foreign_key(
        op.f("fk_assets_merged_into_id_assets"),
        "assets",
        "assets",
        ["merged_into_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(op.f("ix_assets_merged_into_id"), "assets", ["merged_into_id"])

    op.create_table(
        "asset_aliases",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("alias_type", sa.String(40), nullable=False),
        sa.Column("alias_value", sa.String(1024), nullable=False),
        sa.Column("source_asset_id", postgresql.UUID(as_uuid=True)),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True)),
        *_tenant_columns(),
        *_tenant_constraints("asset_aliases"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint(
            "organization_id", "alias_type", "alias_value", name="uq_asset_aliases_unique_asset_alias"
        ),
    )
    _tenant_indexes("asset_aliases")
    op.create_index("ix_asset_aliases_org_asset", "asset_aliases", ["organization_id", "asset_id"])

    op.create_table(
        "asset_relationships",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("relationship_type", sa.String(40), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True)),
        *_tenant_columns(),
        *_tenant_constraints("asset_relationships"),
        sa.ForeignKeyConstraint(["source_asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.CheckConstraint("source_asset_id <> target_asset_id", name="ck_asset_relationships_asset_relationship_no_self"),
        sa.CheckConstraint(
            "relationship_type IN ('depends_on','contains','hosts','connects_to','owned_by')",
            name="ck_asset_relationships_valid_asset_relationship_type",
        ),
        sa.UniqueConstraint(
            "organization_id", "source_asset_id", "target_asset_id", "relationship_type",
            name="uq_asset_relationships_unique_asset_relationship",
        ),
    )
    _tenant_indexes("asset_relationships")
    op.create_index("ix_asset_relationships_org_source", "asset_relationships", ["organization_id", "source_asset_id"])
    op.create_index("ix_asset_relationships_org_target", "asset_relationships", ["organization_id", "target_asset_id"])

    op.create_table(
        "asset_merge_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("merged_by_id", postgresql.UUID(as_uuid=True)),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("source_snapshot", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("moved_counts", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        *_tenant_columns(),
        *_tenant_constraints("asset_merge_events"),
        sa.ForeignKeyConstraint(["target_asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["merged_by_id"], ["users.id"], ondelete="SET NULL"),
    )
    _tenant_indexes("asset_merge_events")
    op.create_index("ix_asset_merge_events_org_target", "asset_merge_events", ["organization_id", "target_asset_id"])


def downgrade() -> None:
    for table, indexes in (
        ("asset_merge_events", ["ix_asset_merge_events_org_target"]),
        ("asset_relationships", ["ix_asset_relationships_org_target", "ix_asset_relationships_org_source"]),
        ("asset_aliases", ["ix_asset_aliases_org_asset"]),
    ):
        for index in indexes:
            op.drop_index(index, table_name=table)
        op.drop_index(op.f(f"ix_{table}_created_at"), table_name=table)
        op.drop_index(op.f(f"ix_{table}_organization_id"), table_name=table)
        op.drop_table(table)
    op.drop_index(op.f("ix_assets_merged_into_id"), table_name="assets")
    op.drop_constraint(op.f("fk_assets_merged_into_id_assets"), "assets", type_="foreignkey")
    op.drop_column("assets", "merged_into_id")
    op.drop_column("assets", "version")
