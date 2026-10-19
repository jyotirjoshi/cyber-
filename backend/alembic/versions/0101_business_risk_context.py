"""Add business services, asset dependencies, and financial risk scenarios."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0101_business_risk_context"
down_revision = "0100_governed_validation_policy"
branch_labels = None
depends_on = None


def _tenant_timestamps() -> list[sa.Column]:
    return [
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "business_services",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("slug", sa.String(120), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("owner_team", sa.String(120)),
        sa.Column("owner_user_id", postgresql.UUID(as_uuid=True)),
        sa.Column("criticality", sa.String(20), server_default="normal", nullable=False),
        sa.Column("environment", sa.String(20), server_default="production", nullable=False),
        sa.Column("revenue_per_hour_usd", sa.Float()),
        sa.Column("maximum_loss_usd", sa.Float()),
        sa.Column("data_records_at_risk", sa.Integer()),
        sa.Column("regulatory_scopes", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("metadata", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("status", sa.String(20), server_default="active", nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        *_tenant_timestamps(),
        sa.CheckConstraint("criticality IN ('critical','high','normal','low')", name="ck_business_services_valid_business_service_criticality"),
        sa.CheckConstraint("environment IN ('production','staging','development','test')", name="ck_business_services_valid_business_service_environment"),
        sa.CheckConstraint("status IN ('active','retired')", name="ck_business_services_valid_business_service_status"),
        sa.CheckConstraint("version > 0", name="ck_business_services_valid_business_service_version"),
        sa.CheckConstraint("revenue_per_hour_usd IS NULL OR revenue_per_hour_usd >= 0", name="ck_business_services_valid_business_service_revenue"),
        sa.CheckConstraint("maximum_loss_usd IS NULL OR maximum_loss_usd >= 0", name="ck_business_services_valid_business_service_maximum_loss"),
        sa.CheckConstraint("data_records_at_risk IS NULL OR data_records_at_risk >= 0", name="ck_business_services_valid_business_service_records"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_business_services")),
        sa.UniqueConstraint("organization_id", "slug", name="unique_business_service_slug"),
    )
    op.create_index("ix_business_services_org_status", "business_services", ["organization_id", "status"])
    op.create_index(op.f("ix_business_services_organization_id"), "business_services", ["organization_id"])
    op.create_index(op.f("ix_business_services_created_at"), "business_services", ["created_at"])

    op.create_table(
        "asset_business_services",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("business_service_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("dependency_type", sa.String(30), server_default="supporting", nullable=False),
        sa.Column("importance_weight", sa.Float(), server_default="1", nullable=False),
        sa.Column("recovery_time_minutes", sa.Integer()),
        sa.Column("recovery_point_minutes", sa.Integer()),
        sa.Column("provenance", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        *_tenant_timestamps(),
        sa.CheckConstraint("dependency_type IN ('primary','supporting','data_store','identity','network')", name="ck_asset_business_services_valid_business_service_dependency_type"),
        sa.CheckConstraint("importance_weight BETWEEN 0.1 AND 10", name="ck_asset_business_services_valid_business_service_importance"),
        sa.CheckConstraint("recovery_time_minutes IS NULL OR recovery_time_minutes >= 0", name="ck_asset_business_services_valid_business_service_rto"),
        sa.CheckConstraint("recovery_point_minutes IS NULL OR recovery_point_minutes >= 0", name="ck_asset_business_services_valid_business_service_rpo"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["business_service_id"], ["business_services.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_asset_business_services")),
        sa.UniqueConstraint("asset_id", "business_service_id", name="unique_asset_business_service"),
    )
    op.create_index("ix_asset_business_services_org_service", "asset_business_services", ["organization_id", "business_service_id"])
    op.create_index("ix_asset_business_services_org_asset", "asset_business_services", ["organization_id", "asset_id"])
    op.create_index(op.f("ix_asset_business_services_organization_id"), "asset_business_services", ["organization_id"])
    op.create_index(op.f("ix_asset_business_services_created_at"), "asset_business_services", ["created_at"])

    op.create_table(
        "business_risk_scenarios",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("business_service_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("threat_event", sa.String(200), nullable=False),
        sa.Column("annual_probability", sa.Float(), nullable=False),
        sa.Column("loss_min_usd", sa.Float(), nullable=False),
        sa.Column("loss_likely_usd", sa.Float(), nullable=False),
        sa.Column("loss_max_usd", sa.Float(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("status", sa.String(20), server_default="active", nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        *_tenant_timestamps(),
        sa.CheckConstraint("annual_probability BETWEEN 0 AND 1", name="ck_business_risk_scenarios_valid_risk_scenario_probability"),
        sa.CheckConstraint("loss_min_usd >= 0 AND loss_likely_usd >= loss_min_usd AND loss_max_usd >= loss_likely_usd", name="ck_business_risk_scenarios_valid_risk_scenario_loss_range"),
        sa.CheckConstraint("status IN ('active','archived')", name="ck_business_risk_scenarios_valid_risk_scenario_status"),
        sa.ForeignKeyConstraint(["business_service_id"], ["business_services.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_business_risk_scenarios")),
        sa.UniqueConstraint("business_service_id", "name", name="unique_business_service_risk_scenario"),
    )
    op.create_index("ix_business_risk_scenarios_org_service", "business_risk_scenarios", ["organization_id", "business_service_id"])
    op.create_index(op.f("ix_business_risk_scenarios_organization_id"), "business_risk_scenarios", ["organization_id"])
    op.create_index(op.f("ix_business_risk_scenarios_created_at"), "business_risk_scenarios", ["created_at"])


def downgrade() -> None:
    op.drop_index(op.f("ix_business_risk_scenarios_created_at"), table_name="business_risk_scenarios")
    op.drop_index(op.f("ix_business_risk_scenarios_organization_id"), table_name="business_risk_scenarios")
    op.drop_index("ix_business_risk_scenarios_org_service", table_name="business_risk_scenarios")
    op.drop_table("business_risk_scenarios")
    op.drop_index(op.f("ix_asset_business_services_created_at"), table_name="asset_business_services")
    op.drop_index(op.f("ix_asset_business_services_organization_id"), table_name="asset_business_services")
    op.drop_index("ix_asset_business_services_org_asset", table_name="asset_business_services")
    op.drop_index("ix_asset_business_services_org_service", table_name="asset_business_services")
    op.drop_table("asset_business_services")
    op.drop_index(op.f("ix_business_services_created_at"), table_name="business_services")
    op.drop_index(op.f("ix_business_services_organization_id"), table_name="business_services")
    op.drop_index("ix_business_services_org_status", table_name="business_services")
    op.drop_table("business_services")
