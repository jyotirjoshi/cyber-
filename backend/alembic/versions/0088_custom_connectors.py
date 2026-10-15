"""Add declarative custom connectors and resumable run history."""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision = "0088_custom_connectors"
down_revision = "0087_report_templates"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "custom_connectors",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("base_url", sa.String(1024), nullable=False),
        sa.Column("routes", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("pagination", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("field_mapping", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("output_type", sa.String(32), nullable=False),
        sa.Column("credential_integration_id", postgresql.UUID(as_uuid=True)),
        sa.Column("rate_limit_per_minute", sa.Integer(), server_default="60", nullable=False),
        sa.Column("is_enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True)),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("output_type IN ('external_alert','canonical_finding')", name=op.f("ck_custom_connectors_valid_custom_connector_output")),
        sa.CheckConstraint("rate_limit_per_minute BETWEEN 1 AND 600", name=op.f("ck_custom_connectors_valid_custom_connector_rate_limit")),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["credential_integration_id"], ["integrations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_custom_connectors")),
        sa.UniqueConstraint("organization_id", "name", name="unique_custom_connector_name"),
    )
    op.create_index("ix_custom_connectors_org_enabled", "custom_connectors", ["organization_id", "is_enabled"])
    op.create_index(op.f("ix_custom_connectors_organization_id"), "custom_connectors", ["organization_id"])
    op.create_index(op.f("ix_custom_connectors_created_at"), "custom_connectors", ["created_at"])
    op.create_table(
        "custom_connector_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("connector_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(20), server_default="running", nullable=False),
        sa.Column("checkpoint", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("result", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("records_read", sa.Integer(), server_default="0", nullable=False),
        sa.Column("records_written", sa.Integer(), server_default="0", nullable=False),
        sa.Column("error_code", sa.String(80)),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("status IN ('running','completed','failed')", name=op.f("ck_custom_connector_runs_valid_custom_connector_run_status")),
        sa.ForeignKeyConstraint(["connector_id"], ["custom_connectors.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_custom_connector_runs")),
    )
    op.create_index("ix_custom_connector_runs_org_connector_time", "custom_connector_runs", ["organization_id", "connector_id", "created_at"])
    op.create_index(op.f("ix_custom_connector_runs_organization_id"), "custom_connector_runs", ["organization_id"])
    op.create_index(op.f("ix_custom_connector_runs_created_at"), "custom_connector_runs", ["created_at"])


def downgrade() -> None:
    op.drop_index(op.f("ix_custom_connector_runs_created_at"), table_name="custom_connector_runs")
    op.drop_index(op.f("ix_custom_connector_runs_organization_id"), table_name="custom_connector_runs")
    op.drop_index("ix_custom_connector_runs_org_connector_time", table_name="custom_connector_runs")
    op.drop_table("custom_connector_runs")
    op.drop_index(op.f("ix_custom_connectors_created_at"), table_name="custom_connectors")
    op.drop_index(op.f("ix_custom_connectors_organization_id"), table_name="custom_connectors")
    op.drop_index("ix_custom_connectors_org_enabled", table_name="custom_connectors")
    op.drop_table("custom_connectors")
