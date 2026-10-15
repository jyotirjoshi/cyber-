"""Add versioned report templates, snapshots, and durable distributions."""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision = "0087_report_templates"
down_revision = "0086_threat_feed_provenance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "report_templates",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("description", sa.String(1000)),
        sa.Column("definition", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True)),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("version > 0", name=op.f("ck_report_templates_valid_report_template_version")),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_report_templates")),
        sa.UniqueConstraint("organization_id", "name", "version", name="unique_report_template_version"),
    )
    op.create_index("ix_report_templates_org_active", "report_templates", ["organization_id", "is_active"])
    op.create_index(op.f("ix_report_templates_organization_id"), "report_templates", ["organization_id"])
    op.create_index(op.f("ix_report_templates_created_at"), "report_templates", ["created_at"])
    op.add_column("reports", sa.Column("template_id", postgresql.UUID(as_uuid=True)))
    op.add_column("reports", sa.Column("template_version", sa.Integer()))
    op.add_column("reports", sa.Column("template_snapshot", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False))
    op.create_foreign_key(op.f("fk_reports_template_id_report_templates"), "reports", "report_templates", ["template_id"], ["id"], ondelete="SET NULL")
    op.add_column("report_schedules", sa.Column("template_id", postgresql.UUID(as_uuid=True)))
    op.create_foreign_key(op.f("fk_report_schedules_template_id_report_templates"), "report_schedules", "report_templates", ["template_id"], ["id"], ondelete="SET NULL")
    op.create_table(
        "report_distributions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("report_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("schedule_id", postgresql.UUID(as_uuid=True)),
        sa.Column("channel", sa.String(20), nullable=False),
        sa.Column("destination", sa.String(1024), nullable=False),
        sa.Column("status", sa.String(20), server_default="pending", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("next_retry_at", sa.DateTime(timezone=True)),
        sa.Column("sent_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.String(1000)),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("channel IN ('email','webhook')", name=op.f("ck_report_distributions_valid_report_distribution_channel")),
        sa.CheckConstraint("status IN ('pending','sent','failed')", name=op.f("ck_report_distributions_valid_report_distribution_status")),
        sa.CheckConstraint("attempts >= 0", name=op.f("ck_report_distributions_valid_report_distribution_attempts")),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["report_id"], ["reports.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["schedule_id"], ["report_schedules.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_report_distributions")),
        sa.UniqueConstraint("report_id", "channel", "destination", name="unique_report_distribution_destination"),
    )
    op.create_index("ix_report_distributions_due", "report_distributions", ["status", "next_retry_at"])
    op.create_index(op.f("ix_report_distributions_organization_id"), "report_distributions", ["organization_id"])
    op.create_index(op.f("ix_report_distributions_created_at"), "report_distributions", ["created_at"])


def downgrade() -> None:
    op.drop_index(op.f("ix_report_distributions_created_at"), table_name="report_distributions")
    op.drop_index(op.f("ix_report_distributions_organization_id"), table_name="report_distributions")
    op.drop_index("ix_report_distributions_due", table_name="report_distributions")
    op.drop_table("report_distributions")
    op.drop_constraint(op.f("fk_report_schedules_template_id_report_templates"), "report_schedules", type_="foreignkey")
    op.drop_column("report_schedules", "template_id")
    op.drop_constraint(op.f("fk_reports_template_id_report_templates"), "reports", type_="foreignkey")
    op.drop_column("reports", "template_snapshot")
    op.drop_column("reports", "template_version")
    op.drop_column("reports", "template_id")
    op.drop_index(op.f("ix_report_templates_created_at"), table_name="report_templates")
    op.drop_index(op.f("ix_report_templates_organization_id"), table_name="report_templates")
    op.drop_index("ix_report_templates_org_active", table_name="report_templates")
    op.drop_table("report_templates")
