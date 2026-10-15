"""Add durable tenant-owned report schedules.

Revision ID: 0034_m4_report_schedules
Revises: 0033_m4_oidc_connections
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

from alembic import op

revision = "0034_m4_report_schedules"
down_revision = "0033_m4_oidc_connections"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "report_schedules",
        sa.Column("id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("assessment_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("created_by_id", pg.UUID(as_uuid=True)),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("title", sa.String(300)),
        sa.Column("format", sa.String(20), nullable=False, server_default="pdf"),
        sa.Column("audience", sa.String(30), nullable=False, server_default="executive"),
        sa.Column("cron_expression", sa.String(120), nullable=False),
        sa.Column("timezone", sa.String(80), nullable=False, server_default="UTC"),
        sa.Column("recipients", pg.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_report_id", pg.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["last_report_id"], ["reports.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "name", name="unique_report_schedule_name"),
        sa.CheckConstraint(
            "format IN ('html','pdf','json')",
            name=op.f("ck_report_schedules_valid_report_schedule_format"),
        ),
        sa.CheckConstraint(
            "audience IN ('executive','technical')",
            name=op.f("ck_report_schedules_valid_report_schedule_audience"),
        ),
    )
    op.create_index("ix_report_schedules_organization_id", "report_schedules", ["organization_id"])
    op.create_index("ix_report_schedules_created_at", "report_schedules", ["created_at"])
    op.create_index("ix_report_schedules_due", "report_schedules", ["is_enabled", "next_run_at"])


def downgrade() -> None:
    op.drop_index("ix_report_schedules_due", table_name="report_schedules")
    op.drop_index("ix_report_schedules_created_at", table_name="report_schedules")
    op.drop_index("ix_report_schedules_organization_id", table_name="report_schedules")
    op.drop_table("report_schedules")
