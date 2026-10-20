"""Add digest-first AI worker evaluation suites and runs.

Revision ID: 0106_agent_evaluation_suites
Revises: 0105_response_action_execution
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0106_agent_evaluation_suites"
down_revision = "0105_response_action_execution"
branch_labels = None
depends_on = None


def _tenant_timestamps() -> list[sa.Column]:
    return [
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    ]


def _base(table: str) -> None:
    op.create_index(op.f(f"ix_{table}_organization_id"), table, ["organization_id"])
    op.create_index(op.f(f"ix_{table}_created_at"), table, ["created_at"])


def upgrade() -> None:
    op.create_table(
        "agent_evaluation_suites",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("suite_key", sa.String(128), nullable=False),
        sa.Column("name", sa.String(240), nullable=False),
        sa.Column("task_kind", sa.String(80), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("dataset_digest", sa.String(64), nullable=False),
        sa.Column("case_manifest", postgresql.JSONB(), nullable=False),
        sa.Column("thresholds", postgresql.JSONB(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True)),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "version > 0", name=op.f("ck_agent_evaluation_suites_valid_agent_evaluation_suite_version")
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name=op.f("fk_agent_evaluation_suites_organization_id_organizations"),
        ),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_evaluation_suites")),
        sa.UniqueConstraint(
            "organization_id", "suite_key", "version", name="unique_agent_evaluation_suite"
        ),
    )
    _base("agent_evaluation_suites")
    op.create_index(
        "ix_agent_evaluation_suites_org_active",
        "agent_evaluation_suites",
        ["organization_id", "active"],
    )

    op.create_table(
        "agent_evaluation_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("suite_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("agent_version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_key", sa.String(128), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("metrics", postgresql.JSONB(), nullable=False),
        sa.Column("failed_thresholds", postgresql.JSONB(), nullable=False),
        sa.Column("case_results", postgresql.JSONB(), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("total_cost_usd", sa.Numeric(12, 6), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        *_tenant_timestamps(),
        sa.CheckConstraint(
            "status IN ('completed','failed','superseded')",
            name=op.f("ck_agent_evaluation_runs_valid_agent_evaluation_run_status"),
        ),
        sa.CheckConstraint(
            "total_cost_usd >= 0",
            name=op.f("ck_agent_evaluation_runs_valid_agent_evaluation_run_cost"),
        ),
        sa.ForeignKeyConstraint(
            ["suite_id"], ["agent_evaluation_suites.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["agent_version_id"], ["agent_definition_versions.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name=op.f("fk_agent_evaluation_runs_organization_id_organizations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_evaluation_runs")),
        sa.UniqueConstraint(
            "organization_id", "run_key", name="unique_agent_evaluation_run_key"
        ),
    )
    _base("agent_evaluation_runs")
    op.create_index(
        "ix_agent_evaluation_runs_org_suite",
        "agent_evaluation_runs",
        ["organization_id", "suite_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_agent_evaluation_runs_org_suite", table_name="agent_evaluation_runs")
    op.drop_index(op.f("ix_agent_evaluation_runs_created_at"), table_name="agent_evaluation_runs")
    op.drop_index(
        op.f("ix_agent_evaluation_runs_organization_id"), table_name="agent_evaluation_runs"
    )
    op.drop_table("agent_evaluation_runs")
    op.drop_index(
        "ix_agent_evaluation_suites_org_active", table_name="agent_evaluation_suites"
    )
    op.drop_index(
        op.f("ix_agent_evaluation_suites_created_at"), table_name="agent_evaluation_suites"
    )
    op.drop_index(
        op.f("ix_agent_evaluation_suites_organization_id"),
        table_name="agent_evaluation_suites",
    )
    op.drop_table("agent_evaluation_suites")
