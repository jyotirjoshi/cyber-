"""Add durable visual workflow definitions and resumable executions."""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0083_durable_workflows"
down_revision = "0082_agent_decisions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "workflow_definitions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column(
            "nodes", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False
        ),
        sa.Column(
            "edges", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False
        ),
        sa.Column("is_enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("dry_run", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "version > 0", name=op.f("ck_workflow_definitions_valid_workflow_definition_version")
        ),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_workflow_definitions")),
        sa.UniqueConstraint("organization_id", "name", name="unique_workflow_definition_name"),
    )
    op.create_index(
        "ix_workflow_definitions_org_enabled",
        "workflow_definitions",
        ["organization_id", "is_enabled"],
    )
    op.create_index(
        "ix_workflow_definitions_due", "workflow_definitions", ["is_enabled", "next_run_at"]
    )
    op.create_index(
        op.f("ix_workflow_definitions_organization_id"), "workflow_definitions", ["organization_id"]
    )
    op.create_index(
        op.f("ix_workflow_definitions_created_at"), "workflow_definitions", ["created_at"]
    )

    op.create_table(
        "workflow_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workflow_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("definition_version", sa.Integer(), nullable=False),
        sa.Column(
            "definition", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column("event_key", sa.String(length=240), nullable=False),
        sa.Column("trigger", sa.String(length=80), nullable=False),
        sa.Column(
            "context", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column("status", sa.String(length=24), server_default="pending", nullable=False),
        sa.Column("dry_run", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("next_resume_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "definition_version > 0", name=op.f("ck_workflow_runs_valid_workflow_run_version")
        ),
        sa.CheckConstraint(
            "attempts >= 0", name=op.f("ck_workflow_runs_valid_workflow_run_attempts")
        ),
        sa.CheckConstraint(
            "status IN ('pending','running','waiting','succeeded','failed','cancelled','dry_run')",
            name=op.f("ck_workflow_runs_valid_workflow_run_status"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workflow_id"], ["workflow_definitions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_workflow_runs")),
        sa.UniqueConstraint("workflow_id", "event_key", name="unique_workflow_run_event"),
    )
    op.create_index(
        "ix_workflow_runs_org_status_resume",
        "workflow_runs",
        ["organization_id", "status", "next_resume_at"],
    )
    op.create_index(op.f("ix_workflow_runs_organization_id"), "workflow_runs", ["organization_id"])
    op.create_index(op.f("ix_workflow_runs_created_at"), "workflow_runs", ["created_at"])

    op.create_table(
        "workflow_step_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("node_id", sa.String(length=64), nullable=False),
        sa.Column("node_type", sa.String(length=24), nullable=False),
        sa.Column("status", sa.String(length=24), server_default="pending", nullable=False),
        sa.Column("attempt", sa.Integer(), server_default="1", nullable=False),
        sa.Column("max_attempts", sa.Integer(), server_default="3", nullable=False),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.Column(
            "input", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column(
            "output", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.Column("error_detail", sa.String(length=500), nullable=True),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "attempt > 0", name=op.f("ck_workflow_step_runs_valid_workflow_step_attempt")
        ),
        sa.CheckConstraint(
            "max_attempts BETWEEN 1 AND 10",
            name=op.f("ck_workflow_step_runs_valid_workflow_step_max_attempts"),
        ),
        sa.CheckConstraint(
            "status IN ('pending','running','waiting_approval','waiting_delay','succeeded','skipped','failed')",
            name=op.f("ck_workflow_step_runs_valid_workflow_step_status"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["workflow_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_workflow_step_runs")),
        sa.UniqueConstraint("idempotency_key", name="unique_workflow_step_idempotency"),
        sa.UniqueConstraint("run_id", "node_id", name="unique_workflow_step_node"),
    )
    op.create_index(
        "ix_workflow_steps_run_status", "workflow_step_runs", ["run_id", "status", "available_at"]
    )
    op.create_index(
        op.f("ix_workflow_step_runs_organization_id"), "workflow_step_runs", ["organization_id"]
    )
    op.create_index(op.f("ix_workflow_step_runs_created_at"), "workflow_step_runs", ["created_at"])


def downgrade() -> None:
    op.drop_index(op.f("ix_workflow_step_runs_created_at"), table_name="workflow_step_runs")
    op.drop_index(op.f("ix_workflow_step_runs_organization_id"), table_name="workflow_step_runs")
    op.drop_index("ix_workflow_steps_run_status", table_name="workflow_step_runs")
    op.drop_table("workflow_step_runs")
    op.drop_index(op.f("ix_workflow_runs_created_at"), table_name="workflow_runs")
    op.drop_index(op.f("ix_workflow_runs_organization_id"), table_name="workflow_runs")
    op.drop_index("ix_workflow_runs_org_status_resume", table_name="workflow_runs")
    op.drop_table("workflow_runs")
    op.drop_index(op.f("ix_workflow_definitions_created_at"), table_name="workflow_definitions")
    op.drop_index(
        op.f("ix_workflow_definitions_organization_id"), table_name="workflow_definitions"
    )
    op.drop_index("ix_workflow_definitions_org_enabled", table_name="workflow_definitions")
    op.drop_index("ix_workflow_definitions_due", table_name="workflow_definitions")
    op.drop_table("workflow_definitions")
