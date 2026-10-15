"""Add durable autonomous specialist task records."""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0081_agent_specialist_tasks"
down_revision = "0080_fortify_direct_integration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_specialist_tasks",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("assessment_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scanner_job_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("plan_index", sa.Integer(), nullable=False),
        sa.Column("specialist", sa.String(length=40), nullable=False),
        sa.Column("scanner", sa.String(length=40), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("target_count", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("worker_id", sa.String(length=64), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("failure_code", sa.String(length=80), nullable=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("specialist IN ('network','web','code','secrets','supply_chain','container','cloud')", name=op.f("ck_agent_specialist_tasks_valid_agent_specialist_role")),
        sa.CheckConstraint("status IN ('pending','running','completed','degraded','failed')", name=op.f("ck_agent_specialist_tasks_valid_agent_specialist_status")),
        sa.CheckConstraint("target_count > 0", name=op.f("ck_agent_specialist_tasks_valid_agent_specialist_target_count")),
        sa.CheckConstraint("attempts >= 0 AND max_attempts BETWEEN 1 AND 10", name=op.f("ck_agent_specialist_tasks_valid_agent_specialist_attempts")),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["agent_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scanner_job_id"], ["scanner_jobs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_specialist_tasks")),
        sa.UniqueConstraint("run_id", "fingerprint", name="unique_agent_specialist_task"),
    )
    op.create_index("ix_agent_specialist_tasks_run_plan", "agent_specialist_tasks", ["run_id", "plan_index"])
    op.create_index("ix_agent_specialist_tasks_org_status", "agent_specialist_tasks", ["organization_id", "status"])
    op.create_index(op.f("ix_agent_specialist_tasks_organization_id"), "agent_specialist_tasks", ["organization_id"])
    op.create_index(op.f("ix_agent_specialist_tasks_created_at"), "agent_specialist_tasks", ["created_at"])
    op.create_index(op.f("ix_agent_specialist_tasks_status"), "agent_specialist_tasks", ["status"])


def downgrade() -> None:
    op.drop_index(op.f("ix_agent_specialist_tasks_status"), table_name="agent_specialist_tasks")
    op.drop_index(op.f("ix_agent_specialist_tasks_created_at"), table_name="agent_specialist_tasks")
    op.drop_index(op.f("ix_agent_specialist_tasks_organization_id"), table_name="agent_specialist_tasks")
    op.drop_index("ix_agent_specialist_tasks_org_status", table_name="agent_specialist_tasks")
    op.drop_index("ix_agent_specialist_tasks_run_plan", table_name="agent_specialist_tasks")
    op.drop_table("agent_specialist_tasks")
