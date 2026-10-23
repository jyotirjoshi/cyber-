"""Add durable adaptive-agent supervisor decisions."""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0082_agent_decisions"
down_revision = "0081_agent_specialist_tasks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_decisions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("hypothesis", sa.Text(), nullable=True),
        sa.Column(
            "candidate_actions",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "accepted_actions",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "rejections",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "input_evidence_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=20), server_default="proposed", nullable=False),
        sa.Column("stop_reason", sa.String(length=80), nullable=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("sequence > 0", name=op.f("ck_agent_decisions_valid_agent_decision_sequence")),
        sa.CheckConstraint(
            "status IN ('proposed','dispatched','stopped','degraded')",
            name=op.f("ck_agent_decisions_valid_agent_decision_status"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["run_id"], ["agent_runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_decisions")),
        sa.UniqueConstraint("run_id", "sequence", name="unique_agent_decision_sequence"),
    )
    op.create_index(
        "ix_agent_decisions_run_sequence", "agent_decisions", ["run_id", "sequence"]
    )
    op.create_index(
        "ix_agent_decisions_org_status", "agent_decisions", ["organization_id", "status"]
    )
    op.create_index(
        op.f("ix_agent_decisions_organization_id"),
        "agent_decisions",
        ["organization_id"],
    )
    op.create_index(
        op.f("ix_agent_decisions_created_at"), "agent_decisions", ["created_at"]
    )
    op.create_index(op.f("ix_agent_decisions_status"), "agent_decisions", ["status"])


def downgrade() -> None:
    op.drop_index(op.f("ix_agent_decisions_status"), table_name="agent_decisions")
    op.drop_index(op.f("ix_agent_decisions_created_at"), table_name="agent_decisions")
    op.drop_index(op.f("ix_agent_decisions_organization_id"), table_name="agent_decisions")
    op.drop_index("ix_agent_decisions_org_status", table_name="agent_decisions")
    op.drop_index("ix_agent_decisions_run_sequence", table_name="agent_decisions")
    op.drop_table("agent_decisions")
