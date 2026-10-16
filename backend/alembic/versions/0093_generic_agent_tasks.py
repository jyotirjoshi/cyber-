"""Add durable generic multi-agent task graphs."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0093_generic_agent_tasks"
down_revision = "0092_graphql_mutation_receipts"
branch_labels = None
depends_on = None


TABLES = (
    "agent_tasks",
    "agent_task_dependencies",
    "agent_task_attempts",
    "agent_evidence",
    "agent_budget_reservations",
)


def _tenant_columns() -> tuple[sa.Column, sa.Column, sa.Column]:
    return (
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )


def _tenant_constraints() -> tuple[sa.ForeignKeyConstraint]:
    return (sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),)


def _tenant_indexes(table: str) -> None:
    op.create_index(f"ix_{table}_organization_id", table, ["organization_id"])
    op.create_index(f"ix_{table}_created_at", table, ["created_at"])


def _task_scope_fk(name: str, local_task_column: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        [local_task_column, "run_id", "organization_id"],
        ["agent_tasks.id", "agent_tasks.run_id", "agent_tasks.organization_id"],
        ondelete="CASCADE",
        name=name,
    )


def upgrade() -> None:
    op.add_column("agent_runs", sa.Column("objective", sa.Text(), nullable=True))
    op.add_column("agent_runs", sa.Column("stop_reason", sa.String(80), nullable=True))
    op.create_table(
        "agent_tasks",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("task_key", sa.String(80), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("idempotency_key", sa.String(160), nullable=False),
        sa.Column("payload_digest", sa.String(64), nullable=False),
        sa.Column("agent_version_id", postgresql.UUID(as_uuid=True)),
        sa.Column("tool_name", sa.String(120)),
        sa.Column("tool_version", sa.Integer(), nullable=False),
        sa.Column("input_schema_version", sa.String(40), nullable=False),
        sa.Column("output_schema_version", sa.String(40), nullable=False),
        sa.Column("input_payload", postgresql.JSONB(), nullable=False),
        sa.Column("orchestration", postgresql.JSONB(), nullable=False),
        sa.Column("output_summary", postgresql.JSONB(), nullable=False),
        sa.Column("required", sa.Boolean(), nullable=False),
        sa.Column("plan_index", sa.Integer(), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("current_lease_generation", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(80)),
        sa.Column("conflict_key", sa.String(200)),
        sa.Column("available_at", sa.DateTime(timezone=True)),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("settled_at", sa.DateTime(timezone=True)),
        sa.Column("cancellation_requested_at", sa.DateTime(timezone=True)),
        sa.Column("failure_code", sa.String(80)),
        sa.Column("failure_detail", sa.Text()),
        *_tenant_columns(),
        sa.CheckConstraint(
            "kind IN ('agent','tool','approval','join','decision','finalize')",
            name=op.f("ck_agent_tasks_valid_agent_task_kind"),
        ),
        sa.CheckConstraint(
            "status IN ('pending','blocked','ready','queued','running','awaiting_approval',"
            "'completed','degraded','skipped','failed','rejected','cancelled')",
            name=op.f("ck_agent_tasks_valid_agent_task_status"),
        ),
        sa.CheckConstraint(
            "plan_index >= 0", name=op.f("ck_agent_tasks_valid_agent_task_plan_index")
        ),
        sa.CheckConstraint(
            "tool_version > 0", name=op.f("ck_agent_tasks_valid_agent_task_tool_version")
        ),
        sa.CheckConstraint(
            "(kind = 'tool' AND tool_name IS NOT NULL AND agent_version_id IS NULL) OR "
            "(kind = 'agent' AND agent_version_id IS NOT NULL AND tool_name IS NULL) OR "
            "(kind <> 'tool' AND kind <> 'agent' AND tool_name IS NULL "
            "AND agent_version_id IS NULL)",
            name=op.f("ck_agent_tasks_valid_agent_task_executor_binding"),
        ),
        sa.CheckConstraint("priority >= 0", name=op.f("ck_agent_tasks_valid_agent_task_priority")),
        sa.CheckConstraint(
            "attempt_count >= 0 AND max_attempts BETWEEN 1 AND 10 "
            "AND current_lease_generation >= 0",
            name=op.f("ck_agent_tasks_valid_agent_task_attempts"),
        ),
        sa.ForeignKeyConstraint(["run_id"], ["agent_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["agent_version_id"],
            ["agent_definition_versions.id"],
            ondelete="RESTRICT",
        ),
        *_tenant_constraints(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_tasks")),
        sa.UniqueConstraint("run_id", "task_key", name="unique_agent_task_key"),
        sa.UniqueConstraint("run_id", "idempotency_key", name="unique_agent_task_idempotency"),
        sa.UniqueConstraint("id", "run_id", "organization_id", name="unique_agent_task_scope"),
    )
    _tenant_indexes("agent_tasks")
    op.create_index("ix_agent_tasks_run_plan", "agent_tasks", ["run_id", "plan_index"])
    op.create_index("ix_agent_tasks_agent_version_id", "agent_tasks", ["agent_version_id"])
    op.create_index(
        "ix_agent_tasks_org_status_available",
        "agent_tasks",
        ["organization_id", "status", "available_at"],
    )
    op.alter_column(
        "approvals",
        "assessment_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=True,
    )
    op.add_column(
        "approvals",
        sa.Column("agent_task_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "approvals",
        sa.Column("agent_version_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column("approvals", sa.Column("tool_name", sa.String(120), nullable=True))
    op.add_column("approvals", sa.Column("tool_version", sa.Integer(), nullable=True))
    op.add_column("approvals", sa.Column("payload_digest", sa.String(64), nullable=True))
    op.create_foreign_key(
        "fk_approvals_agent_task_id_agent_tasks",
        "approvals",
        "agent_tasks",
        ["agent_task_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_approvals_agent_version_id_agent_definition_versions",
        "approvals",
        "agent_definition_versions",
        ["agent_version_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_unique_constraint("unique_approvals_agent_task_id", "approvals", ["agent_task_id"])
    op.create_check_constraint(
        "ck_approvals_valid_approval_subject",
        "approvals",
        "assessment_id IS NOT NULL OR agent_task_id IS NOT NULL",
    )
    op.create_check_constraint(
        "ck_approvals_valid_agent_task_approval_binding",
        "approvals",
        "agent_task_id IS NULL OR (agent_run_id IS NOT NULL AND agent_version_id IS NOT NULL "
        "AND tool_name IS NOT NULL AND tool_version IS NOT NULL AND payload_digest IS NOT NULL)",
    )
    op.add_column(
        "run_dispatches",
        sa.Column("task_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_run_dispatches_task_id_agent_tasks",
        "run_dispatches",
        "agent_tasks",
        ["task_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index("ix_run_dispatches_task_id", "run_dispatches", ["task_id"])
    op.drop_constraint(
        "ck_run_dispatches_valid_run_dispatch_action",
        "run_dispatches",
        type_="check",
    )
    op.create_check_constraint(
        "ck_run_dispatches_valid_run_dispatch_action",
        "run_dispatches",
        "action IN ('start','resume','task')",
    )
    op.create_check_constraint(
        "ck_run_dispatches_valid_run_dispatch_task_binding",
        "run_dispatches",
        "(action = 'task' AND task_id IS NOT NULL) OR "
        "((action = 'start' OR action = 'resume') AND task_id IS NULL)",
    )
    op.drop_constraint(
        "ck_run_dispatches_valid_run_dispatch_status",
        "run_dispatches",
        type_="check",
    )
    op.create_check_constraint(
        "ck_run_dispatches_valid_run_dispatch_status",
        "run_dispatches",
        "status IN ('pending','sent','cancelled')",
    )

    op.create_table(
        "agent_task_dependencies",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("task_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("depends_on_task_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("dependency_kind", sa.String(20), nullable=False),
        *_tenant_columns(),
        sa.CheckConstraint(
            "task_id <> depends_on_task_id",
            name=op.f("ck_agent_task_dependencies_valid_agent_task_dependency_distinct"),
        ),
        sa.CheckConstraint(
            "dependency_kind IN ('required','optional')",
            name=op.f("ck_agent_task_dependencies_valid_agent_task_dependency_kind"),
        ),
        _task_scope_fk("fk_agent_task_dependency_task_scope", "task_id"),
        _task_scope_fk("fk_agent_task_dependency_parent_scope", "depends_on_task_id"),
        *_tenant_constraints(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_task_dependencies")),
        sa.UniqueConstraint("task_id", "depends_on_task_id", name="unique_agent_task_dependency"),
    )
    _tenant_indexes("agent_task_dependencies")
    op.create_index(
        "ix_agent_task_dependencies_run_task",
        "agent_task_dependencies",
        ["run_id", "task_id"],
    )
    op.create_index(
        "ix_agent_task_dependencies_parent",
        "agent_task_dependencies",
        ["depends_on_task_id"],
    )

    op.create_table(
        "agent_task_attempts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("task_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("lease_token_digest", sa.String(64), nullable=False),
        sa.Column("worker_id", sa.String(80), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("leased_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True)),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("settled_at", sa.DateTime(timezone=True)),
        sa.Column("result_digest", sa.String(64)),
        sa.Column("usage", postgresql.JSONB(), nullable=False),
        sa.Column("failure_code", sa.String(80)),
        sa.Column("failure_detail", sa.Text()),
        *_tenant_columns(),
        sa.CheckConstraint(
            "generation > 0",
            name=op.f("ck_agent_task_attempts_valid_agent_task_attempt_lease"),
        ),
        sa.CheckConstraint(
            "status IN ('claimed','running','completed','failed','cancelled','timed_out')",
            name=op.f("ck_agent_task_attempts_valid_agent_task_attempt_status"),
        ),
        _task_scope_fk("fk_agent_task_attempt_task_scope", "task_id"),
        *_tenant_constraints(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_task_attempts")),
        sa.UniqueConstraint("task_id", "generation", name="unique_agent_task_attempt_generation"),
    )
    _tenant_indexes("agent_task_attempts")
    op.create_index(
        "ix_agent_task_attempts_task_generation",
        "agent_task_attempts",
        ["task_id", "generation"],
    )
    op.create_index(
        "ix_agent_task_attempts_lease",
        "agent_task_attempts",
        ["status", "leased_until"],
    )

    op.create_table(
        "agent_evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("task_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("evidence_key", sa.String(160), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("artifact_reference", sa.String(1000), nullable=False),
        sa.Column("content_digest", sa.String(64), nullable=False),
        sa.Column("content_type", sa.String(160)),
        sa.Column("summary", postgresql.JSONB(), nullable=False),
        sa.Column("verified", sa.Boolean(), nullable=False),
        sa.Column("produced_at", sa.DateTime(timezone=True), nullable=False),
        *_tenant_columns(),
        sa.CheckConstraint(
            "kind IN ('observation','artifact','provider_receipt','approval','report','metric')",
            name=op.f("ck_agent_evidence_valid_agent_evidence_kind"),
        ),
        _task_scope_fk("fk_agent_evidence_task_scope", "task_id"),
        *_tenant_constraints(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_evidence")),
        sa.UniqueConstraint("task_id", "evidence_key", name="unique_agent_evidence_key"),
    )
    _tenant_indexes("agent_evidence")
    op.create_index("ix_agent_evidence_run_task", "agent_evidence", ["run_id", "task_id"])

    op.create_table(
        "agent_budget_reservations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("task_id", postgresql.UUID(as_uuid=True)),
        sa.Column("reservation_key", sa.String(160), nullable=False),
        sa.Column("category", sa.String(30), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("reserved_tasks", sa.Integer(), nullable=False),
        sa.Column("reserved_input_tokens", sa.BigInteger(), nullable=False),
        sa.Column("reserved_output_tokens", sa.BigInteger(), nullable=False),
        sa.Column("reserved_spend_micros", sa.BigInteger(), nullable=False),
        sa.Column("actual_tasks", sa.Integer(), nullable=False),
        sa.Column("actual_input_tokens", sa.BigInteger(), nullable=False),
        sa.Column("actual_output_tokens", sa.BigInteger(), nullable=False),
        sa.Column("actual_spend_micros", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("settled_at", sa.DateTime(timezone=True)),
        *_tenant_columns(),
        sa.CheckConstraint(
            "category IN ('model','tool','scanner','pipeline','run')",
            name=op.f("ck_agent_budget_reservations_valid_agent_budget_reservation_category"),
        ),
        sa.CheckConstraint(
            "status IN ('reserved','settled','released','forfeited')",
            name=op.f("ck_agent_budget_reservations_valid_agent_budget_reservation_status"),
        ),
        sa.CheckConstraint(
            "reserved_tasks >= 0 AND actual_tasks >= 0 AND reserved_input_tokens >= 0 "
            "AND reserved_output_tokens >= 0 "
            "AND reserved_spend_micros >= 0 AND actual_input_tokens >= 0 "
            "AND actual_output_tokens >= 0 AND actual_spend_micros >= 0",
            name=op.f("ck_agent_budget_reservations_valid_agent_budget_reservation_amounts"),
        ),
        sa.ForeignKeyConstraint(["run_id"], ["agent_runs.id"], ondelete="CASCADE"),
        _task_scope_fk("fk_agent_budget_reservation_task_scope", "task_id"),
        *_tenant_constraints(),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agent_budget_reservations")),
        sa.UniqueConstraint("run_id", "reservation_key", name="unique_agent_budget_reservation"),
    )
    _tenant_indexes("agent_budget_reservations")
    op.create_index(
        "ix_agent_budget_reservations_run_status",
        "agent_budget_reservations",
        ["run_id", "status"],
    )
    op.create_index(
        "ix_agent_budget_reservations_expiry",
        "agent_budget_reservations",
        ["status", "expires_at"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_run_dispatches_valid_run_dispatch_status",
        "run_dispatches",
        type_="check",
    )
    op.create_check_constraint(
        "ck_run_dispatches_valid_run_dispatch_status",
        "run_dispatches",
        "status IN ('pending','sent')",
    )
    op.drop_constraint(
        "ck_approvals_valid_agent_task_approval_binding",
        "approvals",
        type_="check",
    )
    op.drop_constraint(
        "ck_approvals_valid_approval_subject",
        "approvals",
        type_="check",
    )
    op.drop_constraint(
        "unique_approvals_agent_task_id",
        "approvals",
        type_="unique",
    )
    op.drop_constraint(
        "fk_approvals_agent_version_id_agent_definition_versions",
        "approvals",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_approvals_agent_task_id_agent_tasks",
        "approvals",
        type_="foreignkey",
    )
    op.drop_column("approvals", "payload_digest")
    op.drop_column("approvals", "tool_version")
    op.drop_column("approvals", "tool_name")
    op.drop_column("approvals", "agent_version_id")
    op.drop_column("approvals", "agent_task_id")
    op.execute("DELETE FROM approvals WHERE assessment_id IS NULL")
    op.alter_column(
        "approvals",
        "assessment_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=False,
    )
    op.drop_constraint(
        "ck_run_dispatches_valid_run_dispatch_task_binding",
        "run_dispatches",
        type_="check",
    )
    op.drop_constraint(
        "ck_run_dispatches_valid_run_dispatch_action",
        "run_dispatches",
        type_="check",
    )
    op.create_check_constraint(
        "ck_run_dispatches_valid_run_dispatch_action",
        "run_dispatches",
        "action IN ('start','resume')",
    )
    op.drop_index("ix_run_dispatches_task_id", table_name="run_dispatches")
    op.drop_constraint(
        "fk_run_dispatches_task_id_agent_tasks",
        "run_dispatches",
        type_="foreignkey",
    )
    op.drop_column("run_dispatches", "task_id")
    explicit_indexes = {
        "agent_budget_reservations": (
            "ix_agent_budget_reservations_expiry",
            "ix_agent_budget_reservations_run_status",
        ),
        "agent_evidence": ("ix_agent_evidence_run_task",),
        "agent_task_attempts": (
            "ix_agent_task_attempts_lease",
            "ix_agent_task_attempts_task_generation",
        ),
        "agent_task_dependencies": (
            "ix_agent_task_dependencies_parent",
            "ix_agent_task_dependencies_run_task",
        ),
        "agent_tasks": (
            "ix_agent_tasks_agent_version_id",
            "ix_agent_tasks_org_status_available",
            "ix_agent_tasks_run_plan",
        ),
    }
    for table in reversed(TABLES):
        for name in explicit_indexes.get(table, ()):
            op.drop_index(name, table_name=table)
        op.drop_index(f"ix_{table}_created_at", table_name=table)
        op.drop_index(f"ix_{table}_organization_id", table_name=table)
        op.drop_table(table)
    op.drop_column("agent_runs", "stop_reason")
    op.drop_column("agent_runs", "objective")
