"""Add durable, approval-bound agent execution workspaces."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0096_agent_workspaces"
down_revision = "0095_ptaas_engagements"
branch_labels = None
depends_on = None


def _tenant_columns() -> list[sa.Column]:
    return [
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    ]


def _tenant_constraints(table: str):
    return (
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f(f"pk_{table}")),
    )


def _tenant_indexes(table: str) -> None:
    op.create_index(op.f(f"ix_{table}_organization_id"), table, ["organization_id"])
    op.create_index(op.f(f"ix_{table}_created_at"), table, ["created_at"])


def _drop_tenant_indexes(table: str, *extra: str) -> None:
    for name in extra:
        op.drop_index(name, table_name=table)
    op.drop_index(op.f(f"ix_{table}_created_at"), table_name=table)
    op.drop_index(op.f(f"ix_{table}_organization_id"), table_name=table)


def upgrade() -> None:
    op.create_table(
        "agent_workspaces",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("max_bytes", sa.BigInteger(), nullable=False, server_default="1073741824"),
        sa.Column("used_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column(
            "manifest", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True)),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True)),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        *_tenant_columns(),
        sa.CheckConstraint(
            "status IN ('active','suspended','closed','expired')",
            name=op.f("ck_agent_workspaces_valid_agent_workspace_status"),
        ),
        sa.CheckConstraint(
            "max_bytes > 0 AND used_bytes >= 0 AND used_bytes <= max_bytes",
            name=op.f("ck_agent_workspaces_valid_agent_workspace_storage_quota"),
        ),
        sa.CheckConstraint(
            "version > 0", name=op.f("ck_agent_workspaces_valid_agent_workspace_version")
        ),
        sa.ForeignKeyConstraint(["run_id"], ["agent_runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("run_id", name="unique_agent_workspace_run"),
        *_tenant_constraints("agent_workspaces"),
    )
    _tenant_indexes("agent_workspaces")
    op.create_index(
        "ix_agent_workspaces_org_status", "agent_workspaces", ["organization_id", "status"]
    )
    op.create_index(
        "ix_agent_workspaces_expiry", "agent_workspaces", ["status", "expires_at"]
    )

    op.create_table(
        "agent_workspace_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("task_id", postgresql.UUID(as_uuid=True)),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("filename", sa.String(300), nullable=False),
        sa.Column("storage_key", sa.String(1000), nullable=False),
        sa.Column("content_type", sa.String(160), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column(
            "summary", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column("is_evidence", sa.Boolean(), nullable=False, server_default=sa.false()),
        *_tenant_columns(),
        sa.CheckConstraint(
            "kind IN ('input','output','screenshot','har','console','report','evidence','archive')",
            name=op.f("ck_agent_workspace_artifacts_valid_agent_workspace_artifact_kind"),
        ),
        sa.CheckConstraint(
            "size_bytes >= 0",
            name=op.f("ck_agent_workspace_artifacts_valid_agent_workspace_artifact_size"),
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"], ["agent_workspaces.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["task_id"], ["agent_tasks.id"], ondelete="SET NULL"),
        sa.UniqueConstraint(
            "workspace_id", "storage_key", name="unique_agent_workspace_artifact_key"
        ),
        *_tenant_constraints("agent_workspace_artifacts"),
    )
    _tenant_indexes("agent_workspace_artifacts")
    op.create_index(
        "ix_agent_workspace_artifacts_org_workspace",
        "agent_workspace_artifacts",
        ["organization_id", "workspace_id"],
    )

    op.create_table(
        "agent_workspace_credential_references",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("integration_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("label", sa.String(160), nullable=False),
        sa.Column(
            "allowed_tools", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        *_tenant_columns(),
        sa.CheckConstraint(
            "status IN ('active','revoked','expired')",
            name=op.f(
                "ck_agent_workspace_credential_references_valid_agent_workspace_credential_status"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"], ["agent_workspaces.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["integration_id"], ["integrations.id"], ondelete="CASCADE"
        ),
        sa.UniqueConstraint(
            "workspace_id",
            "integration_id",
            "label",
            name="unique_agent_workspace_credential",
        ),
        *_tenant_constraints("agent_workspace_credential_references"),
    )
    _tenant_indexes("agent_workspace_credential_references")
    op.create_index(
        "ix_agent_workspace_credentials_org_workspace",
        "agent_workspace_credential_references",
        ["organization_id", "workspace_id"],
    )

    op.create_table(
        "agent_workspace_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("namespace", sa.String(80), nullable=False),
        sa.Column("key", sa.String(160), nullable=False),
        sa.Column(
            "value", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_by_task_id", postgresql.UUID(as_uuid=True)),
        *_tenant_columns(),
        sa.CheckConstraint(
            "version > 0",
            name=op.f("ck_agent_workspace_records_valid_agent_workspace_record_version"),
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"], ["agent_workspaces.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["updated_by_task_id"], ["agent_tasks.id"], ondelete="SET NULL"
        ),
        sa.UniqueConstraint(
            "workspace_id", "namespace", "key", name="unique_agent_workspace_record"
        ),
        *_tenant_constraints("agent_workspace_records"),
    )
    _tenant_indexes("agent_workspace_records")
    op.create_index(
        "ix_agent_workspace_records_org_workspace",
        "agent_workspace_records",
        ["organization_id", "workspace_id"],
    )

    op.create_table(
        "agent_workspace_executions",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("task_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("approval_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_kind", sa.String(20), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="pending"),
        sa.Column("executable", sa.String(160), nullable=False),
        sa.Column(
            "argument_names", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
        sa.Column(
            "environment_names", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
        sa.Column("command_digest", sa.String(64), nullable=False),
        sa.Column(
            "result_summary", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        *_tenant_columns(),
        sa.CheckConstraint(
            "execution_kind IN ('shell','browser','scanner')",
            name=op.f(
                "ck_agent_workspace_executions_valid_agent_workspace_execution_kind"
            ),
        ),
        sa.CheckConstraint(
            "status IN ('pending','queued','running','completed','failed','cancelled')",
            name=op.f(
                "ck_agent_workspace_executions_valid_agent_workspace_execution_status"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["workspace_id"], ["agent_workspaces.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["task_id"], ["agent_tasks.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["approval_id"], ["approvals.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("task_id", name="unique_agent_workspace_execution_task"),
        *_tenant_constraints("agent_workspace_executions"),
    )
    _tenant_indexes("agent_workspace_executions")
    op.create_index(
        "ix_agent_workspace_executions_org_workspace",
        "agent_workspace_executions",
        ["organization_id", "workspace_id"],
    )
    op.create_index(
        "ix_agent_workspace_executions_status",
        "agent_workspace_executions",
        ["status", "created_at"],
    )


def downgrade() -> None:
    _drop_tenant_indexes(
        "agent_workspace_executions",
        "ix_agent_workspace_executions_status",
        "ix_agent_workspace_executions_org_workspace",
    )
    op.drop_table("agent_workspace_executions")
    _drop_tenant_indexes(
        "agent_workspace_records", "ix_agent_workspace_records_org_workspace"
    )
    op.drop_table("agent_workspace_records")
    _drop_tenant_indexes(
        "agent_workspace_credential_references",
        "ix_agent_workspace_credentials_org_workspace",
    )
    op.drop_table("agent_workspace_credential_references")
    _drop_tenant_indexes(
        "agent_workspace_artifacts", "ix_agent_workspace_artifacts_org_workspace"
    )
    op.drop_table("agent_workspace_artifacts")
    _drop_tenant_indexes(
        "agent_workspaces", "ix_agent_workspaces_expiry", "ix_agent_workspaces_org_status"
    )
    op.drop_table("agent_workspaces")


__all__ = ["upgrade", "downgrade"]
