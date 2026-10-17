"""Durable, tenant-scoped workspaces for governed agent execution."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantMixin, TimestampMixin, uuid_pk


class AgentWorkspace(Base, TenantMixin, TimestampMixin):
    __tablename__ = "agent_workspaces"

    id: Mapped[uuid.UUID] = uuid_pk()
    run_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    max_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1_073_741_824)
    used_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    manifest: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        CheckConstraint(
            "status IN ('active','suspended','closed','expired')",
            name="valid_agent_workspace_status",
        ),
        CheckConstraint(
            "max_bytes > 0 AND used_bytes >= 0 AND used_bytes <= max_bytes",
            name="valid_agent_workspace_storage_quota",
        ),
        CheckConstraint("version > 0", name="valid_agent_workspace_version"),
        UniqueConstraint("run_id", name="unique_agent_workspace_run"),
        Index("ix_agent_workspaces_org_status", "organization_id", "status"),
        Index("ix_agent_workspaces_expiry", "status", "expires_at"),
    )


class AgentWorkspaceArtifact(Base, TenantMixin, TimestampMixin):
    __tablename__ = "agent_workspace_artifacts"

    id: Mapped[uuid.UUID] = uuid_pk()
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_workspaces.id", ondelete="CASCADE"), nullable=False
    )
    task_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_tasks.id", ondelete="SET NULL")
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    filename: Mapped[str] = mapped_column(String(300), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(1000), nullable=False)
    content_type: Mapped[str] = mapped_column(String(160), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    is_evidence: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (
        CheckConstraint(
            "kind IN ('input','output','screenshot','har','console','report','evidence','archive')",
            name="valid_agent_workspace_artifact_kind",
        ),
        CheckConstraint("size_bytes >= 0", name="valid_agent_workspace_artifact_size"),
        UniqueConstraint("workspace_id", "storage_key", name="unique_agent_workspace_artifact_key"),
        Index("ix_agent_workspace_artifacts_org_workspace", "organization_id", "workspace_id"),
    )


class AgentWorkspaceCredentialReference(Base, TenantMixin, TimestampMixin):
    __tablename__ = "agent_workspace_credential_references"

    id: Mapped[uuid.UUID] = uuid_pk()
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_workspaces.id", ondelete="CASCADE"), nullable=False
    )
    integration_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("integrations.id", ondelete="CASCADE"), nullable=False
    )
    label: Mapped[str] = mapped_column(String(160), nullable=False)
    allowed_tools: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(
            "status IN ('active','revoked','expired')",
            name="valid_agent_workspace_credential_status",
        ),
        UniqueConstraint(
            "workspace_id", "integration_id", "label", name="unique_agent_workspace_credential"
        ),
        Index(
            "ix_agent_workspace_credentials_org_workspace", "organization_id", "workspace_id"
        ),
    )


class AgentWorkspaceRecord(Base, TenantMixin, TimestampMixin):
    __tablename__ = "agent_workspace_records"

    id: Mapped[uuid.UUID] = uuid_pk()
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_workspaces.id", ondelete="CASCADE"), nullable=False
    )
    namespace: Mapped[str] = mapped_column(String(80), nullable=False)
    key: Mapped[str] = mapped_column(String(160), nullable=False)
    value: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    updated_by_task_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_tasks.id", ondelete="SET NULL")
    )

    __table_args__ = (
        CheckConstraint("version > 0", name="valid_agent_workspace_record_version"),
        UniqueConstraint(
            "workspace_id", "namespace", "key", name="unique_agent_workspace_record"
        ),
        Index("ix_agent_workspace_records_org_workspace", "organization_id", "workspace_id"),
    )


class AgentWorkspaceExecution(Base, TenantMixin, TimestampMixin):
    __tablename__ = "agent_workspace_executions"

    id: Mapped[uuid.UUID] = uuid_pk()
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_workspaces.id", ondelete="CASCADE"), nullable=False
    )
    task_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_tasks.id", ondelete="CASCADE"), nullable=False
    )
    approval_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("approvals.id", ondelete="RESTRICT"), nullable=False
    )
    execution_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending")
    executable: Mapped[str] = mapped_column(String(160), nullable=False)
    argument_names: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    environment_names: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    command_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    result_summary: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(
            "execution_kind IN ('shell','browser','scanner')",
            name="valid_agent_workspace_execution_kind",
        ),
        CheckConstraint(
            "status IN ('pending','queued','running','completed','failed','cancelled')",
            name="valid_agent_workspace_execution_status",
        ),
        UniqueConstraint("task_id", name="unique_agent_workspace_execution_task"),
        Index("ix_agent_workspace_executions_org_workspace", "organization_id", "workspace_id"),
        Index("ix_agent_workspace_executions_status", "status", "created_at"),
    )


__all__ = [
    "AgentWorkspace",
    "AgentWorkspaceArtifact",
    "AgentWorkspaceCredentialReference",
    "AgentWorkspaceExecution",
    "AgentWorkspaceRecord",
]
