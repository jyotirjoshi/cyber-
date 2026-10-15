"""Durable, tenant-scoped visual workflow definitions and execution state."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import LAZY, Base, TenantMixin, TimestampMixin, uuid_pk


class WorkflowDefinition(Base, TenantMixin, TimestampMixin):
    __tablename__ = "workflow_definitions"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    nodes: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    edges: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    is_enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    dry_run: Mapped[bool] = mapped_column(nullable=False, default=False)
    next_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    runs: Mapped[list[WorkflowRun]] = relationship(
        back_populates="workflow", cascade="all, delete-orphan", lazy=LAZY
    )

    __table_args__ = (
        CheckConstraint("version > 0", name="valid_workflow_definition_version"),
        UniqueConstraint("organization_id", "name", name="unique_workflow_definition_name"),
        Index("ix_workflow_definitions_org_enabled", "organization_id", "is_enabled"),
        Index("ix_workflow_definitions_due", "is_enabled", "next_run_at"),
    )


class WorkflowRun(Base, TenantMixin, TimestampMixin):
    __tablename__ = "workflow_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    workflow_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("workflow_definitions.id", ondelete="CASCADE"),
        nullable=False,
    )
    definition_version: Mapped[int] = mapped_column(Integer, nullable=False)
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    event_key: Mapped[str] = mapped_column(String(240), nullable=False)
    trigger: Mapped[str] = mapped_column(String(80), nullable=False)
    context: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending")
    dry_run: Mapped[bool] = mapped_column(nullable=False, default=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_resume_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(80))

    workflow: Mapped[WorkflowDefinition] = relationship(back_populates="runs", lazy=LAZY)
    steps: Mapped[list[WorkflowStepRun]] = relationship(
        back_populates="run", cascade="all, delete-orphan", lazy=LAZY
    )

    __table_args__ = (
        CheckConstraint("definition_version > 0", name="valid_workflow_run_version"),
        CheckConstraint("attempts >= 0", name="valid_workflow_run_attempts"),
        CheckConstraint(
            "status IN ('pending','running','waiting','succeeded','failed','cancelled','dry_run')",
            name="valid_workflow_run_status",
        ),
        UniqueConstraint("workflow_id", "event_key", name="unique_workflow_run_event"),
        Index("ix_workflow_runs_org_status_resume", "organization_id", "status", "next_resume_at"),
    )


class WorkflowStepRun(Base, TenantMixin, TimestampMixin):
    __tablename__ = "workflow_step_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    run_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("workflow_runs.id", ondelete="CASCADE"), nullable=False
    )
    node_id: Mapped[str] = mapped_column(String(64), nullable=False)
    node_type: Mapped[str] = mapped_column(String(24), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending")
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)
    input: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    output: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(80))
    error_detail: Mapped[str | None] = mapped_column(String(500))
    available_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    run: Mapped[WorkflowRun] = relationship(back_populates="steps", lazy=LAZY)

    __table_args__ = (
        CheckConstraint("attempt > 0", name="valid_workflow_step_attempt"),
        CheckConstraint("max_attempts BETWEEN 1 AND 10", name="valid_workflow_step_max_attempts"),
        CheckConstraint(
            "status IN ('pending','running','waiting_approval','waiting_delay','succeeded','skipped','failed')",
            name="valid_workflow_step_status",
        ),
        UniqueConstraint("run_id", "node_id", name="unique_workflow_step_node"),
        UniqueConstraint("idempotency_key", name="unique_workflow_step_idempotency"),
        Index("ix_workflow_steps_run_status", "run_id", "status", "available_at"),
    )


__all__ = ["WorkflowDefinition", "WorkflowRun", "WorkflowStepRun"]
