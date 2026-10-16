"""Durable generic task graphs used by multi-agent execution.

The agent runtime may disappear at any instruction boundary.  These records therefore
hold the scheduler's authoritative state: immutable task identity, scoped dependency
edges, generation-fenced attempts, evidence references, and budget reservations.
Large tool outputs remain in object storage and are represented here only by bounded
summaries and content digests.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
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

if TYPE_CHECKING:
    from app.db.models.agent import AgentRun


TASK_STATUSES = (
    "pending",
    "blocked",
    "ready",
    "queued",
    "running",
    "awaiting_approval",
    "completed",
    "degraded",
    "skipped",
    "failed",
    "rejected",
    "cancelled",
)
TASK_KINDS = ("agent", "tool", "approval", "join", "decision", "finalize")


class AgentTask(Base, TenantMixin, TimestampMixin):
    """One immutable unit of work in a validated agent plan."""

    __tablename__ = "agent_tasks"

    id: Mapped[uuid.UUID] = uuid_pk()
    run_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=False
    )
    task_key: Mapped[str] = mapped_column(String(80), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="pending")
    idempotency_key: Mapped[str] = mapped_column(String(160), nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_version_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("agent_definition_versions.id", ondelete="RESTRICT"),
        index=True,
    )
    tool_name: Mapped[str | None] = mapped_column(String(120))
    tool_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    input_schema_version: Mapped[str] = mapped_column(String(40), nullable=False, default="v1")
    output_schema_version: Mapped[str] = mapped_column(String(40), nullable=False, default="v1")
    input_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    orchestration: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    output_summary: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    plan_index: Mapped[int] = mapped_column(Integer, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    current_lease_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    provider: Mapped[str | None] = mapped_column(String(80))
    conflict_key: Mapped[str | None] = mapped_column(String(200))
    available_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    settled_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    cancellation_requested_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    failure_code: Mapped[str | None] = mapped_column(String(80))
    failure_detail: Mapped[str | None] = mapped_column(Text)

    run: Mapped[AgentRun] = relationship(back_populates="tasks", lazy=LAZY)
    attempts: Mapped[list[AgentTaskAttempt]] = relationship(
        back_populates="task",
        cascade="all, delete-orphan",
        lazy=LAZY,
        order_by="AgentTaskAttempt.generation",
        foreign_keys="AgentTaskAttempt.task_id",
    )
    evidence: Mapped[list[AgentEvidence]] = relationship(
        back_populates="task",
        cascade="all, delete-orphan",
        lazy=LAZY,
        foreign_keys="AgentEvidence.task_id",
    )

    __table_args__ = (
        UniqueConstraint("run_id", "task_key", name="unique_agent_task_key"),
        UniqueConstraint("run_id", "idempotency_key", name="unique_agent_task_idempotency"),
        UniqueConstraint("id", "run_id", "organization_id", name="unique_agent_task_scope"),
        CheckConstraint(
            "kind IN ('agent','tool','approval','join','decision','finalize')",
            name="valid_agent_task_kind",
        ),
        CheckConstraint(
            "status IN ('pending','blocked','ready','queued','running','awaiting_approval',"
            "'completed','degraded','skipped','failed','rejected','cancelled')",
            name="valid_agent_task_status",
        ),
        CheckConstraint("plan_index >= 0", name="valid_agent_task_plan_index"),
        CheckConstraint("tool_version > 0", name="valid_agent_task_tool_version"),
        CheckConstraint(
            "(kind = 'tool' AND tool_name IS NOT NULL AND agent_version_id IS NULL) OR "
            "(kind = 'agent' AND agent_version_id IS NOT NULL AND tool_name IS NULL) OR "
            "(kind <> 'tool' AND kind <> 'agent' AND tool_name IS NULL "
            "AND agent_version_id IS NULL)",
            name="valid_agent_task_executor_binding",
        ),
        CheckConstraint("priority >= 0", name="valid_agent_task_priority"),
        CheckConstraint(
            "attempt_count >= 0 AND max_attempts BETWEEN 1 AND 10 "
            "AND current_lease_generation >= 0",
            name="valid_agent_task_attempts",
        ),
        Index("ix_agent_tasks_run_plan", "run_id", "plan_index"),
        Index("ix_agent_tasks_org_status_available", "organization_id", "status", "available_at"),
    )


class AgentTaskDependency(Base, TenantMixin, TimestampMixin):
    """A tenant- and run-scoped edge between two tasks."""

    __tablename__ = "agent_task_dependencies"

    id: Mapped[uuid.UUID] = uuid_pk()
    run_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    task_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    depends_on_task_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    dependency_kind: Mapped[str] = mapped_column(String(20), nullable=False, default="required")

    __table_args__ = (
        ForeignKeyConstraint(
            ["task_id", "run_id", "organization_id"],
            ["agent_tasks.id", "agent_tasks.run_id", "agent_tasks.organization_id"],
            ondelete="CASCADE",
            name="fk_agent_task_dependency_task_scope",
        ),
        ForeignKeyConstraint(
            ["depends_on_task_id", "run_id", "organization_id"],
            ["agent_tasks.id", "agent_tasks.run_id", "agent_tasks.organization_id"],
            ondelete="CASCADE",
            name="fk_agent_task_dependency_parent_scope",
        ),
        UniqueConstraint("task_id", "depends_on_task_id", name="unique_agent_task_dependency"),
        CheckConstraint(
            "task_id <> depends_on_task_id", name="valid_agent_task_dependency_distinct"
        ),
        CheckConstraint(
            "dependency_kind IN ('required','optional')",
            name="valid_agent_task_dependency_kind",
        ),
        Index("ix_agent_task_dependencies_run_task", "run_id", "task_id"),
        Index("ix_agent_task_dependencies_parent", "depends_on_task_id"),
    )


class AgentTaskAttempt(Base, TenantMixin, TimestampMixin):
    """A generation-fenced execution attempt for one task."""

    __tablename__ = "agent_task_attempts"

    id: Mapped[uuid.UUID] = uuid_pk()
    task_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    run_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False)
    lease_token_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    worker_id: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="claimed")
    leased_until: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    heartbeat_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    settled_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    result_digest: Mapped[str | None] = mapped_column(String(64))
    usage: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    failure_code: Mapped[str | None] = mapped_column(String(80))
    failure_detail: Mapped[str | None] = mapped_column(Text)

    task: Mapped[AgentTask] = relationship(
        back_populates="attempts", lazy=LAZY, foreign_keys=[task_id]
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["task_id", "run_id", "organization_id"],
            ["agent_tasks.id", "agent_tasks.run_id", "agent_tasks.organization_id"],
            ondelete="CASCADE",
            name="fk_agent_task_attempt_task_scope",
        ),
        UniqueConstraint("task_id", "generation", name="unique_agent_task_attempt_generation"),
        CheckConstraint("generation > 0", name="valid_agent_task_attempt_lease"),
        CheckConstraint(
            "status IN ('claimed','running','completed','failed','cancelled','timed_out')",
            name="valid_agent_task_attempt_status",
        ),
        Index("ix_agent_task_attempts_task_generation", "task_id", "generation"),
        Index("ix_agent_task_attempts_lease", "status", "leased_until"),
    )


class AgentEvidence(Base, TenantMixin, TimestampMixin):
    """A bounded, content-addressed evidence reference produced by a task."""

    __tablename__ = "agent_evidence"

    id: Mapped[uuid.UUID] = uuid_pk()
    task_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    run_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    evidence_key: Mapped[str] = mapped_column(String(160), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    artifact_reference: Mapped[str] = mapped_column(String(1000), nullable=False)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(160))
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    produced_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    task: Mapped[AgentTask] = relationship(
        back_populates="evidence", lazy=LAZY, foreign_keys=[task_id]
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["task_id", "run_id", "organization_id"],
            ["agent_tasks.id", "agent_tasks.run_id", "agent_tasks.organization_id"],
            ondelete="CASCADE",
            name="fk_agent_evidence_task_scope",
        ),
        UniqueConstraint("task_id", "evidence_key", name="unique_agent_evidence_key"),
        CheckConstraint(
            "kind IN ('observation','artifact','provider_receipt','approval','report','metric')",
            name="valid_agent_evidence_kind",
        ),
        Index("ix_agent_evidence_run_task", "run_id", "task_id"),
    )


class AgentBudgetReservation(Base, TenantMixin, TimestampMixin):
    """An atomic pre-dispatch reservation reconciled against settled usage."""

    __tablename__ = "agent_budget_reservations"

    id: Mapped[uuid.UUID] = uuid_pk()
    run_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=False
    )
    task_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True))
    reservation_key: Mapped[str] = mapped_column(String(160), nullable=False)
    category: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="reserved")
    reserved_input_tokens: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    reserved_output_tokens: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    reserved_spend_micros: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    actual_input_tokens: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    actual_output_tokens: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    actual_spend_micros: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    settled_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        ForeignKeyConstraint(
            ["task_id", "run_id", "organization_id"],
            ["agent_tasks.id", "agent_tasks.run_id", "agent_tasks.organization_id"],
            ondelete="CASCADE",
            name="fk_agent_budget_reservation_task_scope",
        ),
        UniqueConstraint("run_id", "reservation_key", name="unique_agent_budget_reservation"),
        CheckConstraint(
            "category IN ('model','tool','scanner','pipeline','run')",
            name="valid_agent_budget_reservation_category",
        ),
        CheckConstraint(
            "status IN ('reserved','settled','released','forfeited')",
            name="valid_agent_budget_reservation_status",
        ),
        CheckConstraint(
            "reserved_input_tokens >= 0 AND reserved_output_tokens >= 0 "
            "AND reserved_spend_micros >= 0 AND actual_input_tokens >= 0 "
            "AND actual_output_tokens >= 0 AND actual_spend_micros >= 0",
            name="valid_agent_budget_reservation_amounts",
        ),
        Index("ix_agent_budget_reservations_run_status", "run_id", "status"),
        Index("ix_agent_budget_reservations_expiry", "status", "expires_at"),
    )


__all__ = [
    "AgentBudgetReservation",
    "AgentEvidence",
    "AgentTask",
    "AgentTaskAttempt",
    "AgentTaskDependency",
    "TASK_KINDS",
    "TASK_STATUSES",
]
