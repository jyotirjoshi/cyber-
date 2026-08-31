"""Agent sessions, messages, runs and steps (FR-030 .. FR-038).

LangGraph owns the *execution* state -- its Postgres checkpointer holds the graph
channels keyed by ``thread_id``, and that is what allows a run to resume after a
worker restart or after a day-long wait for approval (FR-033).  These tables hold the
*product* state around it: the conversation a person can read, the runs they can
inspect, and a per-node timeline they can watch (FR-038).

The two are joined by :attr:`AgentRun.thread_id`.  Keeping them separate means we
never parse checkpoint blobs to render a UI, and a checkpoint schema change in
LangGraph does not migrate our history.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
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
from app.db.enums import AgentRunStatus, MessageRole, StepStatus

if TYPE_CHECKING:
    from app.db.models.assessment import Assessment
    from app.db.models.identity import User


class AgentSession(Base, TenantMixin, TimestampMixin):
    """One conversation (FR-030). Long-lived: an assessment is started from a session
    and the session outlives it, so follow-up questions keep their context."""

    __tablename__ = "agent_sessions"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    #: Derived from the first user message; editable.
    title: Mapped[str] = mapped_column(String(300), nullable=False, default="New conversation")
    is_archived: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_activity_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )
    message_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: Rolling summary of older turns. FR-031 requires context to persist across a
    #: long conversation without the prompt growing without bound (SEC-006).
    context_summary: Mapped[str | None] = mapped_column(Text)
    summarized_through_seq: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    user: Mapped[User | None] = relationship(lazy=LAZY)
    messages: Mapped[list[AgentMessage]] = relationship(
        back_populates="session",
        cascade="all, delete-orphan",
        lazy=LAZY,
        order_by="AgentMessage.seq",
    )
    runs: Mapped[list[AgentRun]] = relationship(
        back_populates="session", cascade="all, delete-orphan", lazy=LAZY
    )
    assessments: Mapped[list[Assessment]] = relationship(
        back_populates="agent_session",
        lazy=LAZY,
        foreign_keys="Assessment.agent_session_id",
    )

    __table_args__ = (
        Index("ix_agent_sessions_organization_id_user_id", "organization_id", "user_id"),
        Index(
            "ix_agent_sessions_organization_id_last_activity_at",
            "organization_id",
            "last_activity_at",
        ),
    )


class AgentMessage(Base, TenantMixin, TimestampMixin):
    """One turn in the transcript.

    ``seq`` is a per-session monotonic counter rather than an ordering by timestamp:
    streamed assistant messages and tool results can share a millisecond, and a
    transcript that reorders itself on reload is a bug users notice immediately.
    """

    __tablename__ = "agent_messages"

    id: Mapped[uuid.UUID] = uuid_pk()
    session_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_sessions.id", ondelete="CASCADE"), nullable=False
    )
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_runs.id", ondelete="SET NULL")
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")

    #: Tool calls the assistant requested, as ``[{"name": ..., "arguments": {...}}]``.
    #: The column type is given explicitly here and on every other array-of-objects
    #: column: ``from __future__ import annotations`` stringifies the annotation, and
    #: SQLAlchemy's de-stringification leaves the *inner* args of a nested generic as
    #: ForwardRefs, so ``list[dict[str, Any]]`` never matches the ``type_annotation_map``
    #: key in :mod:`app.db.base`.  ``list[str]`` and ``dict[str, Any]`` resolve fine.
    tool_calls: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    #: For ``role="tool"``: the *summarized* result that was returned to the model.
    #: Never the raw scanner output -- that lives in object storage (SEC-006).
    tool_name: Mapped[str | None] = mapped_column(String(80))
    tool_call_id: Mapped[str | None] = mapped_column(String(120))
    tool_status: Mapped[str | None] = mapped_column(String(30))

    #: Citations backing any factual claim in ``content`` (FR-024).
    citations: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    #: Model and token accounting, for the cost view and for LangSmith correlation.
    model: Mapped[str | None] = mapped_column(String(120))
    provider: Mapped[str | None] = mapped_column(String(40))
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    #: True when this message was withheld or rewritten by a guardrail; the UI shows a
    #: marker so a suppressed answer is never mistaken for the agent's real reply.
    guardrail_applied: Mapped[str | None] = mapped_column(String(60))

    session: Mapped[AgentSession] = relationship(back_populates="messages", lazy=LAZY)

    __table_args__ = (
        UniqueConstraint("session_id", "seq", name="unique_message_seq"),
        CheckConstraint("role IN ('user','assistant','system','tool')", name="valid_message_role"),
        Index("ix_agent_messages_session_id_seq", "session_id", "seq"),
    )

    @property
    def role_enum(self) -> MessageRole:
        return MessageRole(self.role)


class AgentRun(Base, TenantMixin, TimestampMixin):
    """One invocation of the graph (FR-033).

    ``thread_id`` is the LangGraph checkpoint key.  It is stable for the life of the
    run, so resuming after an approval interrupt is a matter of re-entering the graph
    with the same thread rather than replaying anything.
    """

    __tablename__ = "agent_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_sessions.id", ondelete="CASCADE")
    )
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE")
    )
    triggered_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    #: LangGraph checkpoint thread id. Unique so a resume can never fork a second run
    #: against the same checkpoint.
    thread_id: Mapped[str] = mapped_column(String(120), nullable=False, unique=True, index=True)
    #: Graph name, e.g. "assessment" or "chat".
    graph: Mapped[str] = mapped_column(String(60), nullable=False, default="assessment")
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default=AgentRunStatus.QUEUED.value, index=True
    )
    #: Node the run is on, or the node it stopped at.
    current_node: Mapped[str | None] = mapped_column(String(80))
    #: Set while ``status='interrupted'``: which approval the run is blocked on.
    #: Intentionally *not* a foreign key. ``approvals.agent_run_id`` already points the
    #: other way, and a second FK back would make the two tables mutually dependent --
    #: a cycle that neither ``create_all`` nor Alembic's autogenerate can order. The
    #: durable provenance link lives on ``Approval``; this column is transient state.
    interrupt_kind: Mapped[str | None] = mapped_column(String(40))
    pending_approval_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True))

    #: Redis Streams message id, so a stuck run can be traced back to its queue entry.
    queue_message_id: Mapped[str | None] = mapped_column(String(64))
    worker_id: Mapped[str | None] = mapped_column(String(64))
    heartbeat_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    resumed_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    #: User-safe failure text plus the taxonomy category (FR-040).
    failure_reason: Mapped[str | None] = mapped_column(Text)
    failure_category: Mapped[str | None] = mapped_column(String(40))

    #: LangSmith run URL, so "why did the agent do that?" starts from a trace rather
    #: than from log archaeology (section 58).
    trace_id: Mapped[str | None] = mapped_column(String(120))
    trace_url: Mapped[str | None] = mapped_column(String(1000))

    total_input_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_output_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tool_call_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    session: Mapped[AgentSession | None] = relationship(back_populates="runs", lazy=LAZY)
    assessment: Mapped[Assessment | None] = relationship(back_populates="agent_runs", lazy=LAZY)
    steps: Mapped[list[AgentStep]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
        lazy=LAZY,
        order_by="AgentStep.seq",
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('queued','running','interrupted','completed','failed','cancelled')",
            name="valid_run_status",
        ),
        Index("ix_agent_runs_organization_id_status", "organization_id", "status"),
        Index("ix_agent_runs_assessment_id_created_at", "assessment_id", "created_at"),
    )

    @property
    def status_enum(self) -> AgentRunStatus:
        return AgentRunStatus(self.status)

    @property
    def is_active(self) -> bool:
        return self.status in (
            AgentRunStatus.QUEUED.value,
            AgentRunStatus.RUNNING.value,
            AgentRunStatus.INTERRUPTED.value,
        )


class AgentStep(Base, TenantMixin, TimestampMixin):
    """One node execution or tool call (FR-032, FR-038).

    This is the row behind the live activity timeline.  ``input_digest`` and
    ``output_digest`` are bounded summaries, never full payloads: a Nuclei run can
    emit tens of megabytes, and storing that here would put it one careless join away
    from an LLM prompt (SEC-006).
    """

    __tablename__ = "agent_steps"

    id: Mapped[uuid.UUID] = uuid_pk()
    run_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=False
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    node: Mapped[str] = mapped_column(String(80), nullable=False)
    #: Stage this node maps to, so the UI checklist and the timeline stay in sync.
    stage: Mapped[str | None] = mapped_column(String(60))
    tool_name: Mapped[str | None] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default=StepStatus.PENDING.value
    )
    #: One-line description shown in the activity feed ("Scanning 12 hosts with Nmap").
    label: Mapped[str | None] = mapped_column(String(300))

    input_digest: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)
    output_digest: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)
    #: Truncation is recorded rather than silent, so a reviewer knows the digest is
    #: partial and where the full artifact lives.
    output_truncated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    artifact_reference: Mapped[str | None] = mapped_column(String(1000))

    failure_code: Mapped[str | None] = mapped_column(String(60))
    failure_detail: Mapped[str | None] = mapped_column(Text)
    #: Populated for ``status='degraded'``: what was unavailable and what we did instead.
    degradation_note: Mapped[str | None] = mapped_column(Text)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    run: Mapped[AgentRun] = relationship(back_populates="steps", lazy=LAZY)

    __table_args__ = (
        UniqueConstraint("run_id", "seq", name="unique_step_seq"),
        CheckConstraint(
            "status IN ('pending','running','completed','failed','skipped','degraded')",
            name="valid_step_status",
        ),
        Index("ix_agent_steps_run_id_seq", "run_id", "seq"),
    )

    @property
    def status_enum(self) -> StepStatus:
        return StepStatus(self.status)


__all__ = ["AgentMessage", "AgentRun", "AgentSession", "AgentStep"]
