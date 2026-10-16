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
from app.db.enums import (
    AgentActionStatus,
    AgentRunStatus,
    AgentSpecialistStatus,
    MessageRole,
    StepStatus,
)

if TYPE_CHECKING:
    from app.db.models.agent_task import AgentTask
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
    #: Immutable custom-agent behavior selected when the conversation is created.
    #: Existing generic sessions keep this null. It is never changed on resume.
    agent_version_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("agent_definition_versions.id", ondelete="RESTRICT"),
        index=True,
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
    #: ``supervised`` requires an explicit approval for every external operation.
    #: ``monitored`` may execute only the small read/synchronization allow-list in
    #: ``agent_action``; state-changing remediation and assessment work stay supervised.
    autonomy_mode: Mapped[str] = mapped_column(
        String(20), nullable=False, default="supervised", server_default="supervised"
    )

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
        CheckConstraint(
            "autonomy_mode IN ('supervised','monitored')",
            name="valid_agent_session_autonomy_mode",
        ),
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
    source_action_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_actions.id", ondelete="SET NULL")
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
        UniqueConstraint("source_action_id", name="unique_action_receipt"),
        CheckConstraint("role IN ('user','assistant','system','tool')", name="valid_message_role"),
        Index("ix_agent_messages_session_id_seq", "session_id", "seq"),
    )

    @property
    def role_enum(self) -> MessageRole:
        return MessageRole(self.role)


class AgentAction(Base, TenantMixin, TimestampMixin):
    """A single proposed external action, approved once against its immutable payload hash."""

    __tablename__ = "agent_actions"

    id: Mapped[uuid.UUID] = uuid_pk()
    session_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_sessions.id", ondelete="CASCADE"), nullable=False
    )
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_runs.id", ondelete="SET NULL")
    )
    depends_on_action_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_actions.id", ondelete="CASCADE"), index=True
    )
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    approved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    label: Mapped[str] = mapped_column(String(300), nullable=False)
    rationale: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    #: SHA-256 over a canonical payload. Execution checks this before acting.
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default=AgentActionStatus.PENDING.value, index=True
    )
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    resolution_note: Mapped[str | None] = mapped_column(Text)
    executed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    result_summary: Mapped[str | None] = mapped_column(Text)
    #: Sanitized, machine-readable proof of the resource changed by a completed action.
    execution_evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        CheckConstraint(
            "action IN ('sync_github_alerts','sync_gitlab_alerts','sync_wazuh_alerts','sync_sonarqube_alerts','sync_snyk_issues','sync_tenable_vulnerabilities','sync_qualys_host_detections','sync_rapid7_vulnerabilities','sync_wiz_issues','sync_prisma_cloud_alerts','sync_crowdstrike_vulnerabilities','sync_aws_security_hub_findings','sync_aws_inspector_findings','sync_hackerone_reports','sync_bugcrowd_submissions','sync_checkmarx_results','sync_fortify_issues','sync_azure_defender_alerts','sync_gcp_scc_findings','sync_burp_dast_findings','update_github_alert','create_jira_ticket','create_ticket','refresh_ticket_status','update_canonical_work','bulk_update_canonical_work','request_retest','request_remediation_group_retests','request_risk_acceptance','start_assessment')",
            name="valid_agent_action",
        ),
        CheckConstraint(
            "status IN ('pending','approved','rejected','executed','failed')",
            name="valid_agent_action_status",
        ),
        CheckConstraint(
            "status = 'pending' OR approved_by_user_id IS NOT NULL",
            name="agent_action_resolution_requires_actor",
        ),
        Index("ix_agent_actions_org_session_status", "organization_id", "session_id", "status"),
    )


class AgentMemory(Base, TenantMixin, TimestampMixin):
    """A curated, organization-scoped fact available to future agent conversations.

    This is intentionally not a transcript dump or autonomous learning store. Entries
    are explicitly curated by an organization manager, bounded, revocable, and always
    injected as untrusted reference data rather than instructions.
    """

    __tablename__ = "agent_memories"

    id: Mapped[uuid.UUID] = uuid_pk()
    key: Mapped[str] = mapped_column(String(120), nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False, default="operational")
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(40), nullable=False, default="manual")
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        UniqueConstraint("organization_id", "key", name="unique_agent_memory_key"),
        CheckConstraint(
            "category IN ('operational','architecture','remediation','scope','preference')",
            name="valid_agent_memory_category",
        ),
        CheckConstraint("source IN ('manual','approved_agent')", name="valid_agent_memory_source"),
        Index("ix_agent_memories_org_active_expiry", "organization_id", "is_active", "expires_at"),
    )


class RunDispatch(Base, TenantMixin, TimestampMixin):
    """Transactional outbox entry for one start or approval-resume request."""

    __tablename__ = "run_dispatches"

    id: Mapped[uuid.UUID] = uuid_pk()
    run_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=False
    )
    task_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_tasks.id", ondelete="CASCADE"), index=True
    )
    action: Mapped[str] = mapped_column(String(10), nullable=False)
    dispatch_key: Mapped[str] = mapped_column(String(160), nullable=False)
    principal: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    available_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    published_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    stream_message_id: Mapped[str | None] = mapped_column(String(64))
    last_error_code: Mapped[str | None] = mapped_column(String(80))

    run: Mapped[AgentRun] = relationship(back_populates="dispatches", lazy=LAZY)

    __table_args__ = (
        UniqueConstraint("organization_id", "dispatch_key", name="unique_run_dispatch_key"),
        CheckConstraint("action IN ('start','resume','task')", name="valid_run_dispatch_action"),
        CheckConstraint(
            "(action = 'task' AND task_id IS NOT NULL) OR "
            "((action = 'start' OR action = 'resume') AND task_id IS NULL)",
            name="valid_run_dispatch_task_binding",
        ),
        CheckConstraint(
            "status IN ('pending','sent','cancelled')", name="valid_run_dispatch_status"
        ),
        Index("ix_run_dispatches_status_available_at", "status", "available_at"),
    )


class AgentSpecialistTask(Base, TenantMixin, TimestampMixin):
    """One durable, bounded specialist assignment inside an assessment run."""

    __tablename__ = "agent_specialist_tasks"

    id: Mapped[uuid.UUID] = uuid_pk()
    run_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=False
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    scanner_job_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scanner_jobs.id", ondelete="SET NULL")
    )
    plan_index: Mapped[int] = mapped_column(Integer, nullable=False)
    specialist: Mapped[str] = mapped_column(String(40), nullable=False)
    scanner: Mapped[str] = mapped_column(String(40), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    target_count: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=AgentSpecialistStatus.PENDING.value, index=True
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    worker_id: Mapped[str | None] = mapped_column(String(64))
    heartbeat_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    failure_code: Mapped[str | None] = mapped_column(String(80))
    run: Mapped[AgentRun] = relationship(back_populates="specialist_tasks", lazy=LAZY)

    __table_args__ = (
        UniqueConstraint("run_id", "fingerprint", name="unique_agent_specialist_task"),
        CheckConstraint(
            "specialist IN ('network','web','code','secrets','supply_chain','container','cloud')",
            name="valid_agent_specialist_role",
        ),
        CheckConstraint(
            "status IN ('pending','running','completed','degraded','failed')",
            name="valid_agent_specialist_status",
        ),
        CheckConstraint("target_count > 0", name="valid_agent_specialist_target_count"),
        CheckConstraint(
            "attempts >= 0 AND max_attempts BETWEEN 1 AND 10",
            name="valid_agent_specialist_attempts",
        ),
        Index("ix_agent_specialist_tasks_run_plan", "run_id", "plan_index"),
        Index("ix_agent_specialist_tasks_org_status", "organization_id", "status"),
    )


class AgentDecision(Base, TenantMixin, TimestampMixin):
    """One immutable supervisor decision between evidence collection rounds.

    Candidate and rejection payloads are bounded summaries produced by the policy
    boundary, not raw model responses or scanner artifacts.  The ordered records let a
    recovered worker prove what it already considered and avoid dispatching it twice.
    """

    __tablename__ = "agent_decisions"

    id: Mapped[uuid.UUID] = uuid_pk()
    run_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=False
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    hypothesis: Mapped[str | None] = mapped_column(Text)
    candidate_actions: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    accepted_actions: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    rejections: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    input_evidence_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="proposed", index=True)
    stop_reason: Mapped[str | None] = mapped_column(String(80))

    run: Mapped[AgentRun] = relationship(back_populates="decisions", lazy=LAZY)

    __table_args__ = (
        UniqueConstraint("run_id", "sequence", name="unique_agent_decision_sequence"),
        CheckConstraint("sequence > 0", name="valid_agent_decision_sequence"),
        CheckConstraint(
            "status IN ('proposed','dispatched','stopped','degraded')",
            name="valid_agent_decision_status",
        ),
        Index("ix_agent_decisions_run_sequence", "run_id", "sequence"),
        Index("ix_agent_decisions_org_status", "organization_id", "status"),
    )


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
    specialist_tasks: Mapped[list[AgentSpecialistTask]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
        lazy=LAZY,
        order_by="AgentSpecialistTask.plan_index",
    )
    decisions: Mapped[list[AgentDecision]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
        lazy=LAZY,
        order_by="AgentDecision.sequence",
    )
    dispatches: Mapped[list[RunDispatch]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
        lazy=LAZY,
        order_by="RunDispatch.created_at",
    )
    tasks: Mapped[list[AgentTask]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
        lazy=LAZY,
        order_by="AgentTask.plan_index",
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


__all__ = [
    "AgentAction",
    "AgentDecision",
    "AgentMemory",
    "AgentMessage",
    "AgentRun",
    "AgentSession",
    "AgentSpecialistTask",
    "AgentStep",
    "RunDispatch",
]
