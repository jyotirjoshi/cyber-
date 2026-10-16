"""Agent conversation and WebSocket wire types (FR-003, FR-033, FR-038; PRD §53, §8).

One envelope, :class:`AgentEvent`, carries every server-to-client push.  ``seq`` is
monotonic per session so a client can detect a gap and re-fetch rather than render a
conversation with a hole in it; ``type`` selects which of the payload models below
``data`` conforms to.  The payloads are declared as real models -- not left as free-form
dicts -- because two of them are the security-sensitive ones:

*   :class:`ToolCallData` carries a *summary* of a tool invocation and never its
    arguments.  Scanner argv and integration calls contain hostnames, tokens and
    credentials; dumping them onto a socket would violate SEC-002 and SEC-006.
*   :class:`ErrorData` carries ``user_message`` only, from the error taxonomy.  The
    operator-facing detail stays in the logs and the trace.
"""

from __future__ import annotations

import datetime as dt
import uuid
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.db.enums import (
    AgentRunStatus,
    AgentTaskKind,
    AgentTaskStatus,
    AssessmentStage,
    AssessmentStatus,
    MessageRole,
    RiskLevel,
    StepStatus,
)
from app.schemas.assessment import ApprovalOut, StageOut

MAX_MESSAGE_LENGTH = 8000


class AgentMessageIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: Omit to start a new session. The service creates one and returns its id.
    session_id: uuid.UUID | None = None
    content: str = Field(min_length=1, max_length=MAX_MESSAGE_LENGTH)
    #: Bind the turn to an existing assessment so the agent answers with its context.
    assessment_id: uuid.UUID | None = None
    #: Used only when creating a conversation. The selected active version is pinned.
    agent_definition_id: uuid.UUID | None = None


class AgentSessionAutonomyIn(BaseModel):
    """Select the session's operating mode without broadening action permissions."""

    model_config = ConfigDict(extra="forbid")

    autonomy_mode: Literal["supervised", "monitored"]


class AgentMessageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    session_id: uuid.UUID
    run_id: uuid.UUID | None = None
    seq: int
    role: MessageRole
    content: str
    #: Summarized tool invocations, never raw arguments. See the module docstring.
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    tool_name: str | None = None
    tool_status: str | None = None
    #: Knowledge-base and intelligence sources backing the answer (FR-021, FR-024).
    citations: list[dict[str, Any]] = Field(default_factory=list)
    model: str | None = None
    #: Set when a guardrail rewrote or blocked the turn (SEC-005, FR-024) -- surfaced so
    #: a suppressed answer is visibly suppressed rather than mysteriously terse.
    guardrail_applied: str | None = None
    created_at: dt.datetime


AgentActionName = Literal[
    "sync_github_alerts",
    "sync_gitlab_alerts",
    "sync_wazuh_alerts",
    "sync_sonarqube_alerts",
    "sync_snyk_issues",
    "sync_tenable_vulnerabilities",
    "sync_qualys_host_detections",
    "sync_rapid7_vulnerabilities",
    "sync_wiz_issues",
    "sync_crowdstrike_vulnerabilities",
    "sync_aws_security_hub_findings",
    "sync_azure_defender_alerts",
    "sync_gcp_scc_findings",
    "update_github_alert",
    "create_jira_ticket",
    "create_ticket",
    "refresh_ticket_status",
    "update_canonical_work",
    "bulk_update_canonical_work",
    "request_retest",
    "request_remediation_group_retests",
    "request_risk_acceptance",
    "start_assessment",
]


class AgentActionProposeIn(BaseModel):
    """A narrow action request. Credentials are never accepted in this payload."""

    model_config = ConfigDict(extra="forbid")

    session_id: uuid.UUID
    action: AgentActionName
    label: str = Field(min_length=1, max_length=300)
    rationale: str | None = Field(default=None, max_length=2000)
    payload: dict[str, Any] = Field(default_factory=dict)


class AgentActionResolveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approve: bool
    note: str | None = Field(default=None, max_length=2000)


class AssessmentWorkOut(BaseModel):
    id: uuid.UUID
    status: str
    current_stage: str
    progress_percent: int
    findings_total: int
    findings_critical: int
    findings_high: int
    assets_discovered: int
    coverage_gap_count: int = 0
    failure_reason: str = ""


class AgentActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    session_id: uuid.UUID
    run_id: uuid.UUID | None = None
    depends_on_action_id: uuid.UUID | None = None
    run_status: str | None = None
    assessment: AssessmentWorkOut | None = None
    action: AgentActionName
    label: str
    rationale: str | None = None
    payload: dict[str, Any]
    payload_digest: str
    status: Literal["pending", "approved", "rejected", "executed", "failed"]
    resolution_note: str | None = None
    resolved_at: dt.datetime | None = None
    executed_at: dt.datetime | None = None
    result_summary: str | None = None
    execution_evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: dt.datetime


class AgentStepOut(BaseModel):
    """One recorded graph step. ``*_digest`` fields are summaries, never raw output."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    run_id: uuid.UUID
    seq: int
    node: str
    stage: AssessmentStage | None = None
    tool_name: str | None = None
    status: StepStatus
    label: str | None = None
    output_truncated: bool = False
    failure_code: str | None = None
    degradation_note: str | None = None
    retry_count: int = 0
    started_at: dt.datetime | None = None
    completed_at: dt.datetime | None = None
    duration_ms: int | None = None


class AgentSpecialistTaskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    plan_index: int
    specialist: str
    scanner: str
    target_count: int
    status: Literal["pending", "running", "completed", "degraded", "failed"]
    attempts: int
    max_attempts: int
    scanner_job_id: uuid.UUID | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    failure_code: str | None = None
    started_at: dt.datetime | None = None
    completed_at: dt.datetime | None = None


class AgentEvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    evidence_key: str
    kind: str
    artifact_reference: str
    content_digest: str
    content_type: str | None = None
    summary: dict[str, Any] = Field(default_factory=dict)
    verified: bool = False
    produced_at: dt.datetime


class AgentTaskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    task_key: str
    kind: AgentTaskKind
    status: AgentTaskStatus
    depends_on: list[str] = Field(default_factory=list)
    required: bool
    plan_index: int
    priority: int
    attempt_count: int
    max_attempts: int
    tool_name: str | None = None
    provider: str | None = None
    output_summary: dict[str, Any] = Field(default_factory=dict)
    failure_code: str | None = None
    failure_detail: str | None = None
    started_at: dt.datetime | None = None
    settled_at: dt.datetime | None = None
    cancellation_requested_at: dt.datetime | None = None
    evidence: list[AgentEvidenceOut] = Field(default_factory=list)


class AgentRunCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: uuid.UUID
    objective: str = Field(min_length=1, max_length=4000)


class AgentTaskApprovalIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str | None = Field(default=None, max_length=2000)


class AgentRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    session_id: uuid.UUID | None = None
    assessment_id: uuid.UUID | None = None
    #: LangGraph checkpointer thread key. Exposed because it is the handle an operator
    #: needs to correlate a run with its persisted state (FR-033).
    thread_id: str
    graph: str
    objective: str | None = None
    status: AgentRunStatus
    current_node: str | None = None
    interrupt_kind: str | None = None
    pending_approval_id: uuid.UUID | None = None
    resumed_count: int = 0
    failure_reason: str | None = None
    failure_category: str | None = None
    stop_reason: str | None = None
    #: LangSmith trace link. Tracing is mandatory per the PRD, so the link is part of the
    #: API rather than something an operator has to reconstruct.
    trace_url: str | None = None
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    tool_call_count: int = 0
    total_spend_micros: int = 0
    started_at: dt.datetime | None = None
    completed_at: dt.datetime | None = None
    steps: list[AgentStepOut] = Field(default_factory=list)
    specialist_tasks: list[AgentSpecialistTaskOut] = Field(default_factory=list)
    tasks: list[AgentTaskOut] = Field(default_factory=list)


class AgentSessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    is_archived: bool = False
    message_count: int = 0
    autonomy_mode: Literal["supervised", "monitored"] = "supervised"
    agent_version_id: uuid.UUID | None = None
    last_activity_at: dt.datetime | None = None
    created_at: dt.datetime


class AgentSessionDetailOut(AgentSessionOut):
    messages: list[AgentMessageOut] = Field(default_factory=list)
    runs: list[AgentRunOut] = Field(default_factory=list)
    #: Rolling summary of turns older than ``summarized_through_seq``, used to keep the
    #: LLM context bounded (SEC-006).
    context_summary: str | None = None
    summarized_through_seq: int = 0


# ---------------------------------------------------------------------------
# WebSocket: WS /ws/agent/{session_id}
# ---------------------------------------------------------------------------


class AgentEventType(StrEnum):
    AGENT_THINKING = "agent_thinking"
    AGENT_PLAN_STEP = "agent_plan_step"
    AGENT_TOOL_CALL = "agent_tool_call"
    AGENT_APPROVAL_REQUIRED = "agent_approval_required"
    AGENT_FINDINGS_UPDATE = "agent_findings_update"
    AGENT_ERROR = "agent_error"
    AGENT_COMPLETE = "agent_complete"
    #: Transport-level additions beyond PRD §53's seven. A socket that cannot deliver
    #: the assistant's actual message, report progress, or answer a keepalive is not a
    #: usable transport.
    AGENT_MESSAGE = "agent_message"
    AGENT_PROGRESS = "agent_progress"
    PONG = "pong"


class AgentEvent(BaseModel):
    """The single envelope on the wire.

    Fanned out over Redis pub/sub by ``app.services.events.EventBus`` so any API replica
    can serve any socket -- the graph runs in a worker process, not in the process
    holding the WebSocket.
    """

    model_config = ConfigDict(from_attributes=True)

    type: AgentEventType
    session_id: uuid.UUID
    assessment_id: uuid.UUID | None = None
    run_id: uuid.UUID | None = None
    #: Monotonic per session. A client that sees seq jump knows it missed an event.
    seq: int
    at: dt.datetime
    data: dict[str, Any] = Field(default_factory=dict)


class ThinkingData(BaseModel):
    """``agent_thinking``. Narration, not chain-of-thought dumping."""

    text: str
    node: str | None = None


class PlanStepData(BaseModel):
    """``agent_plan_step``."""

    step_index: int
    total_steps: int
    stage: AssessmentStage | None = None
    title: str
    status: StepStatus
    detail: str | None = None


class ToolCallData(BaseModel):
    """``agent_tool_call``.

    ``summary`` is a human-readable one-liner produced by the tool contract layer, e.g.
    "nuclei against 12 selected assets". Arguments are deliberately absent -- see the
    module docstring (SEC-002, SEC-006).
    """

    tool: str
    status: Literal["started", "succeeded", "failed"]
    risk_level: RiskLevel | None = None
    summary: str | None = None
    duration_ms: int | None = None


class FindingsUpdateData(BaseModel):
    """``agent_findings_update``. Counters only; the client refetches the list."""

    assessment_id: uuid.UUID
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    new_since_last: int = 0


class ErrorData(BaseModel):
    """``agent_error``. ``user_message`` only -- see the module docstring."""

    code: str
    category: str
    user_message: str
    retryable: bool = False
    degradable: bool = False
    stage: AssessmentStage | None = None


class CompleteData(BaseModel):
    """``agent_complete``."""

    assessment_id: uuid.UUID | None = None
    status: AssessmentStatus | None = None
    findings_total: int = 0
    report_id: uuid.UUID | None = None
    duration_seconds: int | None = None


class ProgressData(BaseModel):
    """``agent_progress``. The FR-038 checklist, derived from ``STAGE_ORDER``."""

    stage: AssessmentStage
    progress_percent: int = Field(ge=0, le=100)
    stages: list[StageOut] = Field(default_factory=list)


#: ``agent_approval_required`` carries an :class:`ApprovalOut`; ``agent_message`` carries
#: an :class:`AgentMessageOut`. Mapping lives here so the API layer and the frontend
#: generator agree on which payload belongs to which type.
EVENT_PAYLOADS: dict[AgentEventType, type[BaseModel]] = {
    AgentEventType.AGENT_THINKING: ThinkingData,
    AgentEventType.AGENT_PLAN_STEP: PlanStepData,
    AgentEventType.AGENT_TOOL_CALL: ToolCallData,
    AgentEventType.AGENT_APPROVAL_REQUIRED: ApprovalOut,
    AgentEventType.AGENT_FINDINGS_UPDATE: FindingsUpdateData,
    AgentEventType.AGENT_ERROR: ErrorData,
    AgentEventType.AGENT_COMPLETE: CompleteData,
    AgentEventType.AGENT_MESSAGE: AgentMessageOut,
    AgentEventType.AGENT_PROGRESS: ProgressData,
}


class ClientFrame(BaseModel):
    """Client-to-server frame. Only auth and keepalive: the socket is not a command
    channel, so there is no frame that can start work.  Messages go through
    ``POST /api/v1/agent/messages``, which is authorized and audited."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["auth", "ping"]
    token: str | None = Field(default=None, max_length=4096)


__all__ = [
    "MAX_MESSAGE_LENGTH",
    "EVENT_PAYLOADS",
    "AgentEvent",
    "AgentEventType",
    "AgentActionOut",
    "AgentActionProposeIn",
    "AgentActionResolveIn",
    "AgentMessageIn",
    "AgentMessageOut",
    "AgentRunOut",
    "AgentSpecialistTaskOut",
    "AgentSessionAutonomyIn",
    "AgentSessionDetailOut",
    "AgentSessionOut",
    "AgentStepOut",
    "ClientFrame",
    "CompleteData",
    "ErrorData",
    "FindingsUpdateData",
    "PlanStepData",
    "ProgressData",
    "ThinkingData",
    "ToolCallData",
]
