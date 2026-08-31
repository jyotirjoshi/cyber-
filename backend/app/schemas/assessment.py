"""Assessment wire types (FR-005, FR-006, FR-011, FR-037, FR-038, FR-039).

Two things here are load-bearing rather than decorative.

``AuthorizationIn`` is a required member of :class:`AssessmentCreateIn`, not an optional
one.  FR-006 requires an explicit, recorded attestation before any target is touched, and
making the field optional would mean a client that simply omitted it got an assessment.
``confirmed=False`` is rejected with ``UnauthorizedTargetError``; there is no path that
infers authorization from anything else.

``StageOut`` is a *derived* projection over ``STAGE_ORDER`` and the recorded agent steps,
never a free-form list the agent writes.  FR-038 promises the operator a checklist whose
stages match what actually ran, and a stage list the agent could author at will would let
a stage be silently skipped while the UI still showed it green.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.db.enums import (
    ApprovalDecision,
    ApprovalKind,
    AssessmentDepth,
    AssessmentStage,
    AssessmentStatus,
    Criticality,
    RiskLevel,
    ScannerName,
    Scope,
    StepStatus,
)

#: PRD FR-005 caps a single assessment's target list. Beyond this the operator is asked
#: to split the engagement, which keeps one assessment's recon bounded and reviewable.
MAX_TARGETS = 50


class AuthorizationIn(BaseModel):
    """Operator attestation of authority to test (FR-006).

    ``attestation_text`` is stored verbatim in ``authorization_records`` alongside the
    actor, source IP and timestamp.  It exists so that after the fact there is a record
    of *what the operator was shown and agreed to*, not merely that a box was ticked.
    """

    model_config = ConfigDict(extra="forbid")

    confirmed: bool = Field(description="Must be true. False is rejected with 403.")
    attestation_text: str = Field(min_length=1, max_length=4000)
    #: Change ticket, signed scope document, engagement letter -- anything an auditor
    #: could follow up on.
    evidence_reference: str | None = Field(default=None, max_length=1024)


class AssessmentCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    targets: list[str] = Field(min_length=1, max_length=MAX_TARGETS)
    title: str | None = Field(default=None, max_length=300)
    scope: Scope = Scope.EXTERNAL
    depth: AssessmentDepth = AssessmentDepth.STANDARD
    #: Free-text intent, interpreted by the agent's request-understanding node (FR-004).
    #: Treated as untrusted input for prompt-injection purposes (SEC-005).
    objective: str | None = Field(default=None, max_length=4000)
    authorization: AuthorizationIn
    #: Email addresses or Slack channels to notify. Resolved against the organization's
    #: notification policy; unknown recipients are dropped, not delivered blind.
    notify: list[str] = Field(default_factory=list, max_length=50)


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    raw_value: str
    canonical_value: str
    target_type: str
    host: str
    port: int | None = None
    #: Expanded host count for a CIDR. Lets the UI show "10.0.0.0/24 (256 hosts)".
    host_count: int = 1


class PlanStepOut(BaseModel):
    """One entry of the agent's declared plan (FR-036)."""

    model_config = ConfigDict(from_attributes=True)

    index: int
    stage: AssessmentStage
    title: str
    tool: str | None = None
    rationale: str | None = None
    requires_approval: bool = False
    status: StepStatus = StepStatus.PENDING


class StageOut(BaseModel):
    """One row of the FR-038 progress checklist. Ordered by ``STAGE_ORDER``."""

    model_config = ConfigDict(from_attributes=True)

    stage: AssessmentStage
    label: str
    status: StepStatus
    started_at: dt.datetime | None = None
    completed_at: dt.datetime | None = None
    detail: str | None = None


class DegradationOut(BaseModel):
    """A dependency that failed without failing the assessment (FR-020, FR-039).

    Recorded and surfaced rather than swallowed: a report whose enrichment silently
    lacked KEV data is worse than one that says so.
    """

    model_config = ConfigDict(from_attributes=True)

    stage: str
    component: str
    reason: str
    impact: str
    occurred_at: dt.datetime | None = None


class ProposedAssetOut(BaseModel):
    """An asset the agent proposes to scan, projected out of ``requested_payload``.

    Projected server-side so the approval UI renders typed fields instead of parsing
    the raw approval JSON -- the operator approving a scope needs to see exactly what
    the agent asked for, in a shape that cannot be misread.
    """

    model_config = ConfigDict(from_attributes=True)

    asset_id: uuid.UUID
    name: str
    endpoint: str | None = None
    criticality: Criticality = Criticality.UNKNOWN
    risk_score: float = 0.0
    internet_exposed: bool = False
    scanners: list[ScannerName] = Field(default_factory=list)
    rationale: str | None = None


class ApprovalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    assessment_id: uuid.UUID
    agent_run_id: uuid.UUID | None = None
    kind: ApprovalKind
    decision: ApprovalDecision
    prompt: str
    rationale: str | None = None
    risk_level: RiskLevel
    requested_payload: dict[str, Any] = Field(default_factory=dict)
    approved_payload: dict[str, Any] = Field(default_factory=dict)
    expires_at: dt.datetime | None = None
    resolved_at: dt.datetime | None = None
    resolved_by: str | None = Field(default=None, description="Email of the resolver.")
    resolution_note: str | None = None
    #: Typed projection of ``requested_payload["assets"]``. See ``ProposedAssetOut``.
    proposed_assets: list[ProposedAssetOut] = Field(default_factory=list)
    proposed_scanners: list[ScannerName] = Field(default_factory=list)
    created_at: dt.datetime


class ApproveIn(BaseModel):
    """Resolution of a pending approval (FR-011).

    ``approved_all`` means "scan everything you proposed"; ``customized`` narrows the
    set and therefore *requires* ``asset_ids`` -- an empty customization would otherwise
    read as approval of nothing while still unblocking the graph.  The service rejects
    ``customized`` without ids.
    """

    model_config = ConfigDict(extra="forbid")

    decision: Literal["approved", "approved_all", "customized", "rejected"]
    asset_ids: list[uuid.UUID] | None = Field(default=None, max_length=1000)
    scanners: list[ScannerName] | None = None
    note: str | None = Field(default=None, max_length=2000)


class CancelIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=2000)


class AssessmentOut(BaseModel):
    """List row."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    #: Per-organization sequential number, e.g. displayed as "ASM-17".
    reference: int
    title: str
    status: AssessmentStatus
    current_stage: AssessmentStage
    progress_percent: int = Field(ge=0, le=100)
    scope: Scope
    depth: AssessmentDepth

    findings_total: int = 0
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_low: int = 0
    findings_info: int = 0
    assets_discovered: int = 0
    assets_in_scope: int = 0

    created_at: dt.datetime
    started_at: dt.datetime | None = None
    completed_at: dt.datetime | None = None
    duration_seconds: int | None = None
    targets: list[TargetOut] = Field(default_factory=list)
    created_by: str | None = Field(default=None, description="Email of the requester.")


class AssessmentDetailOut(AssessmentOut):
    plan: list[PlanStepOut] = Field(default_factory=list)
    #: The agent's structured reading of ``objective`` (FR-004): extracted targets,
    #: inferred scope, assumptions, and anything it could not resolve.
    request_interpretation: dict[str, Any] = Field(default_factory=dict)
    stages: list[StageOut] = Field(default_factory=list)
    degradations: list[DegradationOut] = Field(default_factory=list)
    pending_approval: ApprovalOut | None = None
    failure_reason: str | None = None
    failure_category: str | None = None
    agent_session_id: uuid.UUID | None = None
    defectdojo_engagement_id: int | None = None
    defectdojo_product_id: int | None = None


class AssessmentFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AssessmentStatus | None = None
    scope: Scope | None = None
    #: True selects everything not in a terminal state, so the dashboard's "active"
    #: count does not have to enumerate statuses client-side.
    active: bool | None = None
    awaiting_approval: bool | None = None
    q: str | None = Field(default=None, max_length=200)


__all__ = [
    "MAX_TARGETS",
    "ApprovalOut",
    "ApproveIn",
    "AssessmentCreateIn",
    "AssessmentDetailOut",
    "AssessmentFilter",
    "AssessmentOut",
    "AuthorizationIn",
    "CancelIn",
    "DegradationOut",
    "PlanStepOut",
    "ProposedAssetOut",
    "StageOut",
    "TargetOut",
]
