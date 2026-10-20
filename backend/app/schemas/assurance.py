"""Strict API contracts for the evidence-backed assurance runtime."""

from __future__ import annotations

import datetime as dt
import uuid
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EnforcementTransactionCreateIn(StrictModel):
    recommendation_id: uuid.UUID
    observation_seconds: int = Field(default=300, ge=0, le=604_800)


class EnforcementTransactionTransitionIn(StrictModel):
    action: Literal["approve", "execute", "begin_verification", "verify", "rollback", "cancel"]
    approval_id: uuid.UUID | None = None
    expected_diff_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    verification: dict[str, Any] = Field(default_factory=dict)


class EnforcementTransactionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    recommendation_id: uuid.UUID
    integration_id: uuid.UUID | None
    provider: str
    operation: str
    transaction_key: str
    idempotency_key: str
    status: str
    provider_snapshot: dict[str, Any]
    snapshot_digest: str
    desired_state: dict[str, Any]
    diff: list[dict[str, Any]]
    diff_digest: str
    blast_radius: dict[str, Any]
    approval_id: uuid.UUID | None
    approved_by_id: uuid.UUID | None
    mutation_receipt: dict[str, Any]
    confirmation: dict[str, Any]
    verification: dict[str, Any]
    rollback_plan: dict[str, Any]
    observation_seconds: int
    observation_ends_at: dt.datetime | None
    approved_at: dt.datetime | None
    executed_at: dt.datetime | None
    verified_at: dt.datetime | None
    last_error: str | None


class AIToolManifestCreateIn(StrictModel):
    server_key: str = Field(min_length=1, max_length=512)
    tool_name: str = Field(min_length=1, max_length=240)
    version: str = Field(min_length=1, max_length=80)
    argument_schema: dict[str, Any]
    result_schema: dict[str, Any] = Field(default_factory=dict)
    permissions: list[str] = Field(default_factory=list, max_length=100)
    owner_team: str | None = Field(default=None, max_length=120)

    @model_validator(mode="after")
    def closed_argument_schema(self) -> AIToolManifestCreateIn:
        if self.argument_schema.get("type") != "object":
            raise ValueError("argument schema must have an object root")
        if self.argument_schema.get("additionalProperties") is not False:
            raise ValueError("argument schema must set additionalProperties to false")
        return self


class AIToolManifestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    server_key: str
    tool_name: str
    version: str
    schema_digest: str
    argument_schema: dict[str, Any]
    result_schema: dict[str, Any]
    permissions: list[str]
    owner_team: str | None
    approved: bool
    status: str
    observed_at: dt.datetime
    approved_at: dt.datetime | None


class AIAccessEdgeCreateIn(StrictModel):
    source_resource_id: uuid.UUID
    target_resource_id: uuid.UUID
    relation: Literal[
        "uses",
        "calls",
        "assumes_identity",
        "reads",
        "writes",
        "administers",
        "contains_sensitive_data",
    ]
    privileges: list[str] = Field(default_factory=list, max_length=100)
    approved: bool = False
    source_kind: str = Field(min_length=1, max_length=80)
    provenance: dict[str, Any] = Field(default_factory=dict)


class AIAccessEdgeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    source_resource_id: uuid.UUID
    target_resource_id: uuid.UUID
    relation: str
    privileges: list[str]
    approved: bool
    source_kind: str
    provenance: dict[str, Any]
    first_seen_at: dt.datetime
    last_seen_at: dt.datetime


class AIInteractionReceiptOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    request_key: str
    application_key: str | None
    agent_key: str | None
    model_key: str
    provider: str
    region: str | None
    decision: str
    prompt_digest: str
    output_digest: str | None
    tool_keys: list[str]
    reason_codes: list[str]
    input_tokens: int
    output_tokens: int
    cost_usd: Decimal
    latency_ms: int | None
    retention_mode: str
    occurred_at: dt.datetime


class AIRuntimeEvaluateIn(StrictModel):
    provider: Literal[
        "openai", "anthropic", "google", "openrouter", "azure_openai", "ollama", "vllm"
    ]
    direction: Literal["prompt", "output"] = "prompt"
    model: str = Field(min_length=1, max_length=512)
    region: str | None = Field(default=None, max_length=80)
    content: str = Field(min_length=1, max_length=1_000_000, repr=False)
    requested_output_tokens: int = Field(default=4096, ge=1, le=1_000_000)
    estimated_cost_usd: Decimal = Field(default=0, ge=0)
    policy: dict[str, Any] = Field(default_factory=dict)
    request_key: str = Field(min_length=1, max_length=128)
    application_key: str | None = Field(default=None, max_length=512)
    agent_key: str | None = Field(default=None, max_length=512)


class AIRuntimeDecisionOut(StrictModel):
    decision: Literal["allow", "block", "redact"]
    reason_codes: list[str]
    prompt_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    input_tokens_estimate: int
    requested_output_tokens: int
    retention_mode: Literal["none", "digest_only", "metadata"]


class OpenAIChatMessage(StrictModel):
    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1, max_length=400_000, repr=False)


class OpenAIChatCompletionIn(StrictModel):
    model: str = Field(min_length=1, max_length=512)
    messages: list[OpenAIChatMessage] = Field(min_length=1, max_length=500)
    provider: Literal[
        "openai", "anthropic", "google", "openrouter", "azure_openai", "ollama", "vllm"
    ] | None = None
    region: str | None = Field(default=None, max_length=80)
    max_tokens: int = Field(default=4096, ge=1, le=200_000)
    temperature: float = Field(default=0, ge=0, le=2)
    stream: Literal[False] = False
    request_key: str | None = Field(default=None, min_length=1, max_length=128)
    application_key: str | None = Field(default=None, max_length=512)
    agent_key: str | None = Field(default=None, max_length=512)


class OpenAIChatCompletionOut(StrictModel):
    id: str
    object: Literal["chat.completion"] = "chat.completion"
    created: int
    model: str
    choices: list[dict[str, Any]]
    usage: dict[str, int]
    policy_receipt: dict[str, Any]


class AIToolManifestDecisionIn(StrictModel):
    approved: bool
    expected_schema_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class AIToolCallAuthorizeIn(StrictModel):
    manifest_id: uuid.UUID
    arguments: dict[str, Any]
    expected_manifest_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    approval_scope_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    delegation_expires_at: dt.datetime | None = None


class AIToolAuthorizationOut(StrictModel):
    allowed: bool
    manifest_digest: str
    argument_digest: str
    approval_scope_digest: str
    authorized_at: dt.datetime


class AIAccessGraphQueryIn(StrictModel):
    source_resource_id: uuid.UUID
    target_resource_id: uuid.UUID | None = None
    max_depth: int = Field(default=8, ge=1, le=32)


class AIAccessGraphOut(StrictModel):
    source_resource_id: uuid.UUID
    reachable: dict[str, int]
    paths: list[list[str]]


class AgentRunAssuranceCreateIn(StrictModel):
    run_id: uuid.UUID
    plan_version: int = Field(ge=1)
    plan_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    input_evidence_refs: list[str] = Field(default_factory=list, max_length=1000)
    budgets: dict[str, Any]
    success_criteria: list[dict[str, Any]] = Field(min_length=1, max_length=100)


class AgentRunAssuranceFinalizeIn(StrictModel):
    tool_receipts: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)
    approval_refs: list[str] = Field(default_factory=list, max_length=1000)
    artifact_refs: list[str] = Field(default_factory=list, max_length=1000)
    contradictory_evidence: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    confidence: Decimal = Field(ge=0, le=1)
    reason_codes: list[str] = Field(default_factory=list, max_length=100)
    verifier_status: Literal["passed", "failed", "inconclusive"]
    verifier_result: dict[str, Any]
    metrics: dict[str, Any] = Field(default_factory=dict)


class AgentRunAssuranceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    run_id: uuid.UUID
    plan_version: int
    plan_digest: str
    input_evidence_refs: list[str]
    tool_receipts: list[dict[str, Any]]
    budgets: dict[str, Any]
    approval_refs: list[str]
    artifact_refs: list[str]
    contradictory_evidence: list[dict[str, Any]]
    confidence: Decimal
    reason_codes: list[str]
    success_criteria: list[dict[str, Any]]
    verifier_status: str
    verifier_result: dict[str, Any]
    replay_digest: str | None
    metrics: dict[str, Any]
    finalized_at: dt.datetime | None


class AgentEvaluationCaseIn(StrictModel):
    case_key: str = Field(min_length=1, max_length=128)
    input_evidence_refs: list[str] = Field(min_length=1, max_length=100)
    expected_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    tags: list[str] = Field(default_factory=list, max_length=30)


class AgentEvaluationSuiteCreateIn(StrictModel):
    suite_key: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=240)
    task_kind: Literal[
        "finding_deduplication",
        "ticket_routing",
        "cve_prioritization",
        "false_positive_classification",
        "remediation_correctness",
        "tool_selection",
        "prompt_injection_resistance",
        "unsupported_claim_detection",
        "mixed",
    ]
    version: int = Field(ge=1)
    cases: list[AgentEvaluationCaseIn] = Field(min_length=1, max_length=10_000)
    thresholds: dict[str, Decimal] = Field(default_factory=dict)


class AgentEvaluationSuiteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    suite_key: str
    name: str
    task_kind: str
    version: int
    dataset_digest: str
    case_manifest: list[dict[str, Any]]
    thresholds: dict[str, Any]
    active: bool
    created_by_id: uuid.UUID | None


class AgentEvaluationResultIn(StrictModel):
    case_key: str = Field(min_length=1, max_length=128)
    outcome_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    task_completed: bool
    evidence_grounded: bool
    unsafe_actions: int = Field(default=0, ge=0, le=100_000)
    human_corrections: int = Field(default=0, ge=0, le=100_000)
    unsupported_claims: int = Field(default=0, ge=0, le=100_000)
    verified_outcomes: int = Field(default=0, ge=0, le=100_000)
    cost_usd: Decimal = Field(default=0, ge=0)
    closure_seconds: int | None = Field(default=None, ge=0, le=31_536_000)


class AgentEvaluationRunCreateIn(StrictModel):
    suite_id: uuid.UUID
    agent_version_id: uuid.UUID
    run_key: str = Field(min_length=16, max_length=128)
    results: list[AgentEvaluationResultIn] = Field(min_length=1, max_length=10_000)


class AgentEvaluationRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    suite_id: uuid.UUID
    agent_version_id: uuid.UUID
    run_key: str
    status: str
    metrics: dict[str, Any]
    failed_thresholds: list[str]
    case_results: list[dict[str, Any]]
    passed: bool
    total_cost_usd: Decimal
    completed_at: dt.datetime


class ValidationRecipeCreateIn(StrictModel):
    recipe_key: str = Field(min_length=1, max_length=128)
    assessment_id: uuid.UUID | None = None
    campaign_id: uuid.UUID | None = None
    run_id: uuid.UUID | None = None
    original_recipe_id: uuid.UUID | None = None
    targets: list[str] = Field(min_length=1, max_length=1000, repr=False)
    actions: list[dict[str, Any]] = Field(min_length=1, max_length=500)
    credential_refs: list[str] = Field(default_factory=list, max_length=100)
    artifact_refs: list[str] = Field(default_factory=list, max_length=1000)
    evidence_hashes: list[str] = Field(default_factory=list, max_length=1000)
    budgets: dict[str, Any]
    approval_refs: list[str] = Field(default_factory=list, max_length=100)
    exploitation_verdict: Literal[
        "observed", "likely_exploitable", "proved_exploitable", "not_exploitable"
    ] = "observed"


class ValidationRecipeVerifyIn(StrictModel):
    action_results: list[dict[str, Any]] = Field(min_length=1, max_length=500)
    exploitation_verdict: Literal[
        "observed", "likely_exploitable", "proved_exploitable", "not_exploitable"
    ]


class ValidationEvidenceAppendIn(StrictModel):
    artifact_ref: str = Field(min_length=1, max_length=1000)
    content_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    previous_chain_head: str = Field(pattern=r"^[a-f0-9]{64}$")


class ValidationRecipeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    recipe_key: str
    assessment_id: uuid.UUID | None
    campaign_id: uuid.UUID | None
    run_id: uuid.UUID | None
    original_recipe_id: uuid.UUID | None
    target_digest: str
    authorized_target_refs: list[str]
    actions: list[dict[str, Any]]
    credential_refs: list[str]
    artifact_refs: list[str]
    evidence_hashes: list[str]
    budgets: dict[str, Any]
    approval_refs: list[str]
    exploitation_verdict: str
    reproducibility_score: Decimal
    status: str
    verification: dict[str, Any]
    verified_at: dt.datetime | None


class DataSecurityAssessmentCreateIn(StrictModel):
    resource_id: uuid.UUID
    assessment_key: str = Field(min_length=1, max_length=128)
    provider: str = Field(min_length=1, max_length=80)
    service: str = Field(min_length=1, max_length=80)
    scan_mode: Literal["metadata_only", "controlled_sample", "full_authorized"] = "metadata_only"
    sample_policy: dict[str, Any] = Field(default_factory=dict)
    classifications: list[str] = Field(default_factory=list, max_length=100)
    lineage: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)
    duplicate_group: str | None = Field(default=None, max_length=128)
    sharing: dict[str, Any] = Field(default_factory=dict)
    identity_access: list[dict[str, Any]] = Field(default_factory=list, max_length=2000)
    encryption: dict[str, Any] = Field(default_factory=dict)
    key_posture: dict[str, Any] = Field(default_factory=dict)
    retention: dict[str, Any] = Field(default_factory=dict)
    residency: dict[str, Any] = Field(default_factory=dict)
    observed_at: dt.datetime


class DataSecurityAssessmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    resource_id: uuid.UUID
    assessment_key: str
    provider: str
    service: str
    scan_mode: str
    sample_policy: dict[str, Any]
    classifications: list[str]
    lineage: list[dict[str, Any]]
    duplicate_group: str | None
    sharing: dict[str, Any]
    identity_access: list[dict[str, Any]]
    encryption: dict[str, Any]
    key_posture: dict[str, Any]
    retention: dict[str, Any]
    residency: dict[str, Any]
    findings: list[dict[str, Any]]
    recommendations: list[dict[str, Any]]
    posture_score: Decimal
    observed_at: dt.datetime


class OCSFEventCreateIn(StrictModel):
    event_key: str = Field(min_length=1, max_length=512)
    class_uid: int = Field(gt=0)
    category_uid: int = Field(ge=1, le=8)
    activity_id: int = Field(ge=0)
    type_uid: int = Field(gt=0)
    time: dt.datetime
    severity_id: int = Field(ge=0, le=6)
    status_id: int | None = Field(default=None, ge=0)
    message: str = Field(min_length=1, max_length=4000)
    metadata: dict[str, Any]
    observables: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)
    actor: dict[str, Any] = Field(default_factory=dict)
    device: dict[str, Any] = Field(default_factory=dict)
    attacks: list[dict[str, Any]] = Field(default_factory=list, max_length=100)


class ThreatResponseActionCreateIn(StrictModel):
    story_id: uuid.UUID
    action_type: Literal[
        "isolate_endpoint",
        "revoke_credential",
        "restrict_access",
        "disable_identity",
        "create_ticket",
        "notify",
    ]
    target_ref: str = Field(min_length=1, max_length=512)
    provider: Literal[
        "crowdstrike", "zscaler", "jira", "servicenow", "slack", "manual"
    ] = "manual"
    requested_action: dict[str, Any] = Field(default_factory=dict)
    predicted_impact: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str = Field(min_length=16, max_length=128)


class ThreatResponseActionApproveIn(StrictModel):
    expected_scope_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class ThreatResponseActionExecuteIn(StrictModel):
    expected_scope_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class ThreatResponseActionVerifyIn(StrictModel):
    effective: bool
    evidence: dict[str, Any] = Field(default_factory=dict)


class ThreatResponseActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    story_id: uuid.UUID
    action_type: str
    target_ref: str
    provider: str
    requested_action: dict[str, Any]
    status: str
    predicted_impact: dict[str, Any]
    approval_id: uuid.UUID | None
    approval_scope_digest: str | None
    approved_by_id: uuid.UUID | None
    idempotency_key: str
    provider_receipt: dict[str, Any]
    rollback_receipt: dict[str, Any]
    verification: dict[str, Any]
    failure_code: str | None
    approved_at: dt.datetime | None
    executed_at: dt.datetime | None
    verified_at: dt.datetime | None


class MonteCarloSimulationCreateIn(StrictModel):
    simulation_id: uuid.UUID
    comparison_trial_id: uuid.UUID | None = None
    iterations: int = Field(default=10_000, ge=1000, le=1_000_000)
    seed: int
    frequency_min: Decimal = Field(ge=0, le=1)
    frequency_likely: Decimal = Field(ge=0, le=1)
    frequency_max: Decimal = Field(ge=0, le=1)
    primary_loss_min: Decimal = Field(ge=0)
    primary_loss_likely: Decimal = Field(ge=0)
    primary_loss_max: Decimal = Field(ge=0)
    secondary_loss_min: Decimal = Field(ge=0)
    secondary_loss_likely: Decimal = Field(ge=0)
    secondary_loss_max: Decimal = Field(ge=0)
    control_effectiveness_min: Decimal = Field(ge=0, le=1)
    control_effectiveness_likely: Decimal = Field(ge=0, le=1)
    control_effectiveness_max: Decimal = Field(ge=0, le=1)
    assumptions_version: int = Field(ge=1)
    calibration: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def ordered_ranges(self) -> MonteCarloSimulationCreateIn:
        ranges = (
            (self.frequency_min, self.frequency_likely, self.frequency_max),
            (self.primary_loss_min, self.primary_loss_likely, self.primary_loss_max),
            (self.secondary_loss_min, self.secondary_loss_likely, self.secondary_loss_max),
            (
                self.control_effectiveness_min,
                self.control_effectiveness_likely,
                self.control_effectiveness_max,
            ),
        )
        if any(not low <= likely <= high for low, likely, high in ranges):
            raise ValueError("frequency, loss, and effectiveness ranges must be ordered")
        return self


class RiskSimulationTrialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    simulation_id: uuid.UUID
    comparison_trial_id: uuid.UUID | None
    run_key: str
    status: str
    iterations: int
    seed: int
    assumptions_version: int
    distributions: dict[str, Any]
    percentile_05: Decimal
    percentile_50: Decimal
    percentile_95: Decimal
    mean_annual_loss: Decimal
    standard_deviation: Decimal
    confidence_level: Decimal
    calibration: dict[str, Any]
    completed_at: dt.datetime


class ComplianceInheritanceCreateIn(StrictModel):
    control_id: uuid.UUID
    parent_control_id: uuid.UUID
    source_system: str = Field(min_length=1, max_length=240)
    responsibility: Literal["inherited", "shared", "customer"] = "shared"
    inherited_percentage: Decimal = Field(default=Decimal("100"), ge=0, le=100)
    evidence_refs: list[str] = Field(default_factory=list, max_length=1000)


class ComplianceInheritanceOut(StrictModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    control_id: uuid.UUID
    parent_control_id: uuid.UUID
    source_system: str
    responsibility: str
    inherited_percentage: Decimal
    evidence_refs: list[str]
    created_at: dt.datetime


class ComplianceEvidenceRequestCreateIn(StrictModel):
    workspace_id: uuid.UUID
    control_id: uuid.UUID
    request_key: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=4000)
    assignee_user_id: uuid.UUID | None = None
    freshness_days: int = Field(default=90, ge=1, le=3650)
    due_at: dt.datetime | None = None


class ComplianceEvidenceRequestTransitionIn(StrictModel):
    expected_status: Literal["open", "collecting", "submitted", "accepted", "rejected"]
    status: Literal["collecting", "submitted", "accepted", "rejected", "cancelled"]
    evidence_ids: list[uuid.UUID] = Field(default_factory=list, max_length=1000)
    note: str | None = Field(default=None, max_length=4000)


class ComplianceEvidenceRequestOut(StrictModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    workspace_id: uuid.UUID
    control_id: uuid.UUID
    request_key: str
    title: str
    description: str
    assignee_user_id: uuid.UUID | None
    requested_by_id: uuid.UUID | None
    submitted_by_id: uuid.UUID | None
    reviewed_by_id: uuid.UUID | None
    status: str
    freshness_days: int
    due_at: dt.datetime | None
    fulfilled_evidence_ids: list[str]
    review_note: str | None
    status_changed_at: dt.datetime
    submitted_at: dt.datetime | None
    fulfilled_at: dt.datetime | None
    created_at: dt.datetime


class OSCALExportCreateIn(StrictModel):
    workspace_id: uuid.UUID
    model: Literal["assessment-results", "poam"]
    package_key: str = Field(min_length=1, max_length=128)
    oscal_version: str = Field(default="1.1.2", min_length=1, max_length=20)


class OSCALExportOut(StrictModel):
    package_id: uuid.UUID
    package_key: str
    content_digest: str
    signature: str
    signing_key_id: str
    manifest: dict[str, Any]
    document: dict[str, Any]


__all__ = [name for name in globals() if name.endswith(("In", "Out"))]
