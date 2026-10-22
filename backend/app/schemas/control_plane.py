"""Strict wire contracts for the unified security control plane."""

from __future__ import annotations

import datetime as dt
import uuid
from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Severity = Literal["info", "low", "medium", "high", "critical"]
AttackTechniqueId = Annotated[
    str, Field(min_length=5, max_length=9, pattern=r"^T\d{4}(?:\.\d{3})?$")
]


class SecurityResourceUpsertIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource_key: str = Field(min_length=1, max_length=512)
    kind: Literal[
        "asset",
        "data_store",
        "dataset",
        "saas_application",
        "ai_application",
        "ai_model",
        "ai_agent",
        "mcp_server",
        "ai_tool",
        "identity",
        "endpoint",
        "browser",
    ]
    name: str = Field(min_length=1, max_length=300)
    source_kind: str = Field(min_length=1, max_length=80)
    source_key: str = Field(min_length=1, max_length=512)
    integration_id: uuid.UUID | None = None
    observed_at: dt.datetime
    expires_at: dt.datetime | None = None
    confidence: Decimal = Field(ge=0, le=1, max_digits=4, decimal_places=3)
    provider: str | None = Field(default=None, max_length=80)
    external_id: str | None = Field(default=None, max_length=512)
    asset_id: uuid.UUID | None = None
    owner_team: str | None = Field(default=None, max_length=120)
    environment: Literal["production", "staging", "development", "test", "unknown"] = "unknown"
    internet_exposed: bool = False
    approved: bool | None = None
    sensitivity: Literal["unknown", "public", "internal", "confidential", "restricted"] = "unknown"
    classifications: list[str] = Field(default_factory=list, max_length=100)
    permissions: dict[str, Any] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)


class SecurityResourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    resource_key: str
    kind: str
    name: str
    provider: str | None
    external_id: str | None
    asset_id: uuid.UUID | None
    owner_team: str | None
    environment: str
    internet_exposed: bool
    approved: bool | None
    posture_status: str
    risk_score: Decimal
    sensitivity: str
    classifications: list[str]
    permissions: dict[str, Any]
    attributes: dict[str, Any]
    provenance: dict[str, Any]
    source_count: int
    identity_confidence: Decimal
    first_seen_at: dt.datetime
    last_seen_at: dt.datetime


class SecurityPolicyCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    kind: Literal[
        "ztna",
        "secure_web_gateway",
        "firewall",
        "tls_inspection",
        "dlp",
        "casb",
        "sspm",
        "ai_gateway",
        "ai_guard",
        "endpoint_isolation",
        "browser_isolation",
    ]
    mode: Literal["monitor", "recommend", "enforce"] = "recommend"
    rules: dict[str, Any] = Field(default_factory=dict)
    integration_id: uuid.UUID | None = None


class SecurityPolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    kind: str
    mode: str
    status: str
    version: int
    rules: dict[str, Any]
    integration_id: uuid.UUID | None
    created_at: dt.datetime


class SecurityPolicyEvaluationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    policy_id: uuid.UUID
    resource_id: uuid.UUID | None
    event_id: uuid.UUID | None
    decision: str
    severity: str
    score: Decimal
    findings: list[dict[str, Any]]
    evidence: dict[str, Any]
    content_digest: str | None
    evaluated_at: dt.datetime


class PrivateAccessEvaluateIn(BaseModel):
    """Attested identity/device context for a private-application access request."""

    model_config = ConfigDict(extra="forbid")

    policy_id: uuid.UUID
    request_id: str = Field(min_length=1, max_length=256)
    identity_ref: str = Field(min_length=1, max_length=512)
    groups: list[str] = Field(default_factory=list, max_length=100)
    application_ref: str = Field(min_length=1, max_length=512)
    application_tags: list[str] = Field(default_factory=list, max_length=100)
    device_posture: list[str] = Field(default_factory=list, max_length=100)
    mfa: bool = False
    source_country: str | None = Field(default=None, min_length=2, max_length=2)
    identity_risk_score: Decimal = Field(
        default=Decimal("0"), ge=0, le=100, max_digits=5, decimal_places=2
    )
    requested_session_minutes: int = Field(default=15, ge=1, le=10_080)


class PrivateAccessDecisionOut(BaseModel):
    policy_id: uuid.UUID
    policy_version: int
    event_id: uuid.UUID
    decision: Literal["allow", "deny"]
    enforced: bool
    would_block: bool
    session_minutes: int = Field(ge=1, le=10_080)
    reason_codes: list[str]


class SecurityRecommendationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    policy_id: uuid.UUID | None
    resource_id: uuid.UUID | None
    asset_id: uuid.UUID | None
    integration_id: uuid.UUID | None
    domain: str
    title: str
    rationale: str
    action: str
    severity: str
    status: str
    current_state: dict[str, Any]
    desired_state: dict[str, Any]
    idempotency_key: str
    provider_receipt: dict[str, Any]
    applied_by_id: uuid.UUID | None
    applied_at: dt.datetime | None
    created_at: dt.datetime


class SecurityPostureOut(BaseModel):
    total_resources: int
    active_sources: int
    stale_resources: int
    unknown_owner: int
    internet_exposed: int
    non_compliant: int
    at_risk: int
    approved_ai: int
    unapproved_ai: int
    source_coverage: dict[str, int]
    kind_coverage: dict[str, int]
    average_identity_confidence: Decimal


class NativeAIPostureAssessmentOut(BaseModel):
    policy_id: uuid.UUID
    assessed_resources: int
    compliant_resources: int
    at_risk_resources: int
    critical_resources: int
    recommendations_created: int
    evaluation_ids: list[uuid.UUID]
    recommendation_ids: list[uuid.UUID]
    finding_counts: dict[str, int]
    external_connector_required: bool


class SecurityRecommendationDecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "reject", "apply"]
    note: str | None = Field(default=None, max_length=2000)


class SecurityEventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_key: str = Field(min_length=1, max_length=512)
    category: Literal[
        "experience",
        "incident",
        "identity",
        "deception",
        "access",
        "dlp",
        "ai_gateway",
        "endpoint",
        "browser",
    ]
    event_type: str = Field(min_length=1, max_length=100)
    source_kind: str = Field(min_length=1, max_length=80)
    occurred_at: dt.datetime
    severity: Severity = "info"
    summary: str = Field(min_length=1, max_length=4000)
    content_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    asset_id: uuid.UUID | None = None
    resource_id: uuid.UUID | None = None
    identity_ref: str | None = Field(default=None, max_length=512)
    metrics: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)


class NativeEndpointEventIn(BaseModel):
    """Bounded telemetry contract for a Cynux endpoint sensor or collector."""

    model_config = ConfigDict(extra="forbid")

    event_key: str = Field(min_length=1, max_length=512)
    endpoint_key: str = Field(min_length=1, max_length=256)
    hostname: str = Field(min_length=1, max_length=255)
    operating_system: Literal["windows", "linux", "macos", "other"]
    occurred_at: dt.datetime
    event_type: Literal[
        "process_start",
        "network_connection",
        "file_change",
        "identity_activity",
        "persistence",
        "autorun_change",
        "scheduled_task_created",
        "security_control_disabled",
        "sensor_tamper",
        "defense_evasion",
        "ransomware_activity",
        "malware",
    ]
    process_name: str | None = Field(default=None, max_length=260)
    parent_process_name: str | None = Field(default=None, max_length=260)
    executable_path: str | None = Field(default=None, max_length=1024, repr=False)
    command_line: str | None = Field(default=None, max_length=8192, repr=False)
    signature_status: Literal["signed", "unsigned", "invalid", "unknown"] = "unknown"
    destination_host: str | None = Field(default=None, max_length=253, repr=False)
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    destination_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    network_action: Literal["allowed", "blocked"] | None = None
    file_activity_count: int = Field(default=0, ge=0, le=1_000_000)
    file_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    malware_signature: str | None = Field(default=None, min_length=1, max_length=256)
    scanner_engine: Literal["clamav"] | None = None
    identity_ref: str | None = Field(default=None, max_length=512, repr=False)
    attack_techniques: list[AttackTechniqueId] = Field(default_factory=list, max_length=100)
    asset_id: uuid.UUID | None = None
    environment: Literal["production", "staging", "development", "test", "unknown"] = "unknown"
    internet_exposed: bool = False


class SecurityEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    event_key: str
    category: str
    event_type: str
    source_kind: str
    occurred_at: dt.datetime
    severity: str
    summary: str
    content_digest: str | None
    asset_id: uuid.UUID | None
    resource_id: uuid.UUID | None
    identity_ref: str | None
    metrics: dict[str, Any]
    evidence: dict[str, Any]


class ThreatStoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    correlation_key: str
    title: str
    status: str
    severity: str
    confidence: Decimal
    summary: str
    event_ids: list[str]
    asset_ids: list[str]
    finding_ids: list[str]
    identity_refs: list[str]
    timeline: list[dict[str, Any]]
    first_seen_at: dt.datetime
    last_seen_at: dt.datetime
    assigned_user_id: uuid.UUID | None
    resolution: str | None


class NativeEndpointEventOut(BaseModel):
    endpoint: SecurityResourceOut
    event: SecurityEventOut
    story: ThreatStoryOut | None
    decision: dict[str, Any]


class DeceptionCanaryCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    kind: Literal["credential", "dns", "http", "file", "cloud_resource", "identity"]
    token: str = Field(min_length=24, max_length=512, repr=False)
    asset_id: uuid.UUID | None = None
    placement: dict[str, Any] = Field(default_factory=dict)


class DeceptionCanaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    kind: str
    token_digest: str
    asset_id: uuid.UUID | None
    status: str
    placement: dict[str, Any]
    last_triggered_at: dt.datetime | None
    created_at: dt.datetime


class CanaryInteractionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    interaction_key: str = Field(min_length=1, max_length=256)
    occurred_at: dt.datetime
    source_ip: str | None = Field(default=None, max_length=128, repr=False)
    identity_ref: str | None = Field(default=None, max_length=512)
    protocol: str | None = Field(default=None, max_length=40)
    severity: Severity = "high"
    evidence: dict[str, Any] = Field(default_factory=dict)


class CanaryInteractionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    canary_id: uuid.UUID
    event_id: uuid.UUID | None
    interaction_key: str
    occurred_at: dt.datetime
    source_ip_digest: str | None
    identity_ref: str | None
    protocol: str | None
    severity: str
    evidence: dict[str, Any]


class ExperienceSummaryOut(BaseModel):
    event_count: int
    monitored_journeys: int
    degraded_journeys: int
    average_score: Decimal
    business_impact: Literal["unknown", "low", "moderate", "high", "critical"]
    latest_at: dt.datetime | None


class RiskSimulationCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=240)
    business_service_id: uuid.UUID | None = None
    scenario_id: uuid.UUID | None = None
    annual_probability: Decimal = Field(ge=0, le=1, max_digits=6, decimal_places=5)
    loss_min: Decimal = Field(ge=0, max_digits=16, decimal_places=2)
    loss_likely: Decimal = Field(ge=0, max_digits=16, decimal_places=2)
    loss_max: Decimal = Field(ge=0, max_digits=16, decimal_places=2)
    control_effectiveness: Decimal = Field(ge=0, le=1, max_digits=6, decimal_places=5)
    assumptions: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def ordered_losses(self) -> RiskSimulationCreateIn:
        if not self.loss_min <= self.loss_likely <= self.loss_max:
            raise ValueError("loss estimates must be ordered min <= likely <= max")
        return self


class RiskSimulationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    business_service_id: uuid.UUID | None
    scenario_id: uuid.UUID | None
    status: str
    annual_probability: Decimal
    loss_min: Decimal
    loss_likely: Decimal
    loss_max: Decimal
    control_effectiveness: Decimal
    acceptance_status: str
    expected_loss: Decimal
    inherent_annual_loss: Decimal
    residual_annual_loss: Decimal
    assumptions: dict[str, Any]
    evidence: dict[str, Any]
    narrative: str | None


class AIGatewayEvaluateIn(BaseModel):
    """Transient content input. ``content`` is evaluated in memory and never stored."""

    model_config = ConfigDict(extra="forbid")

    direction: Literal["prompt", "output"]
    content: str = Field(min_length=1, max_length=100_000, repr=False)
    policy_id: uuid.UUID | None = None
    application_key: str | None = Field(default=None, max_length=512)
    model_key: str | None = Field(default=None, max_length=512)
    agent_key: str | None = Field(default=None, max_length=512)
    tool_keys: list[str] = Field(default_factory=list, max_length=100)
    requested_action: str | None = Field(default=None, max_length=200)


class AIGatewayEvaluateOut(BaseModel):
    decision: Literal["allow", "block", "redact", "require_approval"]
    severity: Severity
    score: Decimal
    reasons: list[str]
    content_digest: str
    redacted_content: str | None = Field(default=None, repr=False)
    approval_required: bool


class DataClassificationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(min_length=1, max_length=100_000, repr=False)
    resource_key: str | None = Field(default=None, max_length=512)


class DataClassificationOut(BaseModel):
    labels: list[str]
    highest_sensitivity: Literal["public", "internal", "confidential", "restricted"]
    redacted_content: str = Field(repr=False)
    content_digest: str
    match_counts: dict[str, int]


__all__ = [
    "AIGatewayEvaluateIn",
    "AIGatewayEvaluateOut",
    "CanaryInteractionIn",
    "CanaryInteractionOut",
    "DataClassificationIn",
    "DataClassificationOut",
    "DeceptionCanaryCreateIn",
    "DeceptionCanaryOut",
    "ExperienceSummaryOut",
    "RiskSimulationCreateIn",
    "RiskSimulationOut",
    "SecurityEventIn",
    "SecurityEventOut",
    "SecurityPolicyCreateIn",
    "SecurityPolicyEvaluationOut",
    "NativeAIPostureAssessmentOut",
    "SecurityPolicyOut",
    "SecurityPostureOut",
    "SecurityRecommendationOut",
    "SecurityRecommendationDecisionIn",
    "SecurityResourceOut",
    "SecurityResourceUpsertIn",
    "ThreatStoryOut",
]
