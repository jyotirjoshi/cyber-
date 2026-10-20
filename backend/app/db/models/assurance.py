"""Durable, digest-first records for the assurance runtime."""

from __future__ import annotations

import datetime as dt
import uuid
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantMixin, TimestampMixin, uuid_pk


class EnforcementTransaction(Base, TenantMixin, TimestampMixin):
    __tablename__ = "enforcement_transactions"

    id: Mapped[uuid.UUID] = uuid_pk()
    recommendation_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("security_recommendations.id", ondelete="CASCADE"),
        nullable=False,
    )
    integration_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("integrations.id", ondelete="SET NULL")
    )
    provider: Mapped[str] = mapped_column(String(80), nullable=False)
    operation: Mapped[str] = mapped_column(String(120), nullable=False)
    transaction_key: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="draft")
    provider_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    snapshot_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    desired_state: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    diff: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    diff_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    blast_radius: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    approval_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("approvals.id", ondelete="SET NULL")
    )
    approved_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    mutation_receipt: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    confirmation: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    verification: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    rollback_plan: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    observation_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    observation_ends_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    approved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    executed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "transaction_key", name="unique_enforcement_transaction_key"
        ),
        UniqueConstraint(
            "organization_id", "idempotency_key", name="unique_enforcement_idempotency_key"
        ),
        CheckConstraint(
            "status IN ('draft','simulated','pending_approval','approved','applying','observing',"
            "'verifying','succeeded','rollback_pending','rolling_back','rolled_back','failed','cancelled')",
            name="valid_enforcement_transaction_status",
        ),
        CheckConstraint(
            "observation_seconds BETWEEN 0 AND 604800",
            name="valid_enforcement_observation_seconds",
        ),
        Index("ix_enforcement_transactions_org_status", "organization_id", "status"),
        Index(
            "ix_enforcement_transactions_org_recommendation", "organization_id", "recommendation_id"
        ),
    )


class AIInteractionReceipt(Base, TenantMixin, TimestampMixin):
    __tablename__ = "ai_interaction_receipts"

    id: Mapped[uuid.UUID] = uuid_pk()
    request_key: Mapped[str] = mapped_column(String(128), nullable=False)
    application_key: Mapped[str | None] = mapped_column(String(512))
    agent_key: Mapped[str | None] = mapped_column(String(512))
    model_key: Mapped[str] = mapped_column(String(512), nullable=False)
    provider: Mapped[str] = mapped_column(String(80), nullable=False)
    region: Mapped[str | None] = mapped_column(String(80))
    decision: Mapped[str] = mapped_column(String(24), nullable=False)
    prompt_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    output_digest: Mapped[str | None] = mapped_column(String(64))
    tool_keys: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    reason_codes: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    cost_usd: Mapped[Decimal] = mapped_column(Numeric(14, 6), nullable=False, default=0)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    retention_mode: Mapped[str] = mapped_column(String(20), nullable=False, default="digest_only")
    occurred_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("organization_id", "request_key", name="unique_ai_interaction_request"),
        CheckConstraint(
            "decision IN ('allow','block','redact','require_approval')",
            name="valid_ai_interaction_decision",
        ),
        CheckConstraint(
            "input_tokens >= 0 AND output_tokens >= 0", name="valid_ai_interaction_tokens"
        ),
        CheckConstraint("cost_usd >= 0", name="valid_ai_interaction_cost"),
        CheckConstraint(
            "retention_mode IN ('none','digest_only','metadata')",
            name="valid_ai_interaction_retention",
        ),
        Index("ix_ai_interactions_org_time", "organization_id", "occurred_at"),
        Index("ix_ai_interactions_org_agent", "organization_id", "agent_key"),
    )


class AIToolManifest(Base, TenantMixin, TimestampMixin):
    __tablename__ = "ai_tool_manifests"

    id: Mapped[uuid.UUID] = uuid_pk()
    server_key: Mapped[str] = mapped_column(String(512), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(240), nullable=False)
    version: Mapped[str] = mapped_column(String(80), nullable=False)
    schema_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    argument_schema: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    result_schema: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    permissions: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    owner_team: Mapped[str | None] = mapped_column(String(120))
    approved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending_review")
    observed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "server_key",
            "tool_name",
            "version",
            name="unique_ai_tool_manifest_version",
        ),
        CheckConstraint(
            "status IN ('pending_review','approved','changed','revoked','disabled')",
            name="valid_ai_tool_manifest_status",
        ),
        Index("ix_ai_tool_manifests_org_status", "organization_id", "status"),
        Index("ix_ai_tool_manifests_org_server", "organization_id", "server_key"),
    )


class AIAccessEdge(Base, TenantMixin, TimestampMixin):
    __tablename__ = "ai_access_edges"

    id: Mapped[uuid.UUID] = uuid_pk()
    source_resource_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("security_resources.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_resource_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("security_resources.id", ondelete="CASCADE"),
        nullable=False,
    )
    relation: Mapped[str] = mapped_column(String(40), nullable=False)
    privileges: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    approved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    source_kind: Mapped[str] = mapped_column(String(80), nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "source_resource_id",
            "target_resource_id",
            "relation",
            name="unique_ai_access_edge",
        ),
        CheckConstraint(
            "relation IN ('uses','calls','assumes_identity','reads','writes','administers','contains_sensitive_data')",
            name="valid_ai_access_edge_relation",
        ),
        CheckConstraint(
            "source_resource_id <> target_resource_id", name="valid_ai_access_edge_distinct_nodes"
        ),
        Index("ix_ai_access_edges_org_source", "organization_id", "source_resource_id"),
        Index("ix_ai_access_edges_org_target", "organization_id", "target_resource_id"),
    )


class AgentRunAssurance(Base, TenantMixin, TimestampMixin):
    __tablename__ = "agent_run_assurance"

    id: Mapped[uuid.UUID] = uuid_pk()
    run_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_runs.id", ondelete="CASCADE"), nullable=False
    )
    plan_version: Mapped[int] = mapped_column(Integer, nullable=False)
    plan_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    input_evidence_refs: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    tool_receipts: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    budgets: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    approval_refs: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    artifact_refs: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    contradictory_evidence: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    confidence: Mapped[Decimal] = mapped_column(Numeric(4, 3), nullable=False, default=0)
    reason_codes: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    success_criteria: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    verifier_status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending")
    verifier_result: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    replay_digest: Mapped[str | None] = mapped_column(String(64))
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    finalized_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("organization_id", "run_id", name="unique_agent_run_assurance"),
        CheckConstraint("plan_version > 0", name="valid_agent_assurance_plan_version"),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="valid_agent_assurance_confidence"),
        CheckConstraint(
            "verifier_status IN ('pending','passed','failed','inconclusive')",
            name="valid_agent_assurance_verifier_status",
        ),
        Index("ix_agent_run_assurance_org_verifier", "organization_id", "verifier_status"),
    )


class AgentEvaluationSuite(Base, TenantMixin, TimestampMixin):
    __tablename__ = "agent_evaluation_suites"

    id: Mapped[uuid.UUID] = uuid_pk()
    suite_key: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(240), nullable=False)
    task_kind: Mapped[str] = mapped_column(String(80), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    dataset_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    case_manifest: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    thresholds: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "suite_key", "version", name="unique_agent_evaluation_suite"
        ),
        CheckConstraint("version > 0", name="valid_agent_evaluation_suite_version"),
        Index("ix_agent_evaluation_suites_org_active", "organization_id", "active"),
    )


class AgentEvaluationRun(Base, TenantMixin, TimestampMixin):
    __tablename__ = "agent_evaluation_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    suite_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("agent_evaluation_suites.id", ondelete="CASCADE"),
        nullable=False,
    )
    agent_version_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("agent_definition_versions.id", ondelete="CASCADE"),
        nullable=False,
    )
    run_key: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="completed")
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    failed_thresholds: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    case_results: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    total_cost_usd: Mapped[Decimal] = mapped_column(
        Numeric(12, 6), nullable=False, default=0
    )
    completed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("organization_id", "run_key", name="unique_agent_evaluation_run_key"),
        CheckConstraint(
            "status IN ('completed','failed','superseded')",
            name="valid_agent_evaluation_run_status",
        ),
        CheckConstraint("total_cost_usd >= 0", name="valid_agent_evaluation_run_cost"),
        Index("ix_agent_evaluation_runs_org_suite", "organization_id", "suite_id"),
    )


class ValidationRecipe(Base, TenantMixin, TimestampMixin):
    __tablename__ = "validation_recipes"

    id: Mapped[uuid.UUID] = uuid_pk()
    recipe_key: Mapped[str] = mapped_column(String(128), nullable=False)
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assessments.id", ondelete="SET NULL")
    )
    campaign_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("attack_simulation_campaigns.id", ondelete="SET NULL")
    )
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("attack_simulation_runs.id", ondelete="SET NULL")
    )
    original_recipe_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("validation_recipes.id", ondelete="SET NULL")
    )
    target_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    authorized_target_refs: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    actions: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    credential_refs: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    artifact_refs: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    evidence_hashes: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    budgets: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    approval_refs: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    exploitation_verdict: Mapped[str] = mapped_column(
        String(30), nullable=False, default="observed"
    )
    reproducibility_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="recorded")
    verification: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    verified_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("organization_id", "recipe_key", name="unique_validation_recipe_key"),
        CheckConstraint(
            "exploitation_verdict IN ('observed','likely_exploitable','proved_exploitable','not_exploitable')",
            name="valid_validation_recipe_verdict",
        ),
        CheckConstraint(
            "reproducibility_score BETWEEN 0 AND 100", name="valid_validation_reproducibility"
        ),
        CheckConstraint(
            "status IN ('recorded','approved','executing','verified','failed','superseded')",
            name="valid_validation_recipe_status",
        ),
        Index("ix_validation_recipes_org_status", "organization_id", "status"),
    )


class DataSecurityAssessment(Base, TenantMixin, TimestampMixin):
    __tablename__ = "data_security_assessments"

    id: Mapped[uuid.UUID] = uuid_pk()
    resource_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("security_resources.id", ondelete="CASCADE"),
        nullable=False,
    )
    assessment_key: Mapped[str] = mapped_column(String(128), nullable=False)
    provider: Mapped[str] = mapped_column(String(80), nullable=False)
    service: Mapped[str] = mapped_column(String(80), nullable=False)
    scan_mode: Mapped[str] = mapped_column(String(24), nullable=False, default="metadata_only")
    sample_policy: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    classifications: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    lineage: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    duplicate_group: Mapped[str | None] = mapped_column(String(128))
    sharing: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    identity_access: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    encryption: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    key_posture: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    retention: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    residency: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    recommendations: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    posture_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False, default=0)
    observed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "assessment_key", name="unique_data_security_assessment_key"
        ),
        CheckConstraint(
            "scan_mode IN ('metadata_only','controlled_sample','full_authorized')",
            name="valid_data_security_scan_mode",
        ),
        CheckConstraint(
            "posture_score BETWEEN 0 AND 100", name="valid_data_security_posture_score"
        ),
        Index("ix_data_security_assessments_org_resource", "organization_id", "resource_id"),
        Index("ix_data_security_assessments_org_observed", "organization_id", "observed_at"),
    )


class ThreatResponseAction(Base, TenantMixin, TimestampMixin):
    __tablename__ = "threat_response_actions"

    id: Mapped[uuid.UUID] = uuid_pk()
    story_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("security_threat_stories.id", ondelete="CASCADE"),
        nullable=False,
    )
    action_type: Mapped[str] = mapped_column(String(40), nullable=False)
    target_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    provider: Mapped[str] = mapped_column(String(80), nullable=False, default="manual")
    requested_action: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="proposed")
    predicted_impact: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    approval_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("approvals.id", ondelete="SET NULL")
    )
    approval_scope_digest: Mapped[str | None] = mapped_column(String(64))
    approved_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    provider_receipt: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    rollback_receipt: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    verification: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    failure_code: Mapped[str | None] = mapped_column(String(120))
    approved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    executed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "idempotency_key", name="unique_threat_response_action_key"
        ),
        CheckConstraint(
            "action_type IN ('isolate_endpoint','revoke_credential','restrict_access','disable_identity','create_ticket','notify')",
            name="valid_threat_response_action_type",
        ),
        CheckConstraint(
            "status IN ('proposed','approved','executing','executed','verified','failed','rolled_back')",
            name="valid_threat_response_action_status",
        ),
        Index("ix_threat_response_actions_org_story", "organization_id", "story_id"),
    )


class RiskSimulationTrial(Base, TenantMixin, TimestampMixin):
    __tablename__ = "risk_simulation_trials"

    id: Mapped[uuid.UUID] = uuid_pk()
    simulation_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("security_risk_simulations.id", ondelete="CASCADE"),
        nullable=False,
    )
    comparison_trial_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("risk_simulation_trials.id", ondelete="SET NULL")
    )
    run_key: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="completed")
    iterations: Mapped[int] = mapped_column(Integer, nullable=False)
    seed: Mapped[int] = mapped_column(Integer, nullable=False)
    assumptions_version: Mapped[int] = mapped_column(Integer, nullable=False)
    distributions: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    percentile_05: Mapped[Decimal] = mapped_column(Numeric(16, 2), nullable=False)
    percentile_50: Mapped[Decimal] = mapped_column(Numeric(16, 2), nullable=False)
    percentile_95: Mapped[Decimal] = mapped_column(Numeric(16, 2), nullable=False)
    mean_annual_loss: Mapped[Decimal] = mapped_column(Numeric(16, 2), nullable=False)
    standard_deviation: Mapped[Decimal] = mapped_column(Numeric(16, 2), nullable=False)
    confidence_level: Mapped[Decimal] = mapped_column(
        Numeric(4, 3), nullable=False, default=Decimal("0.95")
    )
    calibration: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    completed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("organization_id", "run_key", name="unique_risk_simulation_trial_key"),
        CheckConstraint(
            "status IN ('completed','failed','superseded')",
            name="valid_risk_simulation_trial_status",
        ),
        CheckConstraint(
            "iterations BETWEEN 1000 AND 1000000", name="valid_risk_simulation_iterations"
        ),
        CheckConstraint(
            "assumptions_version > 0", name="valid_risk_simulation_assumptions_version"
        ),
        CheckConstraint(
            "confidence_level > 0 AND confidence_level < 1", name="valid_risk_simulation_confidence"
        ),
        CheckConstraint(
            "percentile_05 <= percentile_50 AND percentile_50 <= percentile_95",
            name="valid_risk_simulation_percentiles",
        ),
        Index("ix_risk_simulation_trials_org_simulation", "organization_id", "simulation_id"),
    )


class ComplianceControlInheritance(Base, TenantMixin, TimestampMixin):
    __tablename__ = "compliance_control_inheritances"

    id: Mapped[uuid.UUID] = uuid_pk()
    control_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    parent_control_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_system: Mapped[str] = mapped_column(String(240), nullable=False)
    responsibility: Mapped[str] = mapped_column(String(24), nullable=False, default="shared")
    inherited_percentage: Mapped[Decimal] = mapped_column(
        Numeric(5, 2), nullable=False, default=100
    )
    evidence_refs: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "control_id",
            "parent_control_id",
            name="unique_compliance_control_inheritance",
        ),
        CheckConstraint(
            "control_id <> parent_control_id", name="valid_compliance_inheritance_distinct_controls"
        ),
        CheckConstraint(
            "responsibility IN ('inherited','shared','customer')",
            name="valid_compliance_inheritance_responsibility",
        ),
        CheckConstraint(
            "inherited_percentage BETWEEN 0 AND 100", name="valid_compliance_inherited_percentage"
        ),
        Index("ix_compliance_inheritance_org_control", "organization_id", "control_id"),
    )


class ComplianceEvidenceRequest(Base, TenantMixin, TimestampMixin):
    __tablename__ = "compliance_evidence_requests"

    id: Mapped[uuid.UUID] = uuid_pk()
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("compliance_audit_workspaces.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    request_key: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    assignee_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="open")
    freshness_days: Mapped[int] = mapped_column(Integer, nullable=False, default=90)
    due_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    fulfilled_evidence_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    fulfilled_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "request_key", name="unique_compliance_evidence_request_key"
        ),
        CheckConstraint(
            "status IN ('open','collecting','submitted','accepted','rejected','cancelled')",
            name="valid_compliance_evidence_request_status",
        ),
        CheckConstraint(
            "freshness_days BETWEEN 1 AND 3650", name="valid_compliance_evidence_freshness"
        ),
        Index("ix_compliance_evidence_requests_org_workspace", "organization_id", "workspace_id"),
        Index("ix_compliance_evidence_requests_org_status", "organization_id", "status"),
    )


class ComplianceExportPackage(Base, TenantMixin, TimestampMixin):
    __tablename__ = "compliance_export_packages"

    id: Mapped[uuid.UUID] = uuid_pk()
    workspace_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("compliance_audit_workspaces.id", ondelete="CASCADE"),
        nullable=False,
    )
    package_key: Mapped[str] = mapped_column(String(128), nullable=False)
    oscal_model: Mapped[str] = mapped_column(String(40), nullable=False)
    oscal_version: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="generated")
    artifact_reference: Mapped[str | None] = mapped_column(String(2048))
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(80), nullable=False)
    manifest: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    generated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "package_key", name="unique_compliance_export_package_key"
        ),
        CheckConstraint(
            "oscal_model IN ('assessment-results','poam','component-definition','ssp')",
            name="valid_compliance_export_oscal_model",
        ),
        CheckConstraint(
            "status IN ('generated','published','revoked')", name="valid_compliance_export_status"
        ),
        Index("ix_compliance_export_packages_org_workspace", "organization_id", "workspace_id"),
    )


__all__ = [
    "AIAccessEdge",
    "AIInteractionReceipt",
    "AIToolManifest",
    "AgentEvaluationRun",
    "AgentEvaluationSuite",
    "AgentRunAssurance",
    "ComplianceControlInheritance",
    "ComplianceEvidenceRequest",
    "ComplianceExportPackage",
    "DataSecurityAssessment",
    "EnforcementTransaction",
    "RiskSimulationTrial",
    "ThreatResponseAction",
    "ValidationRecipe",
]
