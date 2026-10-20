"""Unified security control-plane persistence.

The control plane stores normalized metadata, deterministic decisions, and
content digests.  It deliberately has no column for raw prompts, model output,
secrets, packet payloads, or sampled customer data.
"""

from __future__ import annotations

import datetime as dt
import uuid
from decimal import Decimal, ROUND_HALF_UP
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


class SecurityResource(Base, TenantMixin, TimestampMixin):
    __tablename__ = "security_resources"

    id: Mapped[uuid.UUID] = uuid_pk()
    resource_key: Mapped[str] = mapped_column(String(512), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    provider: Mapped[str | None] = mapped_column(String(80))
    external_id: Mapped[str | None] = mapped_column(String(512))
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL")
    )
    owner_team: Mapped[str | None] = mapped_column(String(120))
    environment: Mapped[str] = mapped_column(String(24), nullable=False, default="unknown")
    internet_exposed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    approved: Mapped[bool | None] = mapped_column(Boolean)
    posture_status: Mapped[str] = mapped_column(String(24), nullable=False, default="unknown")
    risk_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False, default=0)
    sensitivity: Mapped[str] = mapped_column(String(24), nullable=False, default="unknown")
    classifications: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    permissions: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    source_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    identity_confidence: Mapped[Decimal] = mapped_column(
        Numeric(4, 3), nullable=False, default=Decimal("0")
    )
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("organization_id", "resource_key", name="unique_security_resource_key"),
        CheckConstraint(
            "kind IN ('asset','data_store','dataset','saas_application','ai_application',"
            "'ai_model','ai_agent','mcp_server','ai_tool','identity','endpoint','browser')",
            name="valid_security_resource_kind",
        ),
        CheckConstraint(
            "environment IN ('production','staging','development','test','unknown')",
            name="valid_security_resource_environment",
        ),
        CheckConstraint(
            "posture_status IN ('unknown','healthy','at_risk','non_compliant','inactive')",
            name="valid_security_resource_posture",
        ),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="valid_security_resource_risk"),
        CheckConstraint(
            "sensitivity IN ('unknown','public','internal','confidential','restricted')",
            name="valid_security_resource_sensitivity",
        ),
        CheckConstraint("source_count >= 0", name="valid_security_resource_source_count"),
        CheckConstraint(
            "identity_confidence BETWEEN 0 AND 1",
            name="valid_security_resource_identity_confidence",
        ),
        Index("ix_security_resources_org_kind", "organization_id", "kind"),
        Index("ix_security_resources_org_posture", "organization_id", "posture_status"),
        Index("ix_security_resources_org_asset", "organization_id", "asset_id"),
    )


class SecurityResourceObservation(Base, TenantMixin, TimestampMixin):
    __tablename__ = "security_resource_observations"

    id: Mapped[uuid.UUID] = uuid_pk()
    resource_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("security_resources.id", ondelete="CASCADE"), nullable=False
    )
    integration_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("integrations.id", ondelete="SET NULL")
    )
    source_kind: Mapped[str] = mapped_column(String(80), nullable=False)
    source_key: Mapped[str] = mapped_column(String(512), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    confidence: Mapped[Decimal] = mapped_column(Numeric(4, 3), nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "source_kind",
            "source_key",
            "fingerprint",
            name="unique_security_resource_observation",
        ),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="valid_security_observation_confidence"),
        Index("ix_security_observations_org_resource", "organization_id", "resource_id"),
        Index("ix_security_observations_org_expiry", "organization_id", "expires_at"),
    )


class SecurityPolicy(Base, TenantMixin, TimestampMixin):
    __tablename__ = "security_policies"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    mode: Mapped[str] = mapped_column(String(20), nullable=False, default="recommend")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    rules: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    integration_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("integrations.id", ondelete="SET NULL")
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="unique_security_policy_name"),
        CheckConstraint(
            "kind IN ('ztna','secure_web_gateway','firewall','tls_inspection','dlp','casb','sspm',"
            "'ai_gateway','ai_guard','endpoint_isolation','browser_isolation')",
            name="valid_security_policy_kind",
        ),
        CheckConstraint("mode IN ('monitor','recommend','enforce')", name="valid_security_policy_mode"),
        CheckConstraint("status IN ('draft','active','disabled')", name="valid_security_policy_status"),
        CheckConstraint("version > 0", name="valid_security_policy_version"),
        Index("ix_security_policies_org_kind", "organization_id", "kind"),
        Index("ix_security_policies_org_status", "organization_id", "status"),
    )


class SecurityEvent(Base, TenantMixin, TimestampMixin):
    __tablename__ = "security_events"

    id: Mapped[uuid.UUID] = uuid_pk()
    event_key: Mapped[str] = mapped_column(String(512), nullable=False)
    category: Mapped[str] = mapped_column(String(30), nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(80), nullable=False)
    occurred_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    content_digest: Mapped[str | None] = mapped_column(String(64))
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL")
    )
    resource_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("security_resources.id", ondelete="SET NULL")
    )
    identity_ref: Mapped[str | None] = mapped_column(String(512))
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        UniqueConstraint("organization_id", "event_key", name="unique_security_event_key"),
        CheckConstraint(
            "category IN ('experience','incident','identity','deception','access','dlp',"
            "'ai_gateway','endpoint','browser')",
            name="valid_security_event_category",
        ),
        CheckConstraint(
            "severity IN ('info','low','medium','high','critical')",
            name="valid_security_event_severity",
        ),
        Index("ix_security_events_org_category_time", "organization_id", "category", "occurred_at"),
        Index("ix_security_events_org_asset", "organization_id", "asset_id"),
    )


class SecurityPolicyEvaluation(Base, TenantMixin, TimestampMixin):
    __tablename__ = "security_policy_evaluations"

    id: Mapped[uuid.UUID] = uuid_pk()
    policy_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("security_policies.id", ondelete="CASCADE"), nullable=False
    )
    resource_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("security_resources.id", ondelete="SET NULL")
    )
    event_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("security_events.id", ondelete="SET NULL")
    )
    decision: Mapped[str] = mapped_column(String(24), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False, default=0)
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    content_digest: Mapped[str | None] = mapped_column(String(64))
    evaluated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "decision IN ('allow','block','redact','require_approval','recommend','not_applicable')",
            name="valid_security_evaluation_decision",
        ),
        CheckConstraint(
            "severity IN ('info','low','medium','high','critical')",
            name="valid_security_evaluation_severity",
        ),
        CheckConstraint("score BETWEEN 0 AND 100", name="valid_security_evaluation_score"),
        Index("ix_security_evaluations_org_policy", "organization_id", "policy_id"),
        Index("ix_security_evaluations_org_time", "organization_id", "evaluated_at"),
    )


class SecurityRecommendation(Base, TenantMixin, TimestampMixin):
    __tablename__ = "security_recommendations"

    id: Mapped[uuid.UUID] = uuid_pk()
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("security_policies.id", ondelete="SET NULL")
    )
    resource_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("security_resources.id", ondelete="SET NULL")
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL")
    )
    integration_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("integrations.id", ondelete="SET NULL")
    )
    domain: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="proposed")
    current_state: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    desired_state: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    provider_receipt: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    applied_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    applied_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "idempotency_key", name="unique_security_recommendation_key"
        ),
        CheckConstraint(
            "domain IN ('ztna','secure_web_gateway','firewall','data_security','ai_security',"
            "'endpoint','browser','soc')",
            name="valid_security_recommendation_domain",
        ),
        CheckConstraint(
            "severity IN ('info','low','medium','high','critical')",
            name="valid_security_recommendation_severity",
        ),
        CheckConstraint(
            "status IN ('proposed','approved','applying','applied','rejected','failed','superseded')",
            name="valid_security_recommendation_status",
        ),
        Index("ix_security_recommendations_org_status", "organization_id", "status"),
        Index("ix_security_recommendations_org_domain", "organization_id", "domain"),
    )


class SecurityThreatStory(Base, TenantMixin, TimestampMixin):
    __tablename__ = "security_threat_stories"

    id: Mapped[uuid.UUID] = uuid_pk()
    correlation_key: Mapped[str] = mapped_column(String(256), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[Decimal] = mapped_column(Numeric(4, 3), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    event_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    asset_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    finding_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    identity_refs: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    timeline: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    assigned_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    resolution: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "correlation_key", name="unique_security_threat_story_key"
        ),
        CheckConstraint(
            "status IN ('open','investigating','contained','resolved','dismissed')",
            name="valid_security_threat_story_status",
        ),
        CheckConstraint(
            "severity IN ('info','low','medium','high','critical')",
            name="valid_security_threat_story_severity",
        ),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="valid_security_threat_story_confidence"),
        Index("ix_security_stories_org_status", "organization_id", "status"),
        Index("ix_security_stories_org_last_seen", "organization_id", "last_seen_at"),
    )


class SecurityCanary(Base, TenantMixin, TimestampMixin):
    __tablename__ = "security_canaries"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(30), nullable=False)
    token_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    placement: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    last_triggered_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="unique_security_canary_name"),
        UniqueConstraint(
            "organization_id", "token_digest", name="unique_security_canary_digest"
        ),
        CheckConstraint(
            "kind IN ('credential','dns','http','file','cloud_resource','identity')",
            name="valid_security_canary_kind",
        ),
        CheckConstraint(
            "status IN ('active','disabled','triggered','retired')",
            name="valid_security_canary_status",
        ),
        Index("ix_security_canaries_org_status", "organization_id", "status"),
    )


class SecurityCanaryInteraction(Base, TenantMixin, TimestampMixin):
    __tablename__ = "security_canary_interactions"

    id: Mapped[uuid.UUID] = uuid_pk()
    canary_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("security_canaries.id", ondelete="CASCADE"), nullable=False
    )
    event_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("security_events.id", ondelete="SET NULL")
    )
    interaction_key: Mapped[str] = mapped_column(String(256), nullable=False)
    occurred_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_ip_digest: Mapped[str | None] = mapped_column(String(64))
    identity_ref: Mapped[str | None] = mapped_column(String(512))
    protocol: Mapped[str | None] = mapped_column(String(40))
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="high")
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "interaction_key", name="unique_security_canary_interaction_key"
        ),
        CheckConstraint(
            "severity IN ('info','low','medium','high','critical')",
            name="valid_security_canary_interaction_severity",
        ),
        Index("ix_security_canary_interactions_org_canary", "organization_id", "canary_id"),
        Index("ix_security_canary_interactions_org_time", "organization_id", "occurred_at"),
    )


class SecurityRiskSimulation(Base, TenantMixin, TimestampMixin):
    __tablename__ = "security_risk_simulations"

    id: Mapped[uuid.UUID] = uuid_pk()
    business_service_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("business_services.id", ondelete="SET NULL")
    )
    scenario_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("business_risk_scenarios.id", ondelete="SET NULL")
    )
    name: Mapped[str] = mapped_column(String(240), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    annual_probability: Mapped[Decimal] = mapped_column(Numeric(6, 5), nullable=False)
    loss_min: Mapped[Decimal] = mapped_column(Numeric(16, 2), nullable=False)
    loss_likely: Mapped[Decimal] = mapped_column(Numeric(16, 2), nullable=False)
    loss_max: Mapped[Decimal] = mapped_column(Numeric(16, 2), nullable=False)
    control_effectiveness: Mapped[Decimal] = mapped_column(Numeric(6, 5), nullable=False)
    acceptance_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="unreviewed"
    )
    assumptions: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    narrative: Mapped[str | None] = mapped_column(Text)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        CheckConstraint("annual_probability BETWEEN 0 AND 1", name="valid_security_risk_probability"),
        CheckConstraint(
            "control_effectiveness BETWEEN 0 AND 1",
            name="valid_security_risk_control_effectiveness",
        ),
        CheckConstraint(
            "loss_min >= 0 AND loss_likely >= loss_min AND loss_max >= loss_likely",
            name="valid_security_risk_loss_range",
        ),
        CheckConstraint(
            "status IN ('draft','completed','archived')", name="valid_security_risk_status"
        ),
        CheckConstraint(
            "acceptance_status IN ('unreviewed','accepted','mitigating','rejected','expired')",
            name="valid_security_risk_acceptance_status",
        ),
        Index("ix_security_risk_org_service", "organization_id", "business_service_id"),
        Index("ix_security_risk_org_status", "organization_id", "status"),
    )

    @staticmethod
    def _money(value: Decimal) -> Decimal:
        return value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    @property
    def expected_loss(self) -> Decimal:
        return self._money((self.loss_min + self.loss_likely + self.loss_max) / Decimal("3"))

    @property
    def inherent_annual_loss(self) -> Decimal:
        return self._money(self.annual_probability * self.expected_loss)

    @property
    def residual_annual_loss(self) -> Decimal:
        return self._money(self.inherent_annual_loss * (Decimal("1") - self.control_effectiveness))


__all__ = [
    "SecurityCanary",
    "SecurityCanaryInteraction",
    "SecurityEvent",
    "SecurityPolicy",
    "SecurityPolicyEvaluation",
    "SecurityRecommendation",
    "SecurityResource",
    "SecurityResourceObservation",
    "SecurityRiskSimulation",
    "SecurityThreatStory",
]
