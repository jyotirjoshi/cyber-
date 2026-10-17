"""Tenant-owned canonical findings with lossless provider provenance."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantMixin, TimestampMixin, uuid_pk


class CanonicalFinding(Base, TenantMixin, TimestampMixin):
    __tablename__ = "canonical_findings"

    id: Mapped[uuid.UUID] = uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="RESTRICT"), nullable=False
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(1000), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="new")
    cve_ids: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    risk_factors: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    intel_evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    intel_refreshed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    risk_policy_version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    absence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    disposition_reason: Mapped[str | None] = mapped_column(Text)
    assignee_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    due_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    remediation_plan: Mapped[str | None] = mapped_column(Text)
    remediation_group: Mapped[str | None] = mapped_column(String(160))
    remediation_group_key: Mapped[str | None] = mapped_column(String(160))
    custom_fields: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    __table_args__ = (
        UniqueConstraint("organization_id", "fingerprint", name="unique_canonical_fingerprint"),
        CheckConstraint(
            "status IN ('new','open','reopened','mitigated','accepted_risk','false_positive','closed')",
            name="valid_canonical_status",
        ),
        CheckConstraint(
            "severity IN ('critical','high','medium','low','info')", name="valid_canonical_severity"
        ),
        CheckConstraint("absence_count >= 0", name="valid_canonical_absence_count"),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="valid_canonical_risk_score"),
        CheckConstraint("risk_policy_version >= 0", name="valid_canonical_risk_policy_version"),
        Index("ix_canonical_findings_org_asset_status", "organization_id", "asset_id", "status"),
        Index("ix_canonical_findings_org_status_risk", "organization_id", "status", "risk_score"),
        Index("ix_canonical_findings_org_intel_refresh", "organization_id", "intel_refreshed_at"),
        Index(
            "ix_canonical_findings_org_risk_policy_version",
            "organization_id",
            "risk_policy_version",
        ),
        Index(
            "ix_canonical_findings_org_assignee_due",
            "organization_id",
            "assignee_user_id",
            "due_at",
        ),
        Index(
            "ix_canonical_findings_org_remediation_group",
            "organization_id",
            "remediation_group_key",
        ),
    )


class FindingObservation(Base, TenantMixin, TimestampMixin):
    __tablename__ = "finding_observations"

    id: Mapped[uuid.UUID] = uuid_pk()
    canonical_finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("canonical_findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    external_id: Mapped[str] = mapped_column(String(300), nullable=False)
    cve_id: Mapped[str] = mapped_column(String(30), nullable=False, default="")
    source_record_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True))
    source_status: Mapped[str] = mapped_column(String(30), nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(2000))
    title: Mapped[str] = mapped_column(String(1000), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    missing_sync_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "provider",
            "external_id",
            "cve_id",
            name="unique_finding_observation_source",
        ),
        CheckConstraint("missing_sync_count >= 0", name="valid_observation_missing_count"),
        Index("ix_finding_observations_org_finding", "organization_id", "canonical_finding_id"),
    )


class FindingHistory(Base, TenantMixin):
    __tablename__ = "finding_history"

    id: Mapped[uuid.UUID] = uuid_pk()
    canonical_finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("canonical_findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    previous_status: Mapped[str | None] = mapped_column(String(30))
    new_status: Mapped[str] = mapped_column(String(30), nullable=False)
    reason: Mapped[str] = mapped_column(String(1000), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    occurred_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        Index(
            "ix_finding_history_org_finding_time",
            "organization_id",
            "canonical_finding_id",
            "occurred_at",
        ),
    )


class FindingCollaborationComment(Base, TenantMixin, TimestampMixin):
    """An auditable collaboration entry attached to the unified finding.

    PTaaS conversations must not be stored only in a third-party ticket: the
    tester's evidence, a customer's implementation update, and a retest request
    all describe the same canonical finding even when scanners disagree on their
    individual observations. ``visible_to_client`` is deliberately data rather
    than an authorization shortcut; a future client portal can filter it without
    exposing internal analyst notes.
    """

    __tablename__ = "finding_collaboration_comments"

    id: Mapped[uuid.UUID] = uuid_pk()
    canonical_finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("canonical_findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    author_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    kind: Mapped[str] = mapped_column(String(24), nullable=False, default="note")
    body: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_reference: Mapped[str | None] = mapped_column(String(2048))
    visible_to_client: Mapped[bool] = mapped_column(nullable=False, default=False)

    __table_args__ = (
        CheckConstraint(
            "kind IN ('note','evidence','remediation','retest','status_update')",
            name="valid_finding_collaboration_comment_kind",
        ),
        Index(
            "ix_finding_collaboration_comments_org_finding_time",
            "organization_id",
            "canonical_finding_id",
            "created_at",
        ),
    )


class RiskAcceptance(Base, TenantMixin, TimestampMixin):
    """Time-bounded, independently approved exception to remediation work."""

    __tablename__ = "risk_acceptances"

    id: Mapped[uuid.UUID] = uuid_pk()
    canonical_finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("canonical_findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    requested_by_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    approved_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','approved','rejected','revoked','expired')",
            name="valid_risk_acceptance_status",
        ),
        Index(
            "ix_risk_acceptances_org_finding_status",
            "organization_id",
            "canonical_finding_id",
            "status",
        ),
        Index("ix_risk_acceptances_org_expiry", "organization_id", "expires_at"),
    )


class RetestRequest(Base, TenantMixin, TimestampMixin):
    """Evidence-bearing retest lifecycle, optionally linked to the rescan assessment."""

    __tablename__ = "retest_requests"

    id: Mapped[uuid.UUID] = uuid_pk()
    canonical_finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("canonical_findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT")
    )
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assessments.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="requested")
    request_note: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(
            "status IN ('requested','scheduled','running','confirmed','not_confirmed','failed','cancelled')",
            name="valid_retest_request_status",
        ),
        Index(
            "ix_retest_requests_org_finding_status",
            "organization_id",
            "canonical_finding_id",
            "status",
        ),
        # A finding may have a historical record of each verification cycle, but only one
        # outstanding verification may drive a rescan.  The service also locks the finding;
        # this partial unique index makes that idempotency invariant survive concurrent
        # workers and direct operational writes.
        Index(
            "uq_retest_requests_one_active_per_finding",
            "organization_id",
            "canonical_finding_id",
            unique=True,
            postgresql_where=text("status IN ('requested','scheduled','running')"),
        ),
    )


class SlaEscalation(Base, TenantMixin, TimestampMixin):
    """One immutable escalation level for an overdue canonical finding."""

    __tablename__ = "sla_escalations"

    id: Mapped[uuid.UUID] = uuid_pk()
    canonical_finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("canonical_findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    level: Mapped[int] = mapped_column(Integer, nullable=False)
    due_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    escalated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint("level IN (1,2,3)", name="valid_sla_escalation_level"),
        UniqueConstraint(
            "organization_id",
            "canonical_finding_id",
            "level",
            name="unique_sla_escalation_level",
        ),
        Index(
            "ix_sla_escalations_org_finding_time",
            "organization_id",
            "canonical_finding_id",
            "escalated_at",
        ),
    )


class AutomationRule(Base, TenantMixin, TimestampMixin):
    """Tenant-owned declarative rule; executable behavior is never stored as code."""

    __tablename__ = "automation_rules"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    trigger: Mapped[str] = mapped_column(String(40), nullable=False)
    conditions: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    actions: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    cron_expression: Mapped[str | None] = mapped_column(String(120))
    timezone: Mapped[str] = mapped_column(String(100), nullable=False, default="UTC")
    next_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    is_enabled: Mapped[bool] = mapped_column(nullable=False, default=True)
    dry_run: Mapped[bool] = mapped_column(nullable=False, default=False)
    inbound_secret_ciphertext: Mapped[str | None] = mapped_column(Text)
    inbound_secret_rotated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        CheckConstraint(
            "trigger IN ('finding.created','finding.updated','ticket.closed','retest.confirmed','retest.cleared','sla.breached','asset.created','asset.updated','assessment.started','assessment.completed','engagement.created','engagement.status_changed','scan.failed','integration.error','webhook.received','manual')",
            name="valid_automation_rule_trigger",
        ),
        UniqueConstraint("organization_id", "name", name="unique_automation_rule_name"),
        Index(
            "ix_automation_rules_org_trigger_enabled", "organization_id", "trigger", "is_enabled"
        ),
        Index("ix_automation_rules_due", "is_enabled", "next_run_at"),
    )


class AutomationExecution(Base, TenantMixin, TimestampMixin):
    """Durable record of one evaluated automation event, including dry-runs."""

    __tablename__ = "automation_executions"

    id: Mapped[uuid.UUID] = uuid_pk()
    rule_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("automation_rules.id", ondelete="CASCADE"), nullable=False
    )

    canonical_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("canonical_findings.id", ondelete="SET NULL")
    )
    event_key: Mapped[str] = mapped_column(String(160), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    dry_run: Mapped[bool] = mapped_column(nullable=False, default=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_retry_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    result: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    __table_args__ = (
        CheckConstraint("status IN ('pending','skipped','dry_run','executed','failed')", name="valid_automation_execution_status"),
        CheckConstraint("attempts >= 0", name="valid_automation_execution_attempts"),
        UniqueConstraint("rule_id", "event_key", name="unique_automation_execution_event"),
        Index("ix_automation_executions_org_rule_time", "organization_id", "rule_id", "created_at"),
        Index("ix_automation_executions_due", "status", "next_retry_at"),
    )


class AttackSimulationCampaign(Base, TenantMixin, TimestampMixin):
    """A scheduled, authorization-bound validation exercise with declarative scenarios."""

    __tablename__ = "attack_simulation_campaigns"
    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    authorization_text: Mapped[str] = mapped_column(Text, nullable=False)
    authorization_reference: Mapped[str] = mapped_column(String(1024), nullable=False)
    authorization_expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    scenarios: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    targets: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    cron_expression: Mapped[str | None] = mapped_column(String(120))
    timezone: Mapped[str] = mapped_column(String(100), nullable=False, default="UTC")
    next_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assessments.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    last_error_code: Mapped[str | None] = mapped_column(String(80))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    __table_args__ = (
        CheckConstraint(
            "status IN ('draft','active','paused','completed','failed')",
            name="valid_attack_simulation_campaign_status",
        ),
        UniqueConstraint("organization_id", "name", name="unique_attack_simulation_campaign_name"),
        Index("ix_attack_simulation_campaigns_due", "status", "next_run_at"),
    )


class AttackSimulationRun(Base, TenantMixin, TimestampMixin):
    """Immutable campaign execution snapshot and aggregate evidence outcome."""

    __tablename__ = "attack_simulation_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("attack_simulation_campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    baseline_run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("attack_simulation_runs.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    catalog_version: Mapped[str] = mapped_column(String(40), nullable=False)
    scenarios_snapshot: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    targets_snapshot: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    triggered_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','awaiting_approval','running','completed','failed','cancelled')",
            name="valid_attack_simulation_run_status",
        ),
        UniqueConstraint("assessment_id", name="unique_attack_simulation_run_assessment"),
        Index("ix_attack_simulation_runs_org_campaign_time", "organization_id", "campaign_id", "created_at"),
        Index("ix_attack_simulation_runs_org_status", "organization_id", "status"),
    )


class AttackSimulationTechniqueRun(Base, TenantMixin, TimestampMixin):
    """One bounded technique on one target, linked to its archived scanner evidence."""

    __tablename__ = "attack_simulation_technique_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    run_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("attack_simulation_runs.id", ondelete="CASCADE"), nullable=False
    )
    approval_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("approvals.id", ondelete="SET NULL")
    )
    scanner_job_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scanner_jobs.id", ondelete="SET NULL")
    )
    technique_key: Mapped[str] = mapped_column(String(120), nullable=False)
    scenario: Mapped[str] = mapped_column(String(80), nullable=False)
    mitre_technique: Mapped[str] = mapped_column(String(32), nullable=False)
    adapter: Mapped[str] = mapped_column(String(40), nullable=False)
    target: Mapped[str] = mapped_column(String(2048), nullable=False)
    risk_class: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="queued")
    control_result: Mapped[str | None] = mapped_column(String(24))
    expected_evidence: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    evidence_artifact_ids: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    evidence_summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    error_code: Mapped[str | None] = mapped_column(String(80))
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("risk_class IN ('low','medium','high')", name="valid_bas_technique_risk"),
        CheckConstraint(
            "status IN ('queued','awaiting_approval','running','completed','failed','cancelled')",
            name="valid_bas_technique_status",
        ),
        CheckConstraint(
            "control_result IS NULL OR control_result IN ('detected','prevented','inconclusive','error')",
            name="valid_bas_control_result",
        ),
        UniqueConstraint("run_id", "scenario", "target", name="unique_bas_run_scenario_target"),
        Index("ix_bas_technique_runs_org_status", "organization_id", "status"),
        Index("ix_bas_technique_runs_job", "scanner_job_id"),
    )


class AssessmentCanonicalFinding(Base, TenantMixin):
    """Stable assessment-to-finding membership, independent of later rescans."""

    __tablename__ = "assessment_canonical_findings"

    id: Mapped[uuid.UUID] = uuid_pk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    canonical_finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("canonical_findings.id", ondelete="CASCADE"),
        nullable=False,
    )
    scanner_job_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scanner_jobs.id", ondelete="SET NULL")
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: dt.datetime.now(dt.UTC)
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "assessment_id",
            "canonical_finding_id",
            name="unique_assessment_canonical_finding",
        ),
        Index(
            "ix_assessment_canonical_findings_org_assessment",
            "organization_id",
            "assessment_id",
        ),
    )
