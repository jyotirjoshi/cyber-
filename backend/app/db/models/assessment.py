"""Assessments, their targets, the authorization attestation and approvals.

FR-005 is the reason :class:`AuthorizationRecord` is a separate table rather than a
boolean on the assessment: the attestation is evidence.  It records who claimed
authority over which target, when, from where, and under what wording -- and it is
immutable once written, so an assessment can always be defended after the fact.
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
    ApprovalDecision,
    ApprovalKind,
    AssessmentDepth,
    AssessmentStage,
    AssessmentStatus,
    Scope,
)

if TYPE_CHECKING:
    from app.db.models.agent import AgentRun, AgentSession
    from app.db.models.asset import Asset
    from app.db.models.finding import Finding
    from app.db.models.identity import Organization, User
    from app.db.models.report import Report
    from app.db.models.scanner import ScannerJob


class Assessment(Base, TenantMixin, TimestampMixin):
    __tablename__ = "assessments"

    id: Mapped[uuid.UUID] = uuid_pk()
    #: Short human-facing number, unique per organization: "Assessment #928".
    reference: Mapped[int] = mapped_column(Integer, nullable=False)

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    scope: Mapped[str] = mapped_column(String(40), nullable=False, default=Scope.EXTERNAL.value)
    depth: Mapped[str] = mapped_column(
        String(40), nullable=False, default=AssessmentDepth.STANDARD.value
    )

    status: Mapped[str] = mapped_column(
        String(40), nullable=False, default=AssessmentStatus.CREATED.value, index=True
    )
    current_stage: Mapped[str] = mapped_column(
        String(60), nullable=False, default=AssessmentStage.QUEUED.value
    )
    #: 0-100, derived from completed stages. Stored so a reconnecting client sees the
    #: right progress bar without replaying the whole event stream.
    progress_percent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    #: Populated when status is FAILED. User-safe text only (SEC-002).
    failure_reason: Mapped[str | None] = mapped_column(Text)
    failure_category: Mapped[str | None] = mapped_column(String(40))
    #: Stages that completed without a non-essential dependency, e.g. ZAP failed or
    #: MISP was unreachable. Surfaced in the report appendix so a reader knows what
    #: was *not* covered rather than assuming full coverage.
    degradations: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)

    #: The plan the agent committed to (FR-036), as an ordered list of steps.
    plan: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    #: Structured interpretation of the original request (FR-004).
    request_interpretation: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)

    #: Denormalized counters. DefectDojo remains the source of truth (FR-016); these
    #: exist so the dashboard and list views do not fan out to it on every render.
    findings_total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_critical: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_high: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_medium: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_low: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_info: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    assets_discovered: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    assets_in_scope: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    #: DefectDojo linkage (FR-016). Only ids are stored; no schema duplication.
    defectdojo_product_id: Mapped[int | None] = mapped_column(Integer)
    defectdojo_engagement_id: Mapped[int | None] = mapped_column(Integer)

    organization: Mapped[Organization] = relationship(back_populates="assessments", lazy=LAZY)
    created_by: Mapped[User | None] = relationship(lazy=LAZY)
    targets: Mapped[list[AssessmentTarget]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan", lazy=LAZY
    )
    authorizations: Mapped[list[AuthorizationRecord]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan", lazy=LAZY
    )
    approvals: Mapped[list[Approval]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan", lazy=LAZY
    )
    #: Assets and findings are *not* delete-orphan: both are organization-level records
    #: keyed for reuse across assessments (see the SET NULL foreign keys on those
    #: tables). ``passive_deletes`` hands the NULL-ing to Postgres instead of having
    #: SQLAlchemy load every child row just to detach it.
    assets: Mapped[list[Asset]] = relationship(
        back_populates="assessment", lazy=LAZY, passive_deletes=True
    )
    scanner_jobs: Mapped[list[ScannerJob]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan", lazy=LAZY
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="assessment", lazy=LAZY, passive_deletes=True
    )
    reports: Mapped[list[Report]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan", lazy=LAZY
    )
    agent_runs: Mapped[list[AgentRun]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan", lazy=LAZY
    )
    agent_session_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_sessions.id", ondelete="SET NULL")
    )
    agent_session: Mapped[AgentSession | None] = relationship(
        back_populates="assessments", lazy=LAZY, foreign_keys=[agent_session_id]
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "reference", name="unique_reference"),
        CheckConstraint("progress_percent BETWEEN 0 AND 100", name="progress_bounds"),
        # The FR-007 state machine's vocabulary, pinned at the storage layer.
        #
        # ``ALLOWED_TRANSITIONS`` is only consulted *on a transition*, so a bad value
        # written directly -- a migration backfill, a fixture, a service that formats the
        # status itself instead of using the enum -- raises nothing at write time.  The
        # damaging case is not a garbage string but a case-wrong one: ``'scanning'`` for
        # ``'SCANNING'`` leaves the row readable and plausible while making it invisible
        # to every ``status == 'SCANNING'`` query, including the one the cancellation
        # path uses to find running work (FR-039).
        CheckConstraint(
            "status IN ('CREATED','PLANNING','DISCOVERY','WAITING_FOR_APPROVAL','SCANNING',"
            "'ANALYZING','REMEDIATING','COMPLETED','FAILED','CANCELLING','CANCELLED')",
            name="valid_assessment_status",
        ),
        CheckConstraint(
            "current_stage IN ('queued','understanding_request','validating_target',"
            "'checking_authorization','planning','reconnaissance','asset_analysis',"
            "'awaiting_approval','scanning_nmap','scanning_nuclei','scanning_zap',"
            "'importing_findings','threat_intelligence','ai_analysis','risk_prioritization',"
            "'remediation','creating_actions','report','done')",
            name="valid_assessment_stage",
        ),
        CheckConstraint(
            "scope IN ('external','internal','application','code')", name="valid_scope"
        ),
        CheckConstraint("depth IN ('passive','standard','deep')", name="valid_depth"),
        Index("ix_assessments_organization_id_status", "organization_id", "status"),
        Index("ix_assessments_organization_id_created_at", "organization_id", "created_at"),
    )

    @property
    def status_enum(self) -> AssessmentStatus:
        return AssessmentStatus(self.status)

    @property
    def duration_seconds(self) -> int | None:
        if not self.started_at:
            return None
        end = self.completed_at or dt.datetime.now(dt.UTC)
        return int((end - self.started_at).total_seconds())


class AssessmentTarget(Base, TenantMixin, TimestampMixin):
    """One validated target. An assessment can have several (a domain plus a CIDR).

    Tenant-scoped even though it is reachable only through its assessment: a target row
    is the customer's hostnames and CIDRs, which SEC-003 names directly. Without the
    mixin the only way to load one is a raw ``select(...).where(assessment_id == ...)``,
    and that filter is safe only if the caller verified the assessment's owner first --
    the kind of ordering requirement that holds until the one call site that forgets.
    With the mixin, :func:`~app.db.repository.tenant_select` applies and the guarantee
    is structural, matching its sibling :class:`AuthorizationRecord`.
    """

    __tablename__ = "assessment_targets"

    id: Mapped[uuid.UUID] = uuid_pk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    #: Exactly as the user typed it, for the audit trail.
    raw_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    #: Post-validation canonical form -- the only value handed to a scanner.
    canonical_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    target_type: Mapped[str] = mapped_column(String(40), nullable=False)
    host: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    port: Mapped[int | None] = mapped_column(Integer)
    host_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    target_metadata: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)

    assessment: Mapped[Assessment] = relationship(back_populates="targets", lazy=LAZY)

    __table_args__ = (UniqueConstraint("assessment_id", "canonical_value", name="unique_target"),)


class AuthorizationRecord(Base, TenantMixin, TimestampMixin):
    """FR-005 attestation. Append-only evidence, never updated or deleted."""

    __tablename__ = "authorization_records"

    id: Mapped[uuid.UUID] = uuid_pk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    target: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    #: The exact wording the user agreed to, stored verbatim. If the attestation text
    #: is ever reworded, historical records still show what was actually accepted.
    attestation_text: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str] = mapped_column(String(40), nullable=False, default="explicit_ui")
    source_ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    confirmed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    #: Optional externally supplied evidence, e.g. a signed scope document URL.
    evidence_reference: Mapped[str | None] = mapped_column(String(1024))

    assessment: Mapped[Assessment] = relationship(back_populates="authorizations", lazy=LAZY)

    __table_args__ = (
        Index("ix_authorization_records_organization_id_target", "organization_id", "target"),
    )


class Approval(Base, TenantMixin, TimestampMixin):
    """FR-011 human-in-the-loop gate.

    The agent cannot proceed past a gated node without a row here whose decision is
    terminal and whose ``resolved_by_id`` is a real user.  ``requested_payload``
    holds what the agent proposed; ``approved_payload`` holds what the human
    actually authorized -- they differ whenever the scope was customized, and the
    scanner layer is driven by ``approved_payload`` alone.
    """

    __tablename__ = "approvals"

    id: Mapped[uuid.UUID] = uuid_pk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    agent_run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_runs.id", ondelete="SET NULL")
    )
    kind: Mapped[str] = mapped_column(
        String(40), nullable=False, default=ApprovalKind.SCAN_SCOPE.value
    )
    decision: Mapped[str] = mapped_column(
        String(40), nullable=False, default=ApprovalDecision.PENDING.value, index=True
    )

    #: Human-readable summary rendered in chat and in Slack.
    prompt: Mapped[str] = mapped_column(Text, nullable=False)
    #: The agent's reasoning for the recommendation (FR-010: "must explain why").
    rationale: Mapped[str | None] = mapped_column(Text)
    requested_payload: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)
    approved_payload: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)
    #: Risk level of the gated operation, from the tool contract (FR-034).
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")

    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    resolution_note: Mapped[str | None] = mapped_column(Text)

    assessment: Mapped[Assessment] = relationship(back_populates="approvals", lazy=LAZY)
    resolved_by: Mapped[User | None] = relationship(lazy=LAZY, foreign_keys=[resolved_by_id])

    __table_args__ = (
        CheckConstraint(
            "decision IN ('pending','approved','approved_all','customized','rejected','expired')",
            name="valid_decision",
        ),
        CheckConstraint(
            "kind IN ('scan_scope','high_risk_tool','remediation_apply','ticket_bulk_create')",
            name="valid_approval_kind",
        ),
        # Deliberately narrower than ``RiskLevel``: ``forbidden`` is excluded.  A
        # forbidden tool is registered but never callable (FR-034), so there is no
        # operation for which an approval row could legitimately carry that level --
        # and if one existed, approving it would be a path around the guardrail rather
        # than through it.  Excluding the value here means the bypass cannot be
        # represented, let alone granted (section 56, "never bypass approval").
        CheckConstraint("risk_level IN ('low','medium','high')", name="valid_approval_risk"),
        # An approval is only usable as authority if a human resolved it.
        CheckConstraint(
            "decision = 'pending' OR decision = 'expired' OR resolved_by_id IS NOT NULL",
            name="resolved_requires_actor",
        ),
        Index("ix_approvals_assessment_id_decision", "assessment_id", "decision"),
    )

    @property
    def is_granted(self) -> bool:
        return self.decision in (
            ApprovalDecision.APPROVED.value,
            ApprovalDecision.APPROVED_ALL.value,
            ApprovalDecision.CUSTOMIZED.value,
        )


__all__ = ["Approval", "Assessment", "AssessmentTarget", "AuthorizationRecord"]
