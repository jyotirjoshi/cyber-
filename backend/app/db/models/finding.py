"""Findings, enrichment, remediation and ticket links (FR-016 .. FR-023).

DefectDojo owns vulnerability management: parsing, deduplication, status workflow
and history all live there (section 65, "do not build").  This table is a *projection*
keyed by :attr:`Finding.defectdojo_finding_id` -- it carries only what Cynux adds on
top: the intelligence enrichment, the AI analysis, the computed priority and the
generated remediation.  Nothing here is authoritative about the vulnerability itself,
which is why every field that mirrors DefectDojo is marked as a cached copy.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
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
from app.db.enums import EnrichmentStatus, FindingStatus, Priority, Severity

if TYPE_CHECKING:
    from app.db.models.assessment import Assessment
    from app.db.models.asset import Asset
    from app.db.models.identity import User


class Finding(Base, TenantMixin, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = uuid_pk()
    #: The assessment that surfaced it. ``SET NULL`` because a finding is keyed by its
    #: DefectDojo id per organization: a re-scan updates this row rather than inserting
    #: a new one, so the row can outlive the assessment that first reported it.
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assessments.id", ondelete="SET NULL")
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL")
    )
    scanner_job_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scanner_jobs.id", ondelete="SET NULL")
    )

    # --- The only authoritative identifier (FR-016 / FR-017) ---------------
    #: Primary key in DefectDojo. Every read of finding detail, status or history
    #: goes back to DefectDojo using this id.
    defectdojo_finding_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    defectdojo_test_id: Mapped[int | None] = mapped_column(Integer)

    # --- Cached copies, refreshed on sync; never edited locally -------------
    title: Mapped[str] = mapped_column(String(1000), nullable=False)
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, default=Severity.INFO.value, index=True
    )
    #: The scanner's original severity spelling, kept because our five-level mapping
    #: is lossy and a reviewer occasionally needs the source label.
    severity_raw: Mapped[str | None] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default=FindingStatus.ACTIVE.value, index=True
    )
    scanner: Mapped[str | None] = mapped_column(String(40), index=True)
    #: Where the finding was observed, as DefectDojo reports it.
    endpoint: Mapped[str | None] = mapped_column(String(1000))
    component: Mapped[str | None] = mapped_column(String(300))
    component_version: Mapped[str | None] = mapped_column(String(80))
    cve_ids: Mapped[list[str]] = mapped_column(default=list, nullable=False)
    cwe: Mapped[int | None] = mapped_column(Integer)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(200))
    #: True when DefectDojo has a verified duplicate/false-positive judgement. Used to
    #: keep the agent from analyzing noise.
    is_duplicate: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    synced_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    # --- What Cynux adds (FR-021 .. FR-023) --------------------------------
    #: Computed priority, distinct from severity: it folds in exposure, exploitation
    #: evidence and asset criticality.
    priority: Mapped[str | None] = mapped_column(String(4), index=True)
    #: 0-100 composite. The inputs are recorded in ``risk_factors`` so the number is
    #: reproducible and defensible rather than an opaque model output.
    risk_score: Mapped[float | None] = mapped_column(Float)
    risk_factors: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)
    #: Plain-language explanation for a developer audience (FR-021).
    ai_explanation: Mapped[str | None] = mapped_column(Text)
    ai_business_impact: Mapped[str | None] = mapped_column(Text)
    ai_attack_scenario: Mapped[str | None] = mapped_column(Text)
    #: Every claim the model made, each paired with the source that supports it.
    #: The hallucination guard (FR-024) rejects an analysis whose claims are not all
    #: represented here, so this doubles as the evidence trail shown in the UI.
    ai_evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    ai_model: Mapped[str | None] = mapped_column(String(120))
    ai_analyzed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    #: Set when analysis was skipped -- below the severity floor, or budget exhausted.
    ai_skipped_reason: Mapped[str | None] = mapped_column(String(200))

    #: Snapshot of the asset's criticality at analysis time. Copied deliberately: if
    #: someone retags the asset later, the priority stays explainable against the
    #: context that produced it.
    asset_criticality: Mapped[str | None] = mapped_column(String(20))

    first_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    assessment: Mapped[Assessment | None] = relationship(back_populates="findings", lazy=LAZY)
    asset: Mapped[Asset | None] = relationship(back_populates="findings", lazy=LAZY)
    enrichment: Mapped[FindingEnrichment | None] = relationship(
        back_populates="finding", cascade="all, delete-orphan", uselist=False, lazy=LAZY
    )
    remediations: Mapped[list[Remediation]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", lazy=LAZY
    )
    tickets: Mapped[list[TicketLink]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", lazy=LAZY
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "defectdojo_finding_id", name="unique_defectdojo_finding"
        ),
        CheckConstraint(
            "severity IN ('critical','high','medium','low','info')", name="valid_severity"
        ),
        # Mirrors DefectDojo's workflow states. A value outside this set would slip past
        # the "is this still open?" filters that drive the dashboard counters and the
        # report's executive summary, understating the outstanding risk.
        CheckConstraint(
            "status IN ('active','verified','false_positive','risk_accepted','out_of_scope',"
            "'mitigated','duplicate')",
            name="valid_finding_status",
        ),
        CheckConstraint(
            "priority IS NULL OR priority IN ('P1','P2','P3','P4','P5')", name="valid_priority"
        ),
        # Nullable: the snapshot is only taken at analysis time, so an un-analyzed
        # finding legitimately has none.
        CheckConstraint(
            "asset_criticality IS NULL OR asset_criticality IN ('critical','high','normal',"
            "'low','unknown')",
            name="valid_asset_criticality",
        ),
        CheckConstraint(
            "risk_score IS NULL OR risk_score BETWEEN 0 AND 100", name="finding_risk_bounds"
        ),
        CheckConstraint("cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10", name="valid_cvss"),
        Index("ix_findings_organization_id_severity", "organization_id", "severity"),
        Index("ix_findings_organization_id_priority", "organization_id", "priority"),
        Index("ix_findings_assessment_id_severity", "assessment_id", "severity"),
    )

    @property
    def severity_enum(self) -> Severity:
        return Severity(self.severity)

    @property
    def priority_enum(self) -> Priority | None:
        return Priority(self.priority) if self.priority else None

    @property
    def primary_cve(self) -> str | None:
        return self.cve_ids[0] if self.cve_ids else None


class FindingEnrichment(Base, TenantMixin, TimestampMixin):
    """FR-019 / FR-020 threat intelligence attached to a finding.

    ``status`` distinguishes "we checked and it is not in KEV" from "we could not
    reach KEV".  FR-020 forbids collapsing those two into a silent false, because the
    prioritization step would then treat an outage as evidence of low risk.
    """

    __tablename__ = "finding_enrichments"

    id: Mapped[uuid.UUID] = uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default=EnrichmentStatus.PENDING.value
    )

    # --- NVD ---------------------------------------------------------------
    nvd_status: Mapped[str] = mapped_column(
        String(30), nullable=False, default=EnrichmentStatus.PENDING.value
    )
    nvd_published_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    nvd_last_modified_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    nvd_description: Mapped[str | None] = mapped_column(Text)
    nvd_cvss_v31_score: Mapped[float | None] = mapped_column(Float)
    nvd_cvss_v31_vector: Mapped[str | None] = mapped_column(String(200))
    nvd_cwe_ids: Mapped[list[str]] = mapped_column(default=list, nullable=False)
    nvd_references: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, nullable=False
    )

    # --- CISA KEV ----------------------------------------------------------
    kev_status: Mapped[str] = mapped_column(
        String(30), nullable=False, default=EnrichmentStatus.PENDING.value
    )
    #: Tri-state on purpose: True/False are findings, NULL means unknown.
    in_kev: Mapped[bool | None] = mapped_column(Boolean)
    kev_date_added: Mapped[dt.date | None] = mapped_column(Date)
    kev_due_date: Mapped[dt.date | None] = mapped_column(Date)
    kev_ransomware_use: Mapped[str | None] = mapped_column(String(40))
    kev_required_action: Mapped[str | None] = mapped_column(Text)

    # --- EPSS --------------------------------------------------------------
    epss_status: Mapped[str] = mapped_column(
        String(30), nullable=False, default=EnrichmentStatus.PENDING.value
    )
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)

    # --- MISP --------------------------------------------------------------
    misp_status: Mapped[str] = mapped_column(
        String(30), nullable=False, default=EnrichmentStatus.PENDING.value
    )
    misp_event_count: Mapped[int | None] = mapped_column(Integer)
    misp_attributes: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, nullable=False
    )

    #: Per-provider failure notes, e.g. {"misp": "circuit open"}. Rendered in the
    #: report appendix so a reader knows which intelligence was unavailable.
    provider_errors: Mapped[dict[str, Any]] = mapped_column(default=dict, nullable=False)
    enriched_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    finding: Mapped[Finding] = relationship(back_populates="enrichment", lazy=LAZY)

    __table_args__ = (
        UniqueConstraint("finding_id", name="unique_finding_enrichment"),
        # One constraint per provider rather than a single combined one.  These columns
        # carry the FR-020 distinction between "checked, negative" and "could not
        # reach" -- the whole reason an outage is not scored as low risk -- so when a
        # write is rejected the error should name the provider whose status was wrong,
        # not a constraint spanning five of them.
        CheckConstraint(
            "status IN ('pending','complete','partial','unavailable','not_applicable')",
            name="valid_enrichment_status",
        ),
        CheckConstraint(
            "nvd_status IN ('pending','complete','partial','unavailable','not_applicable')",
            name="valid_nvd_status",
        ),
        CheckConstraint(
            "kev_status IN ('pending','complete','partial','unavailable','not_applicable')",
            name="valid_kev_status",
        ),
        CheckConstraint(
            "epss_status IN ('pending','complete','partial','unavailable','not_applicable')",
            name="valid_epss_status",
        ),
        CheckConstraint(
            "misp_status IN ('pending','complete','partial','unavailable','not_applicable')",
            name="valid_misp_status",
        ),
        CheckConstraint(
            "epss_score IS NULL OR epss_score BETWEEN 0 AND 1", name="valid_epss_score"
        ),
    )

    @property
    def status_enum(self) -> EnrichmentStatus:
        return EnrichmentStatus(self.status)

    @property
    def is_actively_exploited(self) -> bool:
        """True only on positive evidence. An unknown KEV state is not exploitation."""
        return self.in_kev is True


class Remediation(Base, TenantMixin, TimestampMixin):
    """FR-025 / FR-026 generated fix guidance.

    Kept in its own table because a finding can have several candidate remediations
    (upgrade, config change, compensating control) and because a code patch needs a
    review state of its own before anyone applies it.
    """

    __tablename__ = "remediations"

    id: Mapped[uuid.UUID] = uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    approach: Mapped[str] = mapped_column(String(60), nullable=False, default="upgrade")
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    #: Ordered, concrete steps. The prompt forbids "consult your vendor" filler.
    steps: Mapped[list[str]] = mapped_column(default=list, nullable=False)
    #: Suggested patch or config diff (FR-026). Advisory only -- Cynux never applies it.
    code_patch: Mapped[str | None] = mapped_column(Text)
    patch_language: Mapped[str | None] = mapped_column(String(40))
    configuration_change: Mapped[str | None] = mapped_column(Text)
    verification: Mapped[str | None] = mapped_column(Text)
    #: What could break. Populated because a remediation without a risk note gets
    #: applied blindly.
    side_effects: Mapped[str | None] = mapped_column(Text)
    effort: Mapped[str | None] = mapped_column(String(30))
    #: Sources that back the recommendation -- vendor advisory, NVD reference, Dify
    #: knowledge chunk. An empty list means the guidance is unverified and the UI
    #: labels it as such (FR-024).
    references: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)

    ai_model: Mapped[str | None] = mapped_column(String(120))
    generated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    #: Set when a human vouched for the guidance.
    reviewed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    reviewed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    finding: Mapped[Finding] = relationship(back_populates="remediations", lazy=LAZY)
    reviewed_by: Mapped[User | None] = relationship(lazy=LAZY)

    __table_args__ = (
        Index("ix_remediations_organization_id_finding_id", "organization_id", "finding_id"),
    )


class TicketLink(Base, TenantMixin, TimestampMixin):
    """FR-027 Jira issue created for a finding.

    The unique constraint on ``(finding_id, provider)`` is what stops a re-run from
    filing a second ticket for the same finding -- duplicate tickets are the fastest
    way to lose a development team's trust in an automated scanner.
    """

    __tablename__ = "ticket_links"

    id: Mapped[uuid.UUID] = uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(30), nullable=False, default="jira")
    external_key: Mapped[str] = mapped_column(String(80), nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(80))
    url: Mapped[str | None] = mapped_column(String(1000))
    project_key: Mapped[str | None] = mapped_column(String(40))
    issue_type: Mapped[str | None] = mapped_column(String(60))
    #: Last known state in the tracker; refreshed on demand, not polled.
    external_status: Mapped[str | None] = mapped_column(String(80))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    #: True when the agent filed it rather than a person clicking the button.
    created_by_agent: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    finding: Mapped[Finding] = relationship(back_populates="tickets", lazy=LAZY)

    __table_args__ = (
        UniqueConstraint("finding_id", "provider", name="unique_ticket_per_finding"),
        # Narrower than ``IntegrationKind``: only the three issue trackers can hold a
        # ticket. The value is half of the unique constraint above, so a variant
        # spelling ("Jira") is a second row for the same finding -- exactly the
        # duplicate this table exists to prevent.
        CheckConstraint("provider IN ('jira','github','gitlab')", name="valid_ticket_provider"),
        Index("ix_ticket_links_organization_id_provider", "organization_id", "provider"),
    )


__all__ = ["Finding", "FindingEnrichment", "Remediation", "TicketLink"]
