"""Finding, enrichment, remediation and ticket wire types.

(FR-016, FR-017, FR-019, FR-020, FR-022, FR-023, FR-024, FR-025, FR-026, FR-027.)

``in_kev`` is ``bool | None`` and the ``None`` is serialized as JSON ``null``, never
coerced to ``false``.  FR-020 requires that a CISA KEV outage degrade gracefully, and
"we could not reach KEV" is a materially different statement from "this CVE is not
actively exploited" -- collapsing them would let an outage silently de-prioritize a
finding that belongs at the top of the queue.  The same reasoning applies to every
``*_status`` field on :class:`EnrichmentOut`: each provider reports its own outcome so a
reader can tell partial data from absent data.

``ai_evidence`` travels with every AI-authored field for the same reason (FR-024).  The
agent is not permitted to assert a CVE, a CVSS score, exploitation evidence or a MITRE
mapping that it cannot attribute to a retrieved source; the citations are how a reviewer
checks that, so they are part of the wire format rather than an internal detail.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.db.enums import (
    Criticality,
    EnrichmentStatus,
    FindingStatus,
    Priority,
    ScannerName,
    Severity,
)
from app.schemas.asset import AssetOut


class EnrichmentOut(BaseModel):
    """Threat-intelligence overlay for a finding (FR-019, FR-020)."""

    model_config = ConfigDict(from_attributes=True)

    #: Roll-up across providers: ``complete`` only when every applicable provider
    #: answered.
    status: EnrichmentStatus

    nvd_status: EnrichmentStatus
    nvd_published_at: dt.datetime | None = None
    nvd_last_modified_at: dt.datetime | None = None
    nvd_description: str | None = None
    nvd_cvss_v31_score: float | None = None
    nvd_cvss_v31_vector: str | None = None
    nvd_cwe_ids: list[str] = Field(default_factory=list)
    nvd_references: list[dict[str, Any]] = Field(default_factory=list)

    kev_status: EnrichmentStatus
    #: ``None`` means "not determined" -- see the module docstring. Never coerce.
    in_kev: bool | None = None
    kev_date_added: dt.date | None = None
    kev_due_date: dt.date | None = None
    kev_ransomware_use: str | None = None
    kev_required_action: str | None = None

    epss_status: EnrichmentStatus
    epss_score: float | None = None
    epss_percentile: float | None = None

    misp_status: EnrichmentStatus
    misp_event_count: int | None = None
    misp_attributes: list[dict[str, Any]] = Field(default_factory=list)

    #: ``{provider: user_safe_reason}``. Never carries a URL with credentials in it
    #: (SEC-002); the raw provider response stays in the logs.
    provider_errors: dict[str, str] = Field(default_factory=dict)
    enriched_at: dt.datetime | None = None


class RemediationOut(BaseModel):
    """A generated fix (FR-025). ``code_patch`` is a suggestion, never applied
    automatically -- FR-034 forbids autonomous production change in the MVP."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    approach: str
    summary: str
    steps: list[str] = Field(default_factory=list)
    code_patch: str | None = None
    patch_language: str | None = None
    configuration_change: str | None = None
    #: How to confirm the fix worked (FR-026).
    verification: str | None = None
    side_effects: str | None = None
    effort: str | None = None
    references: list[dict[str, Any]] = Field(default_factory=list)
    ai_model: str | None = None
    generated_at: dt.datetime | None = None
    reviewed_at: dt.datetime | None = None
    reviewed_by: str | None = None


class TicketLinkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    provider: str
    external_key: str
    external_id: str | None = None
    url: str | None = None
    project_key: str | None = None
    issue_type: str | None = None
    external_status: str | None = None
    #: True when the agent opened it rather than a human. Shown in the UI so nobody has
    #: to guess where a ticket came from.
    created_by_agent: bool = False
    created_at: dt.datetime


class FindingOut(BaseModel):
    """List row. Mirrors the DefectDojo record plus Cynux's own analysis (FR-017)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    assessment_id: uuid.UUID | None = None
    asset_id: uuid.UUID | None = None
    #: The authoritative id in DefectDojo, which owns dedup and state (FR-016, FR-018).
    defectdojo_finding_id: int
    title: str
    severity: Severity
    status: FindingStatus
    scanner: ScannerName | None = None
    endpoint: str | None = None
    component: str | None = None
    component_version: str | None = None
    cve_ids: list[str] = Field(default_factory=list)
    cwe: int | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    is_duplicate: bool = False
    is_false_positive: bool = False

    #: Cynux's risk-based ordering (FR-023): exploitability and asset criticality, not
    #: raw CVSS.
    priority: Priority | None = None
    risk_score: float | None = None
    risk_factors: dict[str, Any] = Field(default_factory=dict)
    asset_criticality: Criticality | None = None
    in_kev: bool | None = None

    first_seen_at: dt.datetime | None = None
    last_seen_at: dt.datetime | None = None
    created_at: dt.datetime


class FindingDetailOut(FindingOut):
    ai_explanation: str | None = None
    ai_business_impact: str | None = None
    ai_attack_scenario: str | None = None
    #: Citations backing every AI claim above. See the module docstring (FR-024).
    ai_evidence: list[dict[str, Any]] = Field(default_factory=list)
    ai_model: str | None = None
    ai_analyzed_at: dt.datetime | None = None
    #: Set when analysis was deliberately not performed -- unverifiable input, budget
    #: exhausted, provider down. An empty analysis with no reason would look like a bug.
    ai_skipped_reason: str | None = None

    severity_raw: str | None = None
    defectdojo_test_id: int | None = None
    synced_at: dt.datetime | None = None

    enrichment: EnrichmentOut | None = None
    remediations: list[RemediationOut] = Field(default_factory=list)
    tickets: list[TicketLinkOut] = Field(default_factory=list)
    asset: AssetOut | None = None


class FindingFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Severity | None = None
    priority: Priority | None = None
    status: FindingStatus | None = None
    scanner: ScannerName | None = None
    assessment_id: uuid.UUID | None = None
    asset_id: uuid.UUID | None = None
    #: Tri-state on purpose: ``None`` = don't filter, ``True`` = KEV only,
    #: ``False`` = confirmed-not-in-KEV only (which excludes undetermined).
    in_kev: bool | None = None
    cve: str | None = Field(default=None, max_length=40)
    #: Hide DefectDojo-flagged duplicates and false positives. Defaults to hiding them.
    include_duplicates: bool = False
    include_false_positives: bool = False
    q: str | None = Field(default=None, max_length=200)


class AnalyzeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: Re-run even if an analysis already exists. Without this, repeat calls are no-ops
    #: so a UI retry cannot quietly burn tokens.
    force: bool = False


class RemediateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: Steer the fix, e.g. "patch", "configuration", "compensating control".
    approach: str | None = Field(default=None, max_length=60)
    force: bool = False


class JiraTicketIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: All three fall back to the organization's Jira integration config when omitted.
    project_key: str | None = Field(default=None, max_length=40)
    issue_type: str | None = Field(default=None, max_length=60)
    assignee: str | None = Field(default=None, max_length=200)
    include_remediation: bool = True


class FindingStatusIn(BaseModel):
    """Triage decision. Written through to DefectDojo, which is the system of record."""

    model_config = ConfigDict(extra="forbid")

    status: FindingStatus
    note: str | None = Field(default=None, max_length=2000)


__all__ = [
    "AnalyzeIn",
    "EnrichmentOut",
    "FindingDetailOut",
    "FindingFilter",
    "FindingOut",
    "FindingStatusIn",
    "JiraTicketIn",
    "RemediateIn",
    "RemediationOut",
    "TicketLinkOut",
]
