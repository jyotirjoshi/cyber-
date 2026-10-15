"""Dashboard wire types (FR-031).

``mean_time_to_remediate_days`` is ``float | None`` and the ``None`` is meaningful: an
organization with no remediated findings has no MTTR, and rendering that as ``0.0`` would
claim instantaneous remediation.  The same restraint applies to ``kev_findings``, which
counts only findings *confirmed* to be in CISA KEV -- findings whose KEV lookup failed are
excluded rather than assumed absent (FR-020).
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.db.enums import AuditOutcome, Priority, Severity
from app.schemas.assessment import AssessmentOut
from app.schemas.integration import IntegrationHealthOut


class ActivityOut(BaseModel):
    """A recent, human-meaningful event. A readable slice of the audit trail, not the
    trail itself -- ``GET /audit`` serves that, gated on ``audit:read``."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    at: dt.datetime
    actor: str | None = Field(default=None, description="Email, or 'agent'/'system'.")
    actor_type: str = "user"
    action: str
    resource_type: str | None = None
    resource_id: str | None = None
    outcome: AuditOutcome = AuditOutcome.SUCCESS
    #: Pre-rendered one-liner, e.g. "agent requested approval to scan 12 assets".
    summary: str | None = None


class DashboardFindingOut(BaseModel):
    """One ranked exposure with an explicit canonical or legacy destination."""

    id: uuid.UUID
    source_kind: Literal["canonical", "legacy"]
    title: str
    severity: Severity
    priority: Priority | None = None
    risk_score: float | None = None
    risk_factors: dict[str, Any] = Field(default_factory=dict)
    in_kev: bool | None = None
    first_seen_at: dt.datetime


class DashboardOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    assessments_total: int = 0
    assessments_active: int = 0
    #: Drives the badge that tells an approver work is blocked on them (FR-011).
    assessments_awaiting_approval: int = 0

    findings_open: int = 0
    #: Provider alerts are separate from DefectDojo-owned assessment findings.
    external_alerts_actionable: int = 0
    external_alerts_awaiting_triage: int = 0
    #: Keyed by ``Severity`` value; every severity present even at zero, so the chart
    #: does not change shape between refreshes.
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    priority_breakdown: dict[str, int] = Field(default_factory=dict)

    assets_total: int = 0
    assets_critical: int = 0
    #: Confirmed KEV only. See the module docstring.
    kev_findings: int = 0
    #: ``None`` when nothing has been remediated yet. Never coerce to zero.
    mean_time_to_remediate_days: float | None = None

    recent_assessments: list[AssessmentOut] = Field(default_factory=list)
    #: Highest-priority open findings, ordered by Cynux risk score (FR-023).
    top_findings: list[DashboardFindingOut] = Field(default_factory=list)
    activity: list[ActivityOut] = Field(default_factory=list)
    integration_health: list[IntegrationHealthOut] = Field(default_factory=list)
    generated_at: dt.datetime | None = None


class TeamDashboardOut(BaseModel):
    """Exposure rollup for assets assigned to one CMDB or operator-owned team."""

    team_name: str
    assets_total: int = 0
    assets_critical: int = 0
    findings_open: int = 0
    kev_findings: int = 0
    highest_risk_score: float | None = None
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    priority_breakdown: dict[str, int] = Field(default_factory=dict)


class AssetGroupRiskOut(BaseModel):
    """Exposure rollup for a curated asset group using canonical findings."""

    group_name: str
    assets_total: int = 0
    internet_exposed_assets: int = 0
    findings_open: int = 0
    critical_or_high_findings: int = 0
    highest_risk_score: float | None = None
    aggregate_risk_score: float = Field(default=0, ge=0)


class RiskTrendPointOut(BaseModel):
    """One immutable assessment-report snapshot for an exposure trend."""

    assessment_id: uuid.UUID
    assessment_reference: int | None = None
    measured_at: dt.datetime
    exposure_score: float = Field(ge=0, le=100)
    findings_total: int = Field(ge=0)
    assets_total: int = Field(ge=0)
    new_findings: int = Field(ge=0)
    resolved_findings: int = Field(ge=0)


class RiskTrendOut(BaseModel):
    points: list[RiskTrendPointOut] = Field(default_factory=list)
    source: str = "completed_assessment_reports"


__all__ = [
    "ActivityOut",
    "DashboardOut",
    "RiskTrendOut",
    "RiskTrendPointOut",
    "TeamDashboardOut",
    "AssetGroupRiskOut",
]
