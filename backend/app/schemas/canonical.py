"""Public, source-preserving canonical finding projections."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.custom_fields import validate_custom_fields
from app.schemas.finding import TicketLinkOut


class CanonicalFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    title: str
    severity: str
    status: str
    cve_ids: list[str]
    risk_score: float = Field(ge=0, le=100)
    risk_factors: dict[str, Any]
    first_seen_at: dt.datetime
    last_seen_at: dt.datetime
    closed_at: dt.datetime | None
    status_version: int
    assignee_user_id: uuid.UUID | None = None
    due_at: dt.datetime | None = None
    remediation_plan: str | None = None
    remediation_group: str | None = None
    custom_fields: dict[str, Any] = Field(default_factory=dict)


class FindingObservationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    provider: str
    external_id: str
    source_record_id: uuid.UUID | None
    cve_id: str
    title: str
    severity: str
    source_status: str
    source_url: str | None
    first_seen_at: dt.datetime
    last_seen_at: dt.datetime


class FindingHistoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    previous_status: str | None
    new_status: str
    reason: str
    actor_user_id: uuid.UUID | None
    occurred_at: dt.datetime


class FieldProvenanceOut(BaseModel):
    """How a canonical field was selected and which source records support it."""

    field: str
    value: Any
    sources: list[str] = Field(default_factory=list)
    observation_ids: list[uuid.UUID] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    conflicts: bool = False


class CanonicalFindingDetailOut(CanonicalFindingOut):
    observations: list[FindingObservationOut]
    history: list[FindingHistoryOut]
    tickets: list[TicketLinkOut] = Field(default_factory=list)
    field_provenance: list[FieldProvenanceOut] = Field(default_factory=list)


class CanonicalStatusDecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["open", "false_positive"]
    reason: str = Field(min_length=1, max_length=2000)
    expected_version: int = Field(ge=0)


class RiskAcceptanceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rationale: str = Field(min_length=3, max_length=2000)
    expires_at: dt.datetime

    @field_validator("rationale")
    @classmethod
    def clean_rationale(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("risk acceptance rationale cannot be blank")
        return value.strip()

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: dt.datetime) -> dt.datetime:
        from app.services.risk_acceptance import validate_expiry

        return validate_expiry(value)


class RetestRequestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str | None = Field(default=None, max_length=2000)

    @field_validator("note")
    @classmethod
    def clean_note(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("retest note cannot be blank")
        return value.strip() if value is not None else None


class RiskAcceptanceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    canonical_finding_id: uuid.UUID
    requested_by_id: uuid.UUID
    approved_by_id: uuid.UUID | None = None
    rationale: str
    status: str
    expires_at: dt.datetime
    approved_at: dt.datetime | None = None


class RetestRequestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    canonical_finding_id: uuid.UUID
    assessment_id: uuid.UUID | None = None
    status: str
    request_note: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    completed_at: dt.datetime | None = None


class RemediationConvergenceOut(BaseModel):
    """Evidence-conservative progress from tracker work to verified closure."""

    state: Literal[
        "untracked",
        "ticket_active",
        "verification_required",
        "verification_pending",
        "verified_closed",
        "closed_unverified",
        "fix_not_verified",
        "verification_failed",
        "reopened",
        "accepted_risk",
        "false_positive",
    ]
    label: str
    detail: str
    next_action: str
    ticket_closed: bool
    verification_evidence_complete: bool


class CanonicalRemediationOperationOut(BaseModel):
    """The current operational state for one canonical finding.

    This is intentionally a projection rather than a new persistence model.  It lets
    remediation teams work from one queue while preserving canonical finding detail
    and the independent ticket, exception, and retest lifecycles.
    """

    finding: CanonicalFindingOut
    tickets: list[TicketLinkOut] = Field(default_factory=list)
    latest_risk_acceptance: RiskAcceptanceOut | None = None
    latest_retest: RetestRequestOut | None = None
    convergence: RemediationConvergenceOut
    next_action: str
    priority_reasons: list[str] = Field(default_factory=list)
    source_observations: int = Field(default=0, ge=0)
    sla_escalation_level: int = Field(default=0, ge=0, le=3)


class RemediationGroupOut(BaseModel):
    """A bounded operational summary for findings resolved by one common change."""

    name: str
    active_findings: int = Field(ge=0)
    overdue_findings: int = Field(ge=0)
    highest_risk_score: float = Field(ge=0, le=100)
    last_seen_at: dt.datetime


class CanonicalWorkIn(BaseModel):
    """Partial, version-checked remediation work update; null explicitly clears a field."""

    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(ge=0)
    assignee_user_id: uuid.UUID | None = None
    due_at: dt.datetime | None = None
    remediation_plan: str | None = Field(default=None, max_length=4000)
    remediation_group: str | None = Field(default=None, max_length=160)
    custom_fields: dict[str, Any] | None = None

    @field_validator("custom_fields")
    @classmethod
    def clean_custom_fields(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            raise ValueError("custom_fields cannot be null")
        return validate_custom_fields(value)

    @field_validator("remediation_plan")
    @classmethod
    def clean_plan(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("remediation plan cannot be blank; use null to clear it")
        return value.strip() if value is not None else None

    @field_validator("remediation_group")
    @classmethod
    def clean_remediation_group(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("remediation group cannot be blank; use null to clear it")
        cleaned = value.strip() if value is not None else None
        if cleaned is not None and len(cleaned.lower()) > 160:
            raise ValueError("remediation group is too long after normalization")
        return cleaned

    @field_validator("due_at")
    @classmethod
    def require_timezone(cls, value: dt.datetime | None) -> dt.datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("due_at must include a timezone")
        return value

    @model_validator(mode="after")
    def require_change(self) -> CanonicalWorkIn:
        if not (self.model_fields_set - {"expected_version"}):
            raise ValueError("provide at least one remediation work field")
        return self


class BulkCanonicalWorkItemIn(CanonicalWorkIn):
    """One version-checked mutation in an all-or-nothing bulk remediation request."""

    finding_id: uuid.UUID


class BulkCanonicalWorkIn(BaseModel):
    """Bounded batch to avoid unreviewable or accidentally broad remediation changes."""

    model_config = ConfigDict(extra="forbid")

    items: list[BulkCanonicalWorkItemIn] = Field(min_length=1, max_length=100)

    @field_validator("items")
    @classmethod
    def require_unique_finding_ids(
        cls, value: list[BulkCanonicalWorkItemIn]
    ) -> list[BulkCanonicalWorkItemIn]:
        if len({item.finding_id for item in value}) != len(value):
            raise ValueError("bulk remediation finding IDs must be unique")
        return value
