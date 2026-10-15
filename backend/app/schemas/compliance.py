"""Wire types for compliance control evidence and coverage reporting."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

class ComplianceControlCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework: Literal["pci_dss", "iso_27001", "soc_2", "hipaa", "nist_csf", "cis_controls"]
    control_id: str = Field(min_length=1, max_length=120)
    title: str = Field(min_length=1, max_length=500)
    family: str | None = Field(default=None, max_length=160)
    description: str | None = Field(default=None, max_length=8000)
    owner_user_id: uuid.UUID | None = None
    assessment_status: Literal[
        "not_assessed", "satisfied", "partially_satisfied", "at_risk", "not_applicable"
    ] = "not_assessed"
    evidence: dict[str, Any] = Field(default_factory=dict)

    @field_validator("control_id", "title", "family", "description")
    @classmethod
    def normalize_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("value cannot be blank")
        return cleaned


class ComplianceControlUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=500)
    family: str | None = Field(default=None, max_length=160)
    description: str | None = Field(default=None, max_length=8000)
    owner_user_id: uuid.UUID | None = None
    assessment_status: Literal[
        "not_assessed", "satisfied", "partially_satisfied", "at_risk", "not_applicable"
    ] | None = None
    evidence: dict[str, Any] | None = None

    @field_validator("title", "family", "description")
    @classmethod
    def normalize_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("value cannot be blank")
        return cleaned


class ComplianceMappingCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    canonical_finding_id: uuid.UUID
    mapping_type: Literal["manual", "import", "automated"] = "manual"
    note: str | None = Field(default=None, max_length=4000)

    @field_validator("note")
    @classmethod
    def normalize_note(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("note cannot be blank")
        return cleaned


class ComplianceFindingMappingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    canonical_finding_id: uuid.UUID
    mapping_type: str
    note: str | None
    created_at: dt.datetime


class ComplianceControlOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    framework: str
    control_id: str
    title: str
    family: str | None
    description: str | None
    owner_user_id: uuid.UUID | None
    assessment_status: str
    evidence: dict[str, Any]
    mapped_finding_count: int = 0
    active_finding_count: int = 0
    highest_risk_score: float | None = None
    effective_status: str = "not_assessed"


class ComplianceFrameworkSummaryOut(BaseModel):
    framework: str
    control_count: int
    mapped_control_count: int
    at_risk_control_count: int
    partially_satisfied_control_count: int
    satisfied_control_count: int
    active_finding_count: int
    coverage_percent: float = Field(ge=0, le=100)


class ComplianceOverviewOut(BaseModel):
    frameworks: list[ComplianceFrameworkSummaryOut]


__all__ = [
    "ComplianceControlCreateIn",
    "ComplianceControlOut",
    "ComplianceControlUpdateIn",
    "ComplianceFindingMappingOut",
    "ComplianceFrameworkSummaryOut",
    "ComplianceMappingCreateIn",
    "ComplianceOverviewOut",
]
