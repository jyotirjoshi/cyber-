"""Report wire types (FR-030).

``content_digest`` and ``degradations`` are carried on the detail view because a report is
an artifact people forward to other people.  The digest records what the report was built
from -- finding counts by severity, assets, scanners that ran -- and the degradation list
records what was missing when it was built.  Without those two a stale PDF is
indistinguishable from a current one, and a report generated during an NVD outage looks
exactly like a complete one.

``summary_ai_generated`` is explicit for the same reason (FR-024): a reader is entitled to
know that the executive summary was written by a model.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.db.enums import ReportFormat, ReportStatus
from app.schemas.assessment import DegradationOut


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    assessment_id: uuid.UUID
    title: str
    format: ReportFormat
    audience: str
    status: ReportStatus
    size_bytes: int | None = None
    sha256: str | None = None
    generated_at: dt.datetime | None = None
    #: Presigned, short-lived. ``None`` until ``status`` is ``ready``.
    download_url: str | None = None
    failure_reason: str | None = None
    created_at: dt.datetime


class ReportDetailOut(ReportOut):
    executive_summary: str | None = None
    #: True when the summary above came from the LLM rather than a template.
    summary_ai_generated: bool = False
    ai_model: str | None = None
    #: What the report was rendered from. See the module docstring.
    content_digest: dict[str, Any] = Field(default_factory=dict)
    degradations: list[DegradationOut] = Field(default_factory=list)
    template_id: uuid.UUID | None = None
    template_version: int | None = None
    template_snapshot: dict[str, Any] = Field(default_factory=dict)


class ReportGenerateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: ReportFormat = ReportFormat.HTML
    #: ``executive`` leads with business impact and omits scanner detail;
    #: ``technical`` includes endpoints, evidence and remediation steps.
    audience: Literal["executive", "technical"] = "technical"
    title: str | None = Field(default=None, max_length=300)
    #: Regenerate rather than return the existing ready report.
    force: bool = False
    template_id: uuid.UUID | None = None


class ReportScheduleCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    assessment_id: uuid.UUID
    title: str | None = Field(default=None, max_length=300)
    format: ReportFormat = ReportFormat.PDF
    audience: Literal["executive", "technical"] = "executive"
    cron_expression: str = Field(min_length=9, max_length=120)
    timezone: str = Field(default="UTC", min_length=1, max_length=80)
    recipients: list[EmailStr] = Field(default_factory=list, max_length=50)
    template_id: uuid.UUID | None = None

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, value: str) -> str:
        from app.services.scheduling import next_cron_time

        next_cron_time(value, "UTC", dt.datetime.now(dt.UTC))
        return value


class ReportScheduleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    assessment_id: uuid.UUID
    name: str
    title: str | None
    format: ReportFormat
    audience: str
    cron_expression: str
    timezone: str
    recipients: list[str]
    is_enabled: bool
    next_run_at: dt.datetime
    last_run_at: dt.datetime | None
    last_report_id: uuid.UUID | None
    created_at: dt.datetime
    template_id: uuid.UUID | None = None


class ReportTemplateCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=1000)
    definition: dict[str, Any]


class ReportTemplateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    version: int
    description: str | None
    definition: dict[str, Any]
    is_active: bool
    created_at: dt.datetime


class ReportShareCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expires_at: dt.datetime


class ReportShareIssuedOut(BaseModel):
    id: uuid.UUID
    token: str
    expires_at: dt.datetime


class ReportShareLinkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    report_id: uuid.UUID
    token_prefix: str
    expires_at: dt.datetime
    revoked_at: dt.datetime | None = None
    created_at: dt.datetime


__all__ = ["ReportDetailOut", "ReportGenerateIn", "ReportOut", "ReportScheduleCreateIn", "ReportScheduleOut", "ReportShareCreateIn", "ReportShareIssuedOut", "ReportShareLinkOut", "ReportTemplateCreateIn", "ReportTemplateOut"]
