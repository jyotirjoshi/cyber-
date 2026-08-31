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

from pydantic import BaseModel, ConfigDict, Field

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


class ReportGenerateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: ReportFormat = ReportFormat.HTML
    #: ``executive`` leads with business impact and omits scanner detail;
    #: ``technical`` includes endpoints, evidence and remediation steps.
    audience: Literal["executive", "technical"] = "technical"
    title: str | None = Field(default=None, max_length=300)
    #: Regenerate rather than return the existing ready report.
    force: bool = False


__all__ = ["ReportDetailOut", "ReportGenerateIn", "ReportOut"]
