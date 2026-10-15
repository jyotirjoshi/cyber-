"""Application exposure rollup and repeated cross-repository evidence."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field


class ApplicationRiskOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    application: str
    asset_count: int = Field(ge=0)
    active_findings: int = Field(ge=0)
    critical: int = Field(ge=0)
    high: int = Field(ge=0)
    max_risk_score: float = Field(ge=0, le=100)
    aggregate_risk_score: float = Field(ge=0, le=100)


class ApplicationRiskPageOut(BaseModel):
    items: list[ApplicationRiskOut]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class ApplicationPatternOut(BaseModel):
    key: str
    confidence: str
    repository_count: int = Field(ge=2)
    repositories: list[str]
    finding_ids: list[uuid.UUID]
    max_risk_score: float = Field(ge=0, le=100)


class ApplicationPatternsOut(BaseModel):
    application: str
    patterns: list[ApplicationPatternOut]
    findings_sampled: int = Field(ge=0)
    truncated: bool
