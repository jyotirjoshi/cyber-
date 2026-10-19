"""Wire contracts for business-service exposure and quantitative risk."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class BusinessServiceCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    owner_team: str | None = Field(default=None, max_length=120)
    owner_user_id: uuid.UUID | None = None
    criticality: Literal["critical", "high", "normal", "low"] = "normal"
    environment: Literal["production", "staging", "development", "test"] = "production"
    revenue_per_hour_usd: float | None = Field(default=None, ge=0)
    maximum_loss_usd: float | None = Field(default=None, ge=0)
    data_records_at_risk: int | None = Field(default=None, ge=0)
    regulatory_scopes: list[str] = Field(default_factory=list, max_length=30)
    metadata: dict[str, Any] = Field(default_factory=dict)


class BusinessServiceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    slug: str
    name: str
    description: str | None
    owner_team: str | None
    owner_user_id: uuid.UUID | None
    criticality: str
    environment: str
    revenue_per_hour_usd: float | None
    maximum_loss_usd: float | None
    data_records_at_risk: int | None
    regulatory_scopes: list[str]
    status: str
    version: int
    created_at: dt.datetime


class AssetServiceLinkIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: uuid.UUID
    dependency_type: Literal["primary", "supporting", "data_store", "identity", "network"] = (
        "supporting"
    )
    importance_weight: float = Field(default=1.0, ge=0.1, le=10)
    recovery_time_minutes: int | None = Field(default=None, ge=0)
    recovery_point_minutes: int | None = Field(default=None, ge=0)
    provenance: dict[str, Any] = Field(default_factory=dict)


class AssetServiceLinkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    business_service_id: uuid.UUID
    dependency_type: str
    importance_weight: float
    recovery_time_minutes: int | None
    recovery_point_minutes: int | None
    provenance: dict[str, Any]
    created_at: dt.datetime


class BusinessRiskScenarioIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    threat_event: str = Field(min_length=1, max_length=200)
    annual_probability: float = Field(ge=0, le=1)
    loss_min_usd: float = Field(ge=0)
    loss_likely_usd: float = Field(ge=0)
    loss_max_usd: float = Field(ge=0)
    rationale: str = Field(min_length=3, max_length=4000)
    evidence: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def ordered_losses(self) -> BusinessRiskScenarioIn:
        if not self.loss_min_usd <= self.loss_likely_usd <= self.loss_max_usd:
            raise ValueError("loss estimates must be ordered min <= likely <= max")
        return self


class BusinessRiskScenarioOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    business_service_id: uuid.UUID
    name: str
    threat_event: str
    annual_probability: float
    loss_min_usd: float
    loss_likely_usd: float
    loss_max_usd: float
    annualized_loss_expectancy_usd: float
    rationale: str
    evidence: dict[str, Any]
    status: str
    created_at: dt.datetime


class BusinessServiceExposureOut(BaseModel):
    service: BusinessServiceOut
    asset_count: int
    internet_exposed_assets: int
    open_findings: int
    critical_findings: int
    maximum_finding_risk: float
    blast_radius_score: float
    annualized_loss_expectancy_usd: float
    estimated_exposure_usd: float


__all__ = [
    "AssetServiceLinkIn",
    "AssetServiceLinkOut",
    "BusinessRiskScenarioIn",
    "BusinessRiskScenarioOut",
    "BusinessServiceCreateIn",
    "BusinessServiceExposureOut",
    "BusinessServiceOut",
]
