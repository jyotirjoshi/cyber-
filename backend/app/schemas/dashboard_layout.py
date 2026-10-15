"""Declarative, allowlisted custom dashboard layouts."""

from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_WIDGETS = frozenset({"posture", "exposure_trend", "risk_heatmap", "team_exposure", "top_findings", "recent_assessments", "compliance", "integration_health", "activity", "attack_paths"})


class DashboardLayoutIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=160)
    audience: Literal["executive", "technical", "team"] = "technical"
    widgets: list[str] = Field(min_length=1, max_length=10)
    is_default: bool = False

    @field_validator("widgets")
    @classmethod
    def validate_widgets(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value) or not set(value).issubset(_WIDGETS):
            raise ValueError("widgets must be unique supported dashboard widgets")
        return value


class DashboardLayoutOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    name: str
    audience: str
    widgets: list[dict[str, object]]
    is_default: bool


__all__ = ["DashboardLayoutIn", "DashboardLayoutOut"]
