"""Public platform API credential contracts."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.enums import Permission


class PlatformApiKeyCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    scopes: list[str] = Field(min_length=1, max_length=32)
    expires_at: dt.datetime | None = None

    @field_validator("scopes")
    @classmethod
    def require_known_unique_scopes(cls, scopes: list[str]) -> list[str]:
        known = {permission.value for permission in Permission}
        if len(set(scopes)) != len(scopes) or any(scope not in known for scope in scopes):
            raise ValueError("scopes must be unique known platform permissions")
        return scopes


class PlatformApiKeyIssuedOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    key_prefix: str
    scopes: list[str]
    expires_at: dt.datetime | None
    secret: str


class PlatformApiKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    key_prefix: str
    scopes: list[str]
    expires_at: dt.datetime | None
    revoked_at: dt.datetime | None
    last_used_at: dt.datetime | None
    created_at: dt.datetime


class ReadinessCheckOut(BaseModel):
    key: str
    category: str
    label: str
    status: str
    detail: str
    action_path: str | None = None


class PlatformReadinessOut(BaseModel):
    ready: bool
    score: int = Field(ge=0, le=100)
    passed: int = Field(ge=0)
    total: int = Field(ge=1)
    checks: list[ReadinessCheckOut]
    evaluated_at: dt.datetime


class OnboardingStepOut(BaseModel):
    key: str
    title: str
    description: str
    status: str
    action_label: str
    action_path: str
    evidence: str


class FirstValueAreaOut(BaseModel):
    key: str
    label: str
    achieved: bool
    evidence: str
    gap: str | None = None
    action_path: str


class PlatformOnboardingOut(BaseModel):
    complete: bool
    percent: int = Field(ge=0, le=100)
    completed: int = Field(ge=0)
    total: int = Field(ge=1)
    next_step: str | None = None
    steps: list[OnboardingStepOut]
    first_value_score: int = Field(ge=0, le=100)
    first_value_areas: list[FirstValueAreaOut]
    evaluated_at: dt.datetime


class PlatformSearchResultOut(BaseModel):
    kind: Literal["asset", "finding", "case", "ticket", "agent", "report"]
    id: uuid.UUID
    title: str
    subtitle: str
    href: str


class DemoWorkspaceOut(BaseModel):
    assessment_id: uuid.UUID
    report_id: uuid.UUID | None
    reused: bool
    assets: int = Field(ge=0)
    findings: int = Field(ge=0)
    incidents: int = Field(ge=0)
    tickets: int = Field(ge=0)
    attack_paths: int = Field(ge=0)
    ai_resources: int = Field(ge=0)


__all__ = [
    "PlatformApiKeyCreateIn",
    "FirstValueAreaOut",
    "DemoWorkspaceOut",
    "PlatformApiKeyIssuedOut",
    "PlatformApiKeyOut",
    "PlatformOnboardingOut",
    "PlatformReadinessOut",
    "PlatformSearchResultOut",
    "OnboardingStepOut",
    "ReadinessCheckOut",
]
