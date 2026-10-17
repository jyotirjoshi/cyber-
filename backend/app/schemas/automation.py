"""Validated API contracts for tenant remediation automation."""

from __future__ import annotations

import datetime as dt
import json
import re
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class AutomationRuleIn(BaseModel):
    """A declarative rule; action payloads cannot carry code or credentials."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    trigger: str
    conditions: dict[str, Any] = Field(default_factory=dict)
    actions: list[dict[str, Any]] = Field(min_length=1, max_length=10)
    cron_expression: str | None = Field(default=None, max_length=120)
    timezone: str = Field(default="UTC", max_length=100)
    is_enabled: bool = True
    dry_run: bool = False

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("automation rule name cannot be blank")
        return value.strip()

    @model_validator(mode="after")
    def validate_definition(self) -> AutomationRuleIn:
        from app.services.automation import validate_rule_definition
        from app.services.scheduling import next_cron_time

        clean = validate_rule_definition(
            trigger=self.trigger, conditions=self.conditions, actions=self.actions
        )
        self.trigger = clean["trigger"]
        self.conditions = clean["conditions"]
        self.actions = clean["actions"]
        if self.cron_expression is not None:
            try:
                next_cron_time(self.cron_expression, self.timezone, dt.datetime.now(dt.UTC))
            except ValueError as exc:
                raise ValueError(str(exc)) from exc
        return self


class AutomationRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    trigger: str
    conditions: dict[str, Any]
    actions: list[dict[str, Any]]
    cron_expression: str | None = None
    timezone: str
    next_run_at: dt.datetime | None = None
    is_enabled: bool
    dry_run: bool
    created_by_id: uuid.UUID | None = None
    created_at: dt.datetime
    updated_at: dt.datetime


class AutomationExecutionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    rule_id: uuid.UUID
    canonical_finding_id: uuid.UUID | None = None
    event_key: str
    status: str
    dry_run: bool
    attempts: int
    next_retry_at: dt.datetime | None = None
    result: dict[str, Any]
    created_at: dt.datetime


class AutomationManualRunIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(min_length=8, max_length=160)
    context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("idempotency_key")
    @classmethod
    def clean_idempotency_key(cls, value: str) -> str:
        cleaned = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,159}", cleaned):
            raise ValueError("idempotency_key contains unsupported characters")
        return cleaned

    @field_validator("context")
    @classmethod
    def bound_context(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ValueError("automation context must be JSON serializable") from exc
        if len(encoded.encode("utf-8")) > 32_768:
            raise ValueError("automation context exceeds 32 KiB")
        return value


class AutomationInboundSecretOut(BaseModel):
    rule_id: uuid.UUID
    secret: str
    rotated_at: dt.datetime


__all__ = [
    "AutomationExecutionOut",
    "AutomationInboundSecretOut",
    "AutomationManualRunIn",
    "AutomationRuleIn",
    "AutomationRuleOut",
]
