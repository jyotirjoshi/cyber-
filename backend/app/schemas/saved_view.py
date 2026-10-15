"""Safe saved query-preset contracts."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_FILTERS = {
    "findings": frozenset({"status", "severity", "q", "query", "source"}),
    "assets": frozenset(
        {"status", "environment", "criticality", "q", "internet_exposed", "query"}
    ),
}


class SavedViewCreateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=160)
    resource: Literal["findings", "assets"]
    filters: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode="after")
    def only_resource_filters_are_allowed(self) -> SavedViewCreateIn:
        if set(self.filters).difference(_FILTERS[self.resource]):
            raise ValueError("saved view contains unsupported resource filters")
        if self.resource == "findings" and self.filters.get("source", "assessment") not in {
            "assessment",
            "canonical",
        }:
            raise ValueError("finding saved view source must be assessment or canonical")
        if "query" in self.filters:
            from app.core.errors import InvalidConfigurationError
            from app.services.query_language import validate_saved_query

            try:
                validate_saved_query(self.resource, self.filters["query"])
            except InvalidConfigurationError as exc:
                raise ValueError(exc.user_message) from exc
        return self


class SavedViewUpdateIn(BaseModel):
    """Partial, non-executable changes to a saved query preset.

    ``resource`` deliberately cannot change: a finding filter must never become
    an asset filter through an update request.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=160)
    filters: dict[str, object] | None = None

    @field_validator("name")
    @classmethod
    def normalize_name(cls, name: str | None) -> str | None:
        if name is None:
            return None
        normalized = name.strip()
        if not normalized:
            raise ValueError("name cannot be blank")
        return normalized

    @model_validator(mode="after")
    def require_supported_change(self) -> SavedViewUpdateIn:
        if not self.model_fields_set:
            raise ValueError("at least one saved view field is required")
        if self.filters is not None and set(self.filters).difference(
            _FILTERS["findings"] | _FILTERS["assets"]
        ):
            raise ValueError("saved view contains unsupported resource filters")
        return self


class SavedViewOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    resource: str
    filters: dict[str, object]
    created_at: dt.datetime


__all__ = ["SavedViewCreateIn", "SavedViewUpdateIn", "SavedViewOut"]
