"""Write-only API contracts for authenticated scanner profiles."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.db.enums import ScannerName

ScanAuthType = Literal[
    "basic", "bearer", "header", "cookie", "openapi_token", "aws_static", "aws_role",
    "azure_service_principal", "gcp_service_account",
]

_REQUIRED = {
    "basic": {"username", "password"},
    "bearer": {"token"},
    "header": {"header_name", "header_value"},
    "cookie": {"cookie"},
    "openapi_token": {"token"},
    "aws_static": {"access_key_id", "secret_access_key"},
    "aws_role": {"role_arn"},
    "azure_service_principal": {"tenant_id", "client_id", "client_secret"},
    "gcp_service_account": {"service_account_json"},
}


class ScanAuthProfileIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=1, max_length=160)
    auth_type: ScanAuthType
    target_patterns: list[str] = Field(min_length=1, max_length=50)
    permitted_scanners: list[ScannerName] = Field(min_length=1, max_length=12)
    metadata: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, str]
    is_active: bool = True

    @field_validator("target_patterns")
    @classmethod
    def validate_patterns(cls, values: list[str]) -> list[str]:
        clean = []
        for value in values:
            item = value.strip().lower()
            if not item or len(item) > 500 or item == "*" or any(c.isspace() for c in item):
                raise ValueError("invalid scan credential target pattern")
            clean.append(item)
        if len(set(clean)) != len(clean):
            raise ValueError("target patterns must be unique")
        return clean

    @model_validator(mode="after")
    def validate_secret_shape(self) -> ScanAuthProfileIn:
        required = _REQUIRED[self.auth_type]
        optional = (
            {"session_token"}
            if self.auth_type == "aws_static"
            else {"external_id"} if self.auth_type == "aws_role" else set()
        )
        if set(self.secrets) - required - optional or not required.issubset(self.secrets):
            raise ValueError("secret fields do not match authentication type")
        if any(not isinstance(value, str) or not value for value in self.secrets.values()):
            raise ValueError("credential values cannot be blank")
        if any(marker in key.lower() for key in self.metadata for marker in ("secret", "token", "password", "credential")):
            raise ValueError("secret-shaped metadata is not allowed")
        compatible = {
            "basic": {ScannerName.NUCLEI},
            "bearer": {ScannerName.NUCLEI, ScannerName.ZAP},
            "header": {ScannerName.NUCLEI},
            "cookie": {ScannerName.NUCLEI},
            "openapi_token": {ScannerName.NUCLEI, ScannerName.ZAP},
            "aws_static": {ScannerName.PROWLER_AWS},
            "aws_role": {ScannerName.PROWLER_AWS},
            "azure_service_principal": {ScannerName.PROWLER_AZURE},
            "gcp_service_account": {ScannerName.PROWLER_GCP},
        }[self.auth_type]
        if any(scanner not in compatible for scanner in self.permitted_scanners):
            raise ValueError("authentication type is not compatible with permitted scanner")
        return self


class ScanAuthProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    auth_type: str
    target_patterns: list[str]
    permitted_scanners: list[str]
    metadata: dict[str, Any] = Field(validation_alias="metadata_")
    fingerprint: str
    hint: str | None
    is_active: bool
    last_validated_at: dt.datetime | None
    rotated_at: dt.datetime | None
    created_at: dt.datetime
    updated_at: dt.datetime


__all__ = ["ScanAuthProfileIn", "ScanAuthProfileOut", "ScanAuthType"]
