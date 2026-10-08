"""Validation shared by tenant-owned asset and finding custom metadata."""

from __future__ import annotations

import math
import re
from typing import Any

_KEY = re.compile(r"[a-z][a-z0-9_]{0,39}\Z")
_SENSITIVE = ("secret", "password", "token", "credential", "api_key", "private_key")
_TOKEN_VALUE = re.compile(r"(?i)(?:sk-|ghp_|glpat-|AQ\.)[a-z0-9_-]{12,}")


def validate_custom_fields(fields: dict[str, Any]) -> dict[str, str | int | float | bool]:
    if len(fields) > 20:
        raise ValueError("custom_fields supports at most 20 entries")
    normalized: dict[str, str | int | float | bool] = {}
    for key, value in fields.items():
        if not _KEY.fullmatch(key) or any(part in key for part in _SENSITIVE):
            raise ValueError("custom field name is invalid or sensitive")
        if isinstance(value, str):
            if len(value) > 200 or any(ord(char) < 32 for char in value):
                raise ValueError("custom field text must be at most 200 printable characters")
            if _TOKEN_VALUE.search(value):
                raise ValueError("custom fields must not contain credentials")
        elif isinstance(value, bool):
            normalized[key] = value
            continue
        elif isinstance(value, int):
            if abs(value) > 1_000_000_000_000:
                raise ValueError("custom field number is out of range")
        elif isinstance(value, float):
            if not math.isfinite(value) or abs(value) > 1_000_000_000_000:
                raise ValueError("custom field number is out of range")
        else:
            raise ValueError("custom fields support only text, number, or boolean values")
        normalized[key] = value
    return normalized
