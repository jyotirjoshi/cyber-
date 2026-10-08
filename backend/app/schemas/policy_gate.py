"""Machine-readable deployment gate decision."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict


class PolicyGateOut(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: uuid.UUID
    decision: Literal["pass", "warn", "block", "unknown"]
    allow_deploy: bool
    reason_code: str
    counts: dict[str, int]
    scan_imported_at: dt.datetime | None
    evaluated_at: dt.datetime
