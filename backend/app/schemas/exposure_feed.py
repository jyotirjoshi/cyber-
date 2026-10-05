"""Public source-preserving exposure projection."""

from __future__ import annotations

import datetime as dt
import uuid

from pydantic import BaseModel


class ExposureOut(BaseModel):
    id: uuid.UUID
    source: str
    title: str
    severity: str
    status: str
    resource: str | None
    seen_at: dt.datetime | None
