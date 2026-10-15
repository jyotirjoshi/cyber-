"""Operations-facing external notification delivery contracts."""

from __future__ import annotations

import datetime as dt
import uuid

from pydantic import BaseModel, ConfigDict


class ExternalDeliveryOut(BaseModel):
    """A safe projection of one durable external notification attempt."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    event: str
    channel: str
    status: str
    recipient: str
    subject: str | None
    resource_type: str | None
    resource_id: str | None
    attempts: int
    sent_at: dt.datetime | None
    next_retry_at: dt.datetime | None
    last_error: str | None
    created_at: dt.datetime


__all__ = ["ExternalDeliveryOut"]
