"""Audit trail wire types (FR-032).

``actor_type`` distinguishes ``user``, ``agent`` and ``system``.  That distinction is the
point of the audit log in an agentic product: an approval granted by a human and a scan
started by the agent are different events with different accountability, and a trail that
flattened them would not answer the question an incident review actually asks.

``outcome`` includes ``denied`` as a first-class value.  Refused authorization attempts
are the events most worth keeping -- a log that only records successes cannot show that
tenant isolation held (SEC-003).
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.db.enums import AuditOutcome


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID | None = None
    actor_id: uuid.UUID | None = None
    #: Denormalized so the trail still reads correctly after a user is deleted.
    actor_email: str | None = None
    actor_type: str
    action: str
    resource_type: str | None = None
    resource_id: str | None = None
    outcome: AuditOutcome
    #: Structured context, already scrubbed of secrets by the audit service (SEC-002).
    detail: dict[str, Any] = Field(default_factory=dict)
    reason: str | None = None
    source_ip: str | None = None
    user_agent: str | None = None
    #: Correlates the entry with application logs and the LangSmith trace.
    request_id: str | None = None
    trace_id: str | None = None
    created_at: dt.datetime


class AuditFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor_id: uuid.UUID | None = None
    #: Includes ``worker``: queued work is executed under a worker principal, so
    #: omitting it would make a whole class of real rows unfilterable.
    actor_type: Literal["user", "agent", "worker", "system", "api_key"] | None = None
    action: str | None = Field(default=None, max_length=80)
    resource_type: str | None = Field(default=None, max_length=60)
    resource_id: str | None = Field(default=None, max_length=80)
    outcome: AuditOutcome | None = None
    since: dt.datetime | None = None
    until: dt.datetime | None = None
    q: str | None = Field(default=None, max_length=200)


class AuditListQuery(AuditFilter):
    """The audit feed's complete query contract.

    FastAPI query-model validation sees the whole query string. Keeping pagination in
    this model prevents strict filter validation from rejecting the feed's own
    ``limit`` and ``offset`` parameters.
    """

    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)


__all__ = ["AuditEventOut", "AuditFilter", "AuditListQuery"]
