"""Usage metering — per-tenant consumption counters for billing and capacity planning.

Tracks assessments run, scanner jobs executed, findings ingested, AI analysis calls,
and report generations — aggregated by calendar month. These counters are append-only
(never decremented) and tenant-isolated. The metering endpoint is read-only for
tenant owners; only the system principal increments counters.

All writes are upsert-style (INSERT … ON CONFLICT DO UPDATE) so concurrent workers
incrementing the same bucket never race to a negative value.
"""

from __future__ import annotations

import datetime as dt
import uuid
from enum import Enum
from typing import Any

import structlog
from sqlalchemy import BigInteger, Date, String, bindparam, text
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.db.enums import Permission
from app.services.agent_budget import BudgetRequest
from app.services.context import Principal

log = structlog.get_logger(__name__)


class MeterEvent(str, Enum):
    ASSESSMENT_STARTED = "assessment_started"
    SCANNER_JOB_COMPLETED = "scanner_job_completed"
    FINDING_INGESTED = "finding_ingested"
    AI_ANALYSIS_CALL = "ai_analysis_call"
    REPORT_GENERATED = "report_generated"
    ASM_DISCOVERY_RUN = "asm_discovery_run"
    POSTQUANTUM_SCAN = "postquantum_scan"
    AGENT_TASK_COMPLETED = "agent_task_completed"
    AI_INPUT_TOKEN = "ai_input_token"  # noqa: S105 - usage unit, never a credential
    AI_OUTPUT_TOKEN = "ai_output_token"  # noqa: S105 - usage unit, never a credential
    AI_SPEND_MICRO = "ai_spend_micro"


def agent_usage_quantities(actual: BudgetRequest) -> dict[MeterEvent, int]:
    """Translate settled agent usage into append-only billable meter quantities."""

    values = {
        MeterEvent.AGENT_TASK_COMPLETED: actual.tasks,
        MeterEvent.AI_INPUT_TOKEN: actual.input_tokens,
        MeterEvent.AI_OUTPUT_TOKEN: actual.output_tokens,
        MeterEvent.AI_SPEND_MICRO: actual.spend_micros,
    }
    return {event: quantity for event, quantity in values.items() if quantity > 0}


async def record_agent_usage(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    actual: BudgetRequest,
    month: dt.date | None = None,
) -> None:
    """Record every non-zero settled agent counter through the shared durable meter."""

    for event, quantity in agent_usage_quantities(actual).items():
        await increment(
            session,
            organization_id=organization_id,
            event=event,
            quantity=quantity,
            month=month,
        )


async def increment(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    event: MeterEvent,
    quantity: int = 1,
    month: dt.date | None = None,
) -> None:
    """Increment a tenant's monthly usage counter, creating the bucket if needed.

    The optional write runs in a savepoint. Merely catching a PostgreSQL error
    would leave the entire caller transaction aborted, losing its actual work.
    Failures flushing core work still propagate; only the meter is degradable.
    """
    if isinstance(quantity, bool) or not isinstance(quantity, int):
        raise ValueError("meter quantity must be an integer")
    if quantity <= 0:
        return
    month = (month or utcnow().date()).replace(day=1)
    statement = text(
        """
        INSERT INTO usage_meter_buckets
            (id, organization_id, month, event, quantity, updated_at)
        VALUES
            (:id, :org, :month, :event, :qty, now())
        ON CONFLICT (organization_id, month, event)
        DO UPDATE SET
            quantity = usage_meter_buckets.quantity + EXCLUDED.quantity,
            updated_at = now()
        """
    ).bindparams(
        bindparam("id", type_=String(36)),
        bindparam("org", type_=PgUUID(as_uuid=True)),
        bindparam("month", type_=Date()),
        bindparam("event", type_=String(60)),
        bindparam("qty", type_=BigInteger()),
    )
    # begin_nested flushes pending ORM work before establishing its savepoint.
    # Flush explicitly outside the degradation handler so real work cannot fail
    # silently and leave the caller believing its scan or assessment was saved.
    await session.flush()
    try:
        async with session.begin_nested():
            await session.execute(
                statement,
                {
                    "id": str(uuid.uuid4()),
                    "org": organization_id,
                    "month": month,
                    "event": event.value,
                    "qty": quantity,
                },
            )
    except Exception as exc:
        if not session.is_active:
            raise
        log.warning(
            "metering.increment_failed",
            organization_id=str(organization_id),
            meter_event=event.value,
            exc_type=type(exc).__name__,
        )


async def get_usage(
    session: AsyncSession,
    principal: Principal,
    *,
    months: int = 3,
) -> list[dict[str, Any]]:
    """Return the caller's tenant usage for the last N months.

    Only owners and admins may read usage; we do not expose one tenant's counters
    to another under any circumstances.
    """
    principal.require(Permission.ORG_READ)
    if isinstance(months, bool) or not isinstance(months, int) or not 1 <= months <= 12:
        raise ValueError("months must be between 1 and 12")
    current_month = utcnow().date().replace(day=1)
    start_month = current_month
    for _ in range(months - 1):
        start_month = (start_month - dt.timedelta(days=1)).replace(day=1)

    statement = text(
        """
        SELECT month, event, quantity
        FROM usage_meter_buckets
        WHERE organization_id = :org
          AND month >= :start AND month <= :end
        ORDER BY month DESC, event
        """
    ).bindparams(
        bindparam("org", type_=PgUUID(as_uuid=True)),
        bindparam("start", type_=Date()),
        bindparam("end", type_=Date()),
    )
    await session.flush()
    try:
        async with session.begin_nested():
            rows = (
                await session.execute(
                    statement,
                    {"org": principal.organization_id, "start": start_month, "end": current_month},
                )
            ).fetchall()
    except Exception as exc:
        if not session.is_active:
            raise
        log.warning("metering.read_failed", exc_type=type(exc).__name__)
        return []

    return [
        {
            "month": str(row[0]),
            "event": str(row[1]),
            "quantity": int(row[2]),
        }
        for row in rows
        if row[0] is not None  # tenant-isolation: table WHERE clause already filters
    ]


__all__ = [
    "MeterEvent",
    "agent_usage_quantities",
    "get_usage",
    "increment",
    "record_agent_usage",
]
