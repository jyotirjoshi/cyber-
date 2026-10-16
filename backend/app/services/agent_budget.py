"""Atomic reservations for multi-agent task, token, and spend budgets."""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError
from app.db.base import utcnow
from app.db.enums import AgentRunStatus
from app.db.models.agent import AgentRun
from app.db.models.agent_task import AgentBudgetReservation


@dataclass(frozen=True, slots=True)
class BudgetLimits:
    tasks: int
    input_tokens: int
    output_tokens: int
    spend_micros: int

    def __post_init__(self) -> None:
        if min(self.tasks, self.input_tokens, self.output_tokens, self.spend_micros) < 0:
            raise ValueError("budget limits cannot be negative")


@dataclass(frozen=True, slots=True)
class BudgetRequest:
    tasks: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    spend_micros: int = 0

    def __post_init__(self) -> None:
        if min(self.tasks, self.input_tokens, self.output_tokens, self.spend_micros) < 0:
            raise ValueError("budget requests cannot be negative")


@dataclass(frozen=True, slots=True)
class BudgetRemaining:
    tasks: int
    input_tokens: int
    output_tokens: int
    spend_micros: int

    def can_reserve(self, request: BudgetRequest) -> bool:
        return (
            request.tasks <= self.tasks
            and request.input_tokens <= self.input_tokens
            and request.output_tokens <= self.output_tokens
            and request.spend_micros <= self.spend_micros
        )


def _aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=dt.UTC)


def _amount(row: AgentBudgetReservation) -> BudgetRequest:
    if row.status == "settled":
        return BudgetRequest(
            tasks=row.actual_tasks,
            input_tokens=row.actual_input_tokens,
            output_tokens=row.actual_output_tokens,
            spend_micros=row.actual_spend_micros,
        )
    if row.status in {"reserved", "forfeited"}:
        return BudgetRequest(
            tasks=row.reserved_tasks,
            input_tokens=row.reserved_input_tokens,
            output_tokens=row.reserved_output_tokens,
            spend_micros=row.reserved_spend_micros,
        )
    return BudgetRequest()


def _remaining(limits: BudgetLimits, rows: list[AgentBudgetReservation]) -> BudgetRemaining:
    used = [_amount(row) for row in rows]
    return BudgetRemaining(
        tasks=max(0, limits.tasks - sum(item.tasks for item in used)),
        input_tokens=max(0, limits.input_tokens - sum(item.input_tokens for item in used)),
        output_tokens=max(0, limits.output_tokens - sum(item.output_tokens for item in used)),
        spend_micros=max(0, limits.spend_micros - sum(item.spend_micros for item in used)),
    )


async def reserve_budget(
    session: AsyncSession,
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    *,
    reservation_key: str,
    request: BudgetRequest,
    limits: BudgetLimits,
    task_id: uuid.UUID | None = None,
    category: str = "run",
    ttl_seconds: int = 300,
) -> AgentBudgetReservation | None:
    """Reserve capacity under the parent-run lock, returning ``None`` at a hard limit."""

    if not reservation_key or len(reservation_key) > 160:
        raise ValueError("reservation keys must contain 1 to 160 characters")
    if category not in {"model", "tool", "scanner", "pipeline", "run"}:
        raise ValueError("unknown budget reservation category")
    if not 1 <= ttl_seconds <= 86_400:
        raise ValueError("budget reservation TTL must be between 1 and 86400 seconds")
    run = (
        await session.execute(
            select(AgentRun)
            .where(
                AgentRun.id == run_id,
                AgentRun.organization_id == organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if run is None or run.status in {
        AgentRunStatus.COMPLETED.value,
        AgentRunStatus.FAILED.value,
        AgentRunStatus.CANCELLED.value,
    }:
        return None
    rows = list(
        (
            await session.execute(
                select(AgentBudgetReservation)
                .where(
                    AgentBudgetReservation.organization_id == organization_id,
                    AgentBudgetReservation.run_id == run_id,
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    existing = next((row for row in rows if row.reservation_key == reservation_key), None)
    if existing is not None:
        expected = BudgetRequest(
            tasks=existing.reserved_tasks,
            input_tokens=existing.reserved_input_tokens,
            output_tokens=existing.reserved_output_tokens,
            spend_micros=existing.reserved_spend_micros,
        )
        if expected != request or existing.task_id != task_id or existing.category != category:
            raise ConflictError("budget reservation key was reused with different work")
        return existing

    now = utcnow()
    for row in rows:
        if row.status == "reserved" and _aware(row.expires_at) <= now:
            row.status = "released"
            row.settled_at = now
    if not _remaining(limits, rows).can_reserve(request):
        await session.flush()
        return None
    reservation = AgentBudgetReservation(
        id=uuid.uuid4(),
        organization_id=organization_id,
        run_id=run_id,
        task_id=task_id,
        reservation_key=reservation_key,
        category=category,
        status="reserved",
        reserved_tasks=request.tasks,
        reserved_input_tokens=request.input_tokens,
        reserved_output_tokens=request.output_tokens,
        reserved_spend_micros=request.spend_micros,
        actual_tasks=0,
        actual_input_tokens=0,
        actual_output_tokens=0,
        actual_spend_micros=0,
        expires_at=now + dt.timedelta(seconds=ttl_seconds),
    )
    session.add(reservation)
    await session.flush()
    return reservation


async def settle_usage(
    session: AsyncSession,
    organization_id: uuid.UUID,
    reservation_id: uuid.UUID,
    *,
    actual: BudgetRequest,
) -> AgentBudgetReservation:
    """Reconcile a reservation once; repeat settlement must carry identical actuals."""

    reservation = (
        await session.execute(
            select(AgentBudgetReservation)
            .where(
                AgentBudgetReservation.id == reservation_id,
                AgentBudgetReservation.organization_id == organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if reservation is None:
        raise ConflictError("budget reservation is unavailable")
    recorded = BudgetRequest(
        tasks=reservation.actual_tasks,
        input_tokens=reservation.actual_input_tokens,
        output_tokens=reservation.actual_output_tokens,
        spend_micros=reservation.actual_spend_micros,
    )
    if reservation.status == "settled":
        if recorded != actual:
            raise ConflictError("budget reservation was already settled differently")
        return reservation
    if reservation.status != "reserved":
        raise ConflictError("budget reservation is no longer settleable")
    reservation.status = "settled"
    reservation.actual_tasks = actual.tasks
    reservation.actual_input_tokens = actual.input_tokens
    reservation.actual_output_tokens = actual.output_tokens
    reservation.actual_spend_micros = actual.spend_micros
    reservation.settled_at = utcnow()
    await session.flush()
    from app.services.usage_metering import record_agent_usage

    await record_agent_usage(
        session,
        organization_id=organization_id,
        actual=actual,
    )
    return reservation


async def record_reserved_usage(
    session: AsyncSession,
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    *,
    actual: BudgetRequest,
) -> AgentBudgetReservation | None:
    """Atomically accumulate one task's actuals against the run reservation."""

    reservation = (
        await session.execute(
            select(AgentBudgetReservation)
            .where(
                AgentBudgetReservation.organization_id == organization_id,
                AgentBudgetReservation.run_id == run_id,
                AgentBudgetReservation.reservation_key == "supervisor-plan-v1",
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if reservation is None or reservation.status not in {"reserved", "settled"}:
        return reservation
    if reservation.status == "settled":
        raise ConflictError("settled run usage cannot be extended")
    reservation.actual_tasks += actual.tasks
    reservation.actual_input_tokens += actual.input_tokens
    reservation.actual_output_tokens += actual.output_tokens
    reservation.actual_spend_micros += actual.spend_micros
    await session.flush()
    from app.services.usage_metering import record_agent_usage

    await record_agent_usage(session, organization_id=organization_id, actual=actual)
    return reservation


__all__ = [
    "BudgetLimits",
    "BudgetRemaining",
    "BudgetRequest",
    "reserve_budget",
    "record_reserved_usage",
    "settle_usage",
]
