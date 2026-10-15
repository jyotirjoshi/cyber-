"""Transactional dispatch records for assessment run requests."""

from __future__ import annotations

import datetime as dt
import uuid

from redis.asyncio.client import Redis
from redis.exceptions import RedisError
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.base import utcnow
from app.db.enums import AgentRunStatus
from app.db.models.agent import AgentRun, AgentSession, RunDispatch
from app.db.models.assessment import Assessment
from app.db.repository import tenant_select
from app.services.context import Principal
from app.worker.protocol import RunAction, RunRequest, publish_run_request


def stage_assessment_run(
    session: AsyncSession,
    principal: Principal,
    assessment: Assessment,
) -> tuple[uuid.UUID, uuid.UUID]:
    """Stage the conversation, queued run, and dispatch as one database unit."""
    session_id = uuid.uuid4()
    run_id = uuid.uuid4()
    session.add(
        AgentSession(
            id=session_id,
            organization_id=principal.organization_id,
            user_id=principal.user_id,
            title=assessment.title,
        )
    )
    assessment.agent_session_id = session_id
    run = AgentRun(
        id=run_id,
        organization_id=principal.organization_id,
        session_id=session_id,
        assessment_id=assessment.id,
        triggered_by_id=principal.user_id,
        thread_id=str(run_id),
        graph="assessment",
        status=AgentRunStatus.QUEUED.value,
    )
    session.add(run)
    dispatch = stage_run_dispatch(
        session,
        organization_id=principal.organization_id,
        run_id=run_id,
        action=RunAction.START,
        principal=principal,
    )
    dispatch.run = run
    return run_id, dispatch.id


def stage_run_dispatch(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    action: RunAction,
    principal: Principal | None = None,
) -> RunDispatch:
    """Stage one idempotent run request inside the caller's transaction."""
    if action is RunAction.START:
        if principal is None or principal.organization_id != organization_id:
            raise ValueError("A start dispatch needs the same-tenant initiating principal")
    elif principal is not None:
        raise ValueError("A resume dispatch must recover authority from its checkpoint")
    dispatch = RunDispatch(
        id=uuid.uuid4(),
        organization_id=organization_id,
        run_id=run_id,
        action=action.value,
        dispatch_key=f"{run_id}:{action.value}",
        principal=principal.to_dict() if principal is not None else None,
        status="pending",
        attempts=0,
        available_at=utcnow(),
    )
    session.add(dispatch)
    return dispatch


async def publish_staged_dispatch(
    dispatch: RunDispatch,
    redis: Redis,
    settings: Settings,
) -> bool:
    """Publish a locked outbox row; leave transient failures pending for a later sweep."""
    if dispatch.status == "sent":
        return True
    if dispatch.status != "pending":
        raise ValueError("Unsupported run dispatch state")
    request = RunRequest.new(
        dispatch.run_id,
        RunAction(dispatch.action),
        principal=dispatch.principal,
    )
    try:
        message_id = await publish_run_request(redis, settings, request)
    except RedisError as exc:
        dispatch.attempts += 1
        delay = min(30 * (2 ** min(dispatch.attempts - 1, 6)), 1800)
        dispatch.available_at = utcnow() + dt.timedelta(seconds=delay)
        dispatch.last_error_code = type(exc).__name__
        return False
    dispatch.status = "sent"
    dispatch.stream_message_id = message_id
    dispatch.published_at = utcnow()
    dispatch.last_error_code = None
    return True


async def deliver_pending_dispatches(
    session: AsyncSession,
    redis: Redis,
    settings: Settings,
    *,
    limit: int = 20,
) -> int:
    """Publish due requests fairly while locking rows across worker replicas."""
    batch_size = max(1, min(limit, 100))
    ranked = (
        select(
            RunDispatch.id.label("dispatch_id"),
            func.row_number()
            .over(
                partition_by=RunDispatch.organization_id,
                order_by=(RunDispatch.available_at, RunDispatch.created_at, RunDispatch.id),
            )
            .label("tenant_rank"),
        )
        .join(
            AgentRun,
            and_(
                AgentRun.id == RunDispatch.run_id,
                AgentRun.organization_id == RunDispatch.organization_id,
            ),
        )
        .where(RunDispatch.status == "pending", RunDispatch.available_at <= utcnow())
        .subquery()
    )
    statement = (
        select(RunDispatch)
        .join(ranked, ranked.c.dispatch_id == RunDispatch.id)
        .where(ranked.c.tenant_rank <= 2)
        .order_by(ranked.c.tenant_rank, RunDispatch.available_at, RunDispatch.id)
        .limit(batch_size)
        .with_for_update(of=RunDispatch, skip_locked=True)
    )
    rows = (await session.execute(statement)).scalars().all()
    delivered = 0
    for row in rows:
        if await publish_staged_dispatch(row, redis, settings):
            delivered += 1
    return delivered


async def deliver_run_dispatch(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    dispatch_id: uuid.UUID,
    redis: Redis,
    settings: Settings,
) -> bool:
    """Attempt one committed dispatch without ever selecting another tenant's row."""
    row = (
        await session.execute(
            tenant_select(RunDispatch, organization_id)
            .join(
                AgentRun,
                and_(
                    AgentRun.id == RunDispatch.run_id,
                    AgentRun.organization_id == RunDispatch.organization_id,
                ),
            )
            .where(RunDispatch.id == dispatch_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if row is None or row.organization_id != organization_id:
        return False
    return await publish_staged_dispatch(row, redis, settings)


__all__ = [
    "deliver_pending_dispatches",
    "deliver_run_dispatch",
    "publish_staged_dispatch",
    "stage_assessment_run",
    "stage_run_dispatch",
]
