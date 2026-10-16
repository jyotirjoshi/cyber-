"""Generation-fenced execution, settlement, and recovery for durable agent tasks."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import secrets
import uuid
from collections.abc import Awaitable
from dataclasses import dataclass, field
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.base import utcnow
from app.db.enums import AgentTaskAttemptStatus, AgentTaskStatus
from app.db.models.agent import AgentRun, RunDispatch
from app.db.models.agent_task import AgentEvidence, AgentTask, AgentTaskAttempt
from app.services.agent_scheduler import release_ready_tasks
from app.worker.dispatch import stage_task_dispatch

_SETTLEMENT_STATUSES = frozenset(
    {
        AgentTaskStatus.COMPLETED.value,
        AgentTaskStatus.DEGRADED.value,
        AgentTaskStatus.SKIPPED.value,
        AgentTaskStatus.FAILED.value,
        AgentTaskStatus.REJECTED.value,
    }
)


@dataclass(frozen=True, slots=True)
class TaskClaim:
    task_id: uuid.UUID
    run_id: uuid.UUID
    organization_id: uuid.UUID
    generation: int
    lease_token: str
    idempotency_key: str
    kind: str
    input_payload: dict[str, Any]
    agent_version_id: uuid.UUID | None
    tool_name: str | None
    tool_version: int
    provider: str | None
    conflict_key: str | None


@dataclass(frozen=True, slots=True)
class TaskEvidenceRecord:
    key: str
    kind: str
    artifact_reference: str
    content_digest: str
    summary: dict[str, Any] = field(default_factory=dict)
    content_type: str | None = None
    verified: bool = False
    produced_at: dt.datetime | None = None


@dataclass(frozen=True, slots=True)
class TaskExecutionResult:
    status: str
    output_summary: dict[str, Any] = field(default_factory=dict)
    evidence: tuple[TaskEvidenceRecord, ...] = ()
    usage: dict[str, Any] = field(default_factory=dict)
    failure_code: str | None = None
    failure_detail: str | None = None

    def __post_init__(self) -> None:
        if self.status not in _SETTLEMENT_STATUSES:
            raise ValueError("task results must use a terminal settlement status")


class TaskHandler(Protocol):
    def __call__(self, claim: TaskClaim) -> Awaitable[TaskExecutionResult]:
        ...


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _result_digest(result: TaskExecutionResult) -> str:
    encoded = json.dumps(
        {
            "status": result.status,
            "output_summary": result.output_summary,
            "usage": result.usage,
            "failure_code": result.failure_code,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


async def claim_task(
    session: AsyncSession,
    organization_id: uuid.UUID,
    task_id: uuid.UUID,
    *,
    worker_id: str,
    lease_seconds: int = 90,
) -> TaskClaim | None:
    """Acquire a new lease generation or return ``None`` when the task is not claimable."""

    if not worker_id or len(worker_id) > 80:
        raise ValueError("worker ids must contain 1 to 80 characters")
    if not 1 <= lease_seconds <= 3600:
        raise ValueError("task leases must be between 1 and 3600 seconds")
    task = (
        await session.execute(
            select(AgentTask)
            .join(
                AgentRun,
                (AgentRun.id == AgentTask.run_id)
                & (AgentRun.organization_id == AgentTask.organization_id),
            )
            .where(
                AgentTask.id == task_id,
                AgentTask.organization_id == organization_id,
                AgentTask.status.in_([AgentTaskStatus.READY.value, AgentTaskStatus.QUEUED.value]),
                AgentTask.cancellation_requested_at.is_(None),
                AgentRun.status.notin_(
                    [
                        "completed",
                        "failed",
                        "cancelled",
                    ]
                ),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if task is None or task.attempt_count >= task.max_attempts:
        return None

    now = utcnow()
    token = secrets.token_urlsafe(32)
    generation = task.current_lease_generation + 1
    attempt = AgentTaskAttempt(
        id=uuid.uuid4(),
        organization_id=organization_id,
        run_id=task.run_id,
        task_id=task.id,
        generation=generation,
        lease_token_digest=_token_digest(token),
        worker_id=worker_id,
        status=AgentTaskAttemptStatus.RUNNING.value,
        leased_until=now + dt.timedelta(seconds=lease_seconds),
        heartbeat_at=now,
        started_at=now,
        usage={},
    )
    session.add(attempt)
    task.status = AgentTaskStatus.RUNNING.value
    task.started_at = task.started_at or now
    task.attempt_count += 1
    task.current_lease_generation = generation
    await session.flush()
    return TaskClaim(
        task_id=task.id,
        run_id=task.run_id,
        organization_id=task.organization_id,
        generation=generation,
        lease_token=token,
        idempotency_key=task.idempotency_key,
        kind=task.kind,
        input_payload=dict(task.input_payload),
        agent_version_id=task.agent_version_id,
        tool_name=task.tool_name,
        tool_version=task.tool_version,
        provider=task.provider,
        conflict_key=task.conflict_key,
    )


async def _locked_attempt(
    session: AsyncSession, claim: TaskClaim
) -> tuple[AgentTask | None, AgentTaskAttempt | None]:
    task = (
        await session.execute(
            select(AgentTask)
            .where(
                AgentTask.id == claim.task_id,
                AgentTask.organization_id == claim.organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if task is None or task.current_lease_generation != claim.generation:
        return task, None
    attempt = (
        await session.execute(
            select(AgentTaskAttempt)
            .where(
                AgentTaskAttempt.task_id == claim.task_id,
                AgentTaskAttempt.organization_id == claim.organization_id,
                AgentTaskAttempt.generation == claim.generation,
                AgentTaskAttempt.lease_token_digest == _token_digest(claim.lease_token),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    return task, attempt


async def heartbeat_task(
    session: AsyncSession,
    claim: TaskClaim,
    *,
    lease_seconds: int = 90,
) -> bool:
    if not 1 <= lease_seconds <= 3600:
        raise ValueError("task leases must be between 1 and 3600 seconds")
    task, attempt = await _locked_attempt(session, claim)
    if (
        task is None
        or attempt is None
        or task.status != AgentTaskStatus.RUNNING.value
        or task.cancellation_requested_at is not None
        or attempt.status != AgentTaskAttemptStatus.RUNNING.value
    ):
        return False
    now = utcnow()
    attempt.heartbeat_at = now
    attempt.leased_until = now + dt.timedelta(seconds=lease_seconds)
    await session.flush()
    return True


async def settle_task(
    session: AsyncSession,
    claim: TaskClaim,
    result: TaskExecutionResult,
) -> bool:
    """Settle only the current lease generation; stale and cancelled results are ignored."""

    task, attempt = await _locked_attempt(session, claim)
    if (
        task is None
        or attempt is None
        or task.status != AgentTaskStatus.RUNNING.value
        or task.cancellation_requested_at is not None
        or attempt.status != AgentTaskAttemptStatus.RUNNING.value
    ):
        return False
    now = utcnow()
    attempt.status = (
        AgentTaskAttemptStatus.COMPLETED.value
        if result.status
        in {
            AgentTaskStatus.COMPLETED.value,
            AgentTaskStatus.DEGRADED.value,
            AgentTaskStatus.SKIPPED.value,
        }
        else AgentTaskAttemptStatus.FAILED.value
    )
    attempt.settled_at = now
    attempt.result_digest = _result_digest(result)
    attempt.usage = dict(result.usage)
    attempt.failure_code = result.failure_code
    attempt.failure_detail = result.failure_detail
    task.status = result.status
    task.output_summary = dict(result.output_summary)
    task.failure_code = result.failure_code
    task.failure_detail = result.failure_detail
    task.settled_at = now
    for evidence in result.evidence:
        session.add(
            AgentEvidence(
                id=uuid.uuid4(),
                organization_id=claim.organization_id,
                run_id=claim.run_id,
                task_id=claim.task_id,
                evidence_key=evidence.key,
                kind=evidence.kind,
                artifact_reference=evidence.artifact_reference,
                content_digest=evidence.content_digest,
                content_type=evidence.content_type,
                summary=dict(evidence.summary),
                verified=evidence.verified,
                produced_at=evidence.produced_at or now,
            )
        )
    await session.flush()
    return True


async def execute_task(
    organization_id: uuid.UUID,
    task_id: uuid.UUID,
    session_factory: async_sessionmaker[AsyncSession],
    handler: TaskHandler,
    *,
    worker_id: str,
    lease_seconds: int = 90,
) -> bool:
    """Claim, execute outside a transaction, settle, and release downstream work."""

    async with session_factory() as claim_session:
        claim = await claim_task(
            claim_session,
            organization_id,
            task_id,
            worker_id=worker_id,
            lease_seconds=lease_seconds,
        )
        if claim is None:
            await claim_session.rollback()
            return False
        await claim_session.commit()

    try:
        result = await handler(claim)
    except Exception as exc:
        result = TaskExecutionResult(
            status=AgentTaskStatus.FAILED.value,
            failure_code=type(exc).__name__,
            failure_detail="Task execution failed before producing a valid result.",
        )

    async with session_factory() as settle_session:
        settled = await settle_task(settle_session, claim, result)
        if settled:
            await settle_session.commit()
        else:
            await settle_session.rollback()
            return False

    async with session_factory() as schedule_session:
        await release_ready_tasks(
            schedule_session,
            claim.organization_id,
            claim.run_id,
        )
        await schedule_session.commit()
    return True


async def recover_stale_tasks(
    session: AsyncSession,
    organization_id: uuid.UUID,
    *,
    now: dt.datetime | None = None,
) -> list[AgentTask]:
    """Fence expired attempts and redispatch retryable tasks without reusing generations."""

    timestamp = now or utcnow()
    attempts = (
        (
            await session.execute(
                select(AgentTaskAttempt)
                .where(
                    AgentTaskAttempt.organization_id == organization_id,
                    AgentTaskAttempt.status == AgentTaskAttemptStatus.RUNNING.value,
                    AgentTaskAttempt.leased_until <= timestamp,
                )
                .order_by(AgentTaskAttempt.leased_until, AgentTaskAttempt.id)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    recovered: list[AgentTask] = []
    for attempt in attempts:
        task = (
            await session.execute(
                select(AgentTask)
                .where(
                    AgentTask.id == attempt.task_id,
                    AgentTask.organization_id == organization_id,
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if (
            task is None
            or task.status != AgentTaskStatus.RUNNING.value
            or task.current_lease_generation != attempt.generation
        ):
            continue
        attempt.status = AgentTaskAttemptStatus.TIMED_OUT.value
        attempt.settled_at = timestamp
        attempt.failure_code = "task_lease_expired"
        if task.cancellation_requested_at is not None:
            task.status = AgentTaskStatus.CANCELLED.value
            task.settled_at = timestamp
            task.failure_code = "run_cancelled"
            continue
        if task.attempt_count >= task.max_attempts:
            task.status = AgentTaskStatus.FAILED.value
            task.settled_at = timestamp
            task.failure_code = "task_attempts_exhausted"
            continue
        task.status = AgentTaskStatus.READY.value
        task.failure_code = "task_lease_expired"
        generation = task.current_lease_generation + 1
        dispatch_key = f"{task.run_id}:task:{task.id}:{generation}"
        exists = (
            await session.execute(
                select(RunDispatch.id).where(
                    RunDispatch.organization_id == organization_id,
                    RunDispatch.dispatch_key == dispatch_key,
                )
            )
        ).scalar_one_or_none()
        if exists is None:
            stage_task_dispatch(
                session,
                organization_id=organization_id,
                run_id=task.run_id,
                task_id=task.id,
                generation=generation,
            )
        recovered.append(task)
    await session.flush()
    return recovered


__all__ = [
    "TaskClaim",
    "TaskEvidenceRecord",
    "TaskExecutionResult",
    "TaskHandler",
    "claim_task",
    "execute_task",
    "heartbeat_task",
    "recover_stale_tasks",
    "settle_task",
]
