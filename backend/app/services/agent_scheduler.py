"""Transactional materialization and readiness scheduling for agent DAG tasks."""

from __future__ import annotations

import datetime as dt
import uuid
from collections import defaultdict
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.db.enums import AgentRunStatus, AgentTaskKind, AgentTaskStatus
from app.db.models.agent import AgentRun, RunDispatch
from app.db.models.agent_task import AgentBudgetReservation, AgentTask, AgentTaskDependency
from app.db.models.assessment import Approval
from app.schemas.agent_plan import AgentPlanCondition, ValidatedAgentPlan
from app.worker.dispatch import stage_task_dispatch

_SUCCESS = frozenset({AgentTaskStatus.COMPLETED.value, AgentTaskStatus.DEGRADED.value})
_FAILURE = frozenset(
    {
        AgentTaskStatus.FAILED.value,
        AgentTaskStatus.REJECTED.value,
        AgentTaskStatus.CANCELLED.value,
        AgentTaskStatus.SKIPPED.value,
    }
)
_TERMINAL = _SUCCESS | _FAILURE
_RUN_TERMINAL = frozenset(
    {
        AgentRunStatus.COMPLETED.value,
        AgentRunStatus.FAILED.value,
        AgentRunStatus.CANCELLED.value,
    }
)


class PlanMaterializationConflict(RuntimeError):
    """The run already contains a different plan under the same identity."""


async def _locked_run(
    session: AsyncSession, organization_id: uuid.UUID, run_id: uuid.UUID
) -> AgentRun | None:
    return (
        await session.execute(
            select(AgentRun)
            .where(
                AgentRun.id == run_id,
                AgentRun.organization_id == organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()


def _orchestration_payload(task: Any) -> dict[str, Any]:
    return {
        "condition": task.condition.model_dump(mode="json") if task.condition else None,
        "join_policy": task.join_policy,
        "quorum": task.quorum,
        "target_asset_ids": [str(asset_id) for asset_id in task.target_asset_ids],
        "success_criteria": [item.model_dump(mode="json") for item in task.success_criteria],
    }


async def materialize_plan(
    session: AsyncSession,
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    validated: ValidatedAgentPlan,
) -> list[AgentTask]:
    """Persist a validated graph exactly once inside the caller's transaction.

    A second invocation returns the existing rows only when every immutable key and
    payload digest matches.  It never silently replaces a partially different plan.
    """

    run = await _locked_run(session, organization_id, run_id)
    if run is None or run.status in _RUN_TERMINAL:
        return []

    existing = (
        (
            await session.execute(
                select(AgentTask)
                .where(
                    AgentTask.organization_id == organization_id,
                    AgentTask.run_id == run_id,
                )
                .order_by(AgentTask.plan_index, AgentTask.id)
            )
        )
        .scalars()
        .all()
    )
    if existing:
        expected = [
            (task.key, validated.payload_digests[task.key]) for task in validated.ordered_tasks
        ]
        found = [(task.task_key, task.payload_digest) for task in existing]
        if found != expected:
            raise PlanMaterializationConflict(
                "the run already contains a different immutable task plan"
            )
        return list(existing)

    created: list[AgentTask] = []
    by_key: dict[str, AgentTask] = {}
    for index, planned in enumerate(validated.ordered_tasks):
        digest = validated.payload_digests[planned.key]
        task = AgentTask(
            id=uuid.uuid4(),
            organization_id=organization_id,
            run_id=run_id,
            task_key=planned.key,
            kind=planned.kind.value,
            status=(
                AgentTaskStatus.BLOCKED.value
                if planned.depends_on
                else AgentTaskStatus.PENDING.value
            ),
            idempotency_key=planned.idempotency_key
            or f"{validated.plan.schema_version}:{planned.key}:{digest}",
            payload_digest=digest,
            agent_version_id=planned.agent_version_id,
            tool_name=planned.tool_name,
            tool_version=planned.tool_version,
            input_schema_version=validated.plan.schema_version,
            output_schema_version="v1",
            input_payload=planned.input,
            orchestration=_orchestration_payload(planned),
            output_summary={},
            required=planned.required,
            plan_index=index,
            priority=100,
            attempt_count=0,
            max_attempts=planned.max_attempts,
            current_lease_generation=0,
            provider=planned.provider,
            conflict_key=planned.conflict_key,
        )
        session.add(task)
        created.append(task)
        by_key[planned.key] = task
    await session.flush()

    for planned in validated.ordered_tasks:
        for parent_key in planned.depends_on:
            session.add(
                AgentTaskDependency(
                    id=uuid.uuid4(),
                    organization_id=organization_id,
                    run_id=run_id,
                    task_id=by_key[planned.key].id,
                    depends_on_task_id=by_key[parent_key].id,
                    dependency_kind="required",
                )
            )
    await session.flush()
    return created


def _read_path(payload: dict[str, Any], path: str) -> tuple[bool, Any]:
    value: Any = payload
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return False, None
        value = value[part]
    return True, value


def _condition_matches(condition: dict[str, Any] | None, parents: dict[str, AgentTask]) -> bool:
    if condition is None:
        return True
    parsed = AgentPlanCondition.model_validate(condition)
    parent = parents.get(parsed.task_key)
    if parent is None:
        return False
    exists, actual = _read_path(parent.output_summary, parsed.path)
    if parsed.operator == "exists":
        return exists
    if parsed.operator == "truthy":
        return exists and bool(actual)
    if parsed.operator == "falsy":
        return not exists or not bool(actual)
    if not exists:
        return False
    if parsed.operator == "eq":
        return actual == parsed.value
    return actual != parsed.value


def _dependency_decision(task: AgentTask, parents: list[AgentTask]) -> str:
    """Return ``ready``, ``wait``, ``failed``, or ``skipped``."""

    if not parents:
        return "ready"
    statuses = [parent.status for parent in parents]
    successful = sum(status in _SUCCESS for status in statuses)
    failed = sum(status in _FAILURE for status in statuses)
    terminal = successful + failed
    policy = task.orchestration.get("join_policy")

    if task.kind == AgentTaskKind.JOIN.value:
        if policy == "quorum":
            quorum = int(task.orchestration.get("quorum") or len(parents))
            if successful >= quorum:
                return "ready"
            if successful + (len(parents) - terminal) < quorum:
                return "failed"
            return "wait"
        if policy == "best_effort":
            return "ready" if terminal == len(parents) else "wait"
        if failed:
            return "failed"
        return "ready" if successful == len(parents) else "wait"

    if failed:
        return "skipped"
    return "ready" if successful == len(parents) else "wait"


async def _dependencies(
    session: AsyncSession, organization_id: uuid.UUID, run_id: uuid.UUID
) -> tuple[dict[uuid.UUID, list[uuid.UUID]], dict[uuid.UUID, AgentTask]]:
    tasks = (
        (
            await session.execute(
                select(AgentTask).where(
                    AgentTask.organization_id == organization_id,
                    AgentTask.run_id == run_id,
                )
            )
        )
        .scalars()
        .all()
    )
    by_id = {task.id: task for task in tasks}
    rows = (
        (
            await session.execute(
                select(AgentTaskDependency).where(
                    AgentTaskDependency.organization_id == organization_id,
                    AgentTaskDependency.run_id == run_id,
                )
            )
        )
        .scalars()
        .all()
    )
    parents: dict[uuid.UUID, list[uuid.UUID]] = defaultdict(list)
    for row in rows:
        parents[row.task_id].append(row.depends_on_task_id)
    return dict(parents), by_id


async def release_ready_tasks(
    session: AsyncSession,
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
) -> list[AgentTask]:
    """Release eligible tasks and stage generation-one deliveries atomically."""

    run = await _locked_run(session, organization_id, run_id)
    if run is None or run.status in _RUN_TERMINAL:
        return []
    candidates = (
        (
            await session.execute(
                select(AgentTask)
                .where(
                    AgentTask.organization_id == organization_id,
                    AgentTask.run_id == run_id,
                    AgentTask.status.in_(
                        [AgentTaskStatus.PENDING.value, AgentTaskStatus.BLOCKED.value]
                    ),
                )
                .order_by(AgentTask.plan_index, AgentTask.id)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    if not candidates:
        return []

    parent_ids, all_tasks = await _dependencies(session, organization_id, run_id)
    existing_dispatch_keys = set(
        (
            await session.execute(
                select(RunDispatch.dispatch_key).where(
                    RunDispatch.organization_id == organization_id,
                    RunDispatch.run_id == run_id,
                    RunDispatch.action == "task",
                )
            )
        ).scalars()
    )
    released: list[AgentTask] = []
    for task in candidates:
        parents = [all_tasks[parent_id] for parent_id in parent_ids.get(task.id, [])]
        decision = _dependency_decision(task, parents)
        if decision == "wait":
            continue
        if decision in {"failed", "skipped"}:
            task.status = decision
            task.failure_code = "dependency_failed"
            task.failure_detail = "One or more required dependencies did not complete."
            task.settled_at = utcnow()
            continue

        parents_by_key = {parent.task_key: parent for parent in parents}
        condition = task.orchestration.get("condition")
        if not _condition_matches(condition, parents_by_key):
            task.status = AgentTaskStatus.SKIPPED.value
            task.failure_code = "condition_false"
            task.settled_at = utcnow()
            continue
        degraded = sorted(parent.task_key for parent in parents if parent.status in _FAILURE)
        if degraded:
            task.output_summary = {"degraded_dependencies": degraded}
        if task.kind == AgentTaskKind.APPROVAL.value:
            task.status = AgentTaskStatus.AWAITING_APPROVAL.value
            continue

        task.status = AgentTaskStatus.READY.value
        generation = task.current_lease_generation + 1
        dispatch_key = f"{run_id}:task:{task.id}:{generation}"
        if dispatch_key not in existing_dispatch_keys:
            stage_task_dispatch(
                session,
                organization_id=organization_id,
                run_id=run_id,
                task_id=task.id,
                generation=generation,
            )
            existing_dispatch_keys.add(dispatch_key)
        released.append(task)
    await session.flush()
    return released


async def finalize_run_if_settled(
    session: AsyncSession,
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
) -> AgentRun | None:
    """Settle a run only when every persisted task is terminal.

    Missing events never imply success: the database task states are authoritative.
    Required failed/rejected/cancelled tasks fail the run; optional failures complete
    with an explicit degraded stop reason.
    """

    run = await _locked_run(session, organization_id, run_id)
    if run is None or run.status in _RUN_TERMINAL:
        return run
    tasks = list(
        (
            await session.execute(
                select(AgentTask).where(
                    AgentTask.organization_id == organization_id,
                    AgentTask.run_id == run_id,
                )
            )
        )
        .scalars()
        .all()
    )
    if not tasks or any(task.status not in _TERMINAL for task in tasks):
        return run
    required_failures = [task for task in tasks if task.required and task.status in _FAILURE]
    optional_failures = [task for task in tasks if not task.required and task.status in _FAILURE]
    run.completed_at = utcnow()
    run.current_node = "finalize"
    if required_failures:
        run.status = AgentRunStatus.FAILED.value
        run.stop_reason = "policy_blocked"
        run.failure_category = "task_failure"
        run.failure_reason = (
            f"{len(required_failures)} required agent task(s) did not complete successfully."
        )
    else:
        run.status = AgentRunStatus.COMPLETED.value
        run.stop_reason = "objective_complete"
        if optional_failures:
            run.failure_category = "degraded"
            run.failure_reason = (
                f"Completed with {len(optional_failures)} optional task degradation(s)."
            )
    reservation = (
        await session.execute(
            select(AgentBudgetReservation)
            .where(
                AgentBudgetReservation.organization_id == organization_id,
                AgentBudgetReservation.run_id == run_id,
                AgentBudgetReservation.reservation_key == "supervisor-plan-v1",
                AgentBudgetReservation.status == "reserved",
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if reservation is not None:
        reservation.status = "settled"
        reservation.settled_at = utcnow()
    await session.flush()
    return run


async def settle_join(
    session: AsyncSession,
    organization_id: uuid.UUID,
    task_id: uuid.UUID,
) -> AgentTask | None:
    """Deterministically aggregate bounded dependency summaries for one join."""

    task = (
        await session.execute(
            select(AgentTask)
            .where(
                AgentTask.id == task_id,
                AgentTask.organization_id == organization_id,
                AgentTask.kind == AgentTaskKind.JOIN.value,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if task is None:
        return None
    parent_ids, all_tasks = await _dependencies(session, organization_id, task.run_id)
    parents = [all_tasks[parent_id] for parent_id in parent_ids.get(task.id, [])]
    if _dependency_decision(task, parents) != "ready":
        return task
    task.output_summary = {
        "dependencies": {
            parent.task_key: {
                "status": parent.status,
                "summary": parent.output_summary,
            }
            for parent in parents
        }
    }
    task.status = (
        AgentTaskStatus.DEGRADED.value
        if any(parent.status in _FAILURE for parent in parents)
        else AgentTaskStatus.COMPLETED.value
    )
    task.settled_at = utcnow()
    await session.flush()
    return task


async def cancel_run_tasks(
    session: AsyncSession,
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    *,
    requested_at: dt.datetime | None = None,
) -> int:
    """Cancel every undispatched task; running-task propagation is added by the executor."""

    timestamp = requested_at or utcnow()
    result = await session.execute(
        update(AgentTask)
        .where(
            AgentTask.organization_id == organization_id,
            AgentTask.run_id == run_id,
            AgentTask.status.in_(
                [
                    AgentTaskStatus.PENDING.value,
                    AgentTaskStatus.BLOCKED.value,
                    AgentTaskStatus.READY.value,
                    AgentTaskStatus.QUEUED.value,
                    AgentTaskStatus.AWAITING_APPROVAL.value,
                    AgentTaskStatus.RUNNING.value,
                ]
            ),
        )
        .values(
            status=AgentTaskStatus.CANCELLED.value,
            cancellation_requested_at=timestamp,
            settled_at=timestamp,
            failure_code="run_cancelled",
        )
    )
    return int(result.rowcount or 0)


async def cancel_agent_run(
    session: AsyncSession,
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    *,
    requested_at: dt.datetime | None = None,
) -> AgentRun | None:
    """Cancel a parent run, every live task, pending dispatch, and approval atomically."""

    run = await _locked_run(session, organization_id, run_id)
    if run is None:
        return None
    if run.status == AgentRunStatus.CANCELLED.value:
        return run
    if run.status in {AgentRunStatus.COMPLETED.value, AgentRunStatus.FAILED.value}:
        return run
    timestamp = requested_at or utcnow()
    run.status = AgentRunStatus.CANCELLED.value
    run.completed_at = timestamp
    run.failure_category = "cancelled"
    run.failure_reason = "Cancelled by an authorized operator."
    await cancel_run_tasks(
        session,
        organization_id,
        run_id,
        requested_at=timestamp,
    )
    await session.execute(
        update(RunDispatch)
        .where(
            RunDispatch.organization_id == organization_id,
            RunDispatch.run_id == run_id,
            RunDispatch.status == "pending",
        )
        .values(status="cancelled", last_error_code="run_cancelled")
    )
    await session.execute(
        update(Approval)
        .where(
            Approval.organization_id == organization_id,
            Approval.agent_run_id == run_id,
            Approval.decision == "pending",
        )
        .values(
            decision="expired",
            resolved_at=timestamp,
            resolution_note="Run cancelled before approval execution.",
        )
    )
    await session.flush()
    return run


__all__ = [
    "PlanMaterializationConflict",
    "cancel_agent_run",
    "cancel_run_tasks",
    "finalize_run_if_settled",
    "materialize_plan",
    "release_ready_tasks",
    "settle_join",
]
