"""Generation-fenced execution, settlement, and recovery for durable agent tasks."""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import secrets
import uuid
from collections.abc import Awaitable
from dataclasses import dataclass, field, replace
from types import SimpleNamespace
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agent.tools.policy import EffectiveTool, OrganizationToolPolicy, resolve_effective_tools
from app.core.errors import ConflictError, PermissionDeniedError
from app.db.base import utcnow
from app.db.enums import AgentTaskAttemptStatus, AgentTaskStatus, ApprovalDecision, Role
from app.db.models.agent import AgentRun, RunDispatch
from app.db.models.agent_definition import AgentDefinitionVersion, AgentVersionTool
from app.db.models.agent_task import AgentEvidence, AgentTask, AgentTaskAttempt
from app.db.models.assessment import Approval
from app.db.models.identity import Membership, Organization
from app.services.agent_scheduler import finalize_run_if_settled, release_ready_tasks
from app.services.approval import task_approval_digest
from app.services.context import Principal
from app.services.organization import load_policy
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


class _TaskLeaseLost(Exception):
    """The current worker no longer owns the task generation."""


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


@dataclass(frozen=True, slots=True)
class ResultVerification:
    passed: bool
    failed_criteria: tuple[str, ...]


def _read_result_path(value: Any, path: str) -> tuple[bool, Any]:
    current = value
    for part in path.split("."):
        if isinstance(current, dict):
            if part not in current:
                return False, None
            current = current[part]
        else:
            if not hasattr(current, part):
                return False, None
            current = getattr(current, part)
    return True, current


def _criterion_matches(exists: bool, actual: Any, operator: str, expected: Any) -> bool:
    if operator == "exists":
        return exists
    if operator == "truthy":
        return exists and bool(actual)
    if operator == "falsy":
        return not exists or not bool(actual)
    if not exists:
        return False
    if operator == "eq":
        return actual == expected
    if operator == "ne":
        return actual != expected
    if operator == "gte":
        return isinstance(actual, int | float) and isinstance(expected, int | float) and actual >= expected
    if operator == "lte":
        return isinstance(actual, int | float) and isinstance(expected, int | float) and actual <= expected
    return False


def verify_task_result(
    result: TaskExecutionResult, criteria: list[dict[str, Any]]
) -> ResultVerification:
    """Verify declared postconditions using only bounded output and verified evidence."""

    failed: list[str] = []
    verified_evidence = [item for item in result.evidence if item.verified]
    for criterion in criteria:
        source = str(criterion.get("source", ""))
        path = str(criterion.get("path", ""))
        operator = str(criterion.get("operator", ""))
        expected = criterion.get("value")
        matched = False
        if source == "output":
            exists, actual = _read_result_path(result.output_summary, path)
            matched = _criterion_matches(exists, actual, operator, expected)
        elif source == "evidence":
            matched = any(
                _criterion_matches(*_read_result_path(item, path), operator, expected)
                for item in verified_evidence
            )
        if not matched:
            failed.append(f"{source}.{path}:{operator}")
    return ResultVerification(passed=not failed, failed_criteria=tuple(failed))


def enforce_task_postconditions(
    result: TaskExecutionResult,
    *,
    required: bool,
    criteria: list[dict[str, Any]],
) -> TaskExecutionResult:
    if not criteria or result.status not in {
        AgentTaskStatus.COMPLETED.value,
        AgentTaskStatus.DEGRADED.value,
    }:
        return result
    verification = verify_task_result(result, criteria)
    if verification.passed:
        return replace(
            result,
            output_summary={**result.output_summary, "success_criteria_passed": True},
        )
    return replace(
        result,
        status=(AgentTaskStatus.FAILED.value if required else AgentTaskStatus.DEGRADED.value),
        output_summary={
            **result.output_summary,
            "success_criteria_passed": False,
            "failed_criteria": list(verification.failed_criteria),
        },
        failure_code="success_criteria_failed",
        failure_detail="Task output did not satisfy its declared postconditions.",
    )


class TaskHandler(Protocol):
    def __call__(self, claim: TaskClaim) -> Awaitable[TaskExecutionResult]:
        ...


@dataclass(frozen=True, slots=True)
class ApprovedTaskExecutionContext:
    """Trusted, execution-time authority for one exact approved tool invocation."""

    organization_id: uuid.UUID
    run_id: uuid.UUID
    task_id: uuid.UUID
    approval_id: uuid.UUID
    agent_version_id: uuid.UUID
    tool_name: str
    tool_version: int
    input_payload: dict[str, Any]
    idempotency_key: str
    principal: Principal
    effective_tool: EffectiveTool


class ApprovedTaskProvider(Protocol):
    def __call__(self, context: ApprovedTaskExecutionContext) -> Awaitable[Any]:
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


def _aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=dt.UTC)


def organization_tool_policy(organization: Organization) -> OrganizationToolPolicy:
    policy = load_policy(organization)
    return OrganizationToolPolicy(
        disabled_tools=frozenset(policy.agent_disabled_tools),
        allowed_side_effects=frozenset(policy.agent_allowed_side_effects),
        max_timeout_seconds=policy.agent_max_tool_timeout_seconds,
        max_calls_per_tool=policy.agent_max_calls_per_tool,
        approval_overrides=dict(policy.agent_tool_approval_overrides),
    )


async def execute_approved_task(
    session: AsyncSession,
    organization_id: uuid.UUID,
    approval_id: uuid.UUID,
    provider: ApprovedTaskProvider,
    *,
    manage_task_state: bool = True,
) -> Any:
    """Revalidate a human grant and current authority before the provider side effect."""

    approval = (
        await session.execute(
            select(Approval)
            .where(
                Approval.id == approval_id,
                Approval.organization_id == organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if approval is None or approval.agent_task_id is None:
        raise ConflictError("agent task approval is unavailable")
    if approval.decision not in {
        ApprovalDecision.APPROVED.value,
        ApprovalDecision.APPROVED_ALL.value,
        ApprovalDecision.CUSTOMIZED.value,
    }:
        raise ConflictError("agent task approval is not granted")
    if approval.expires_at is not None and _aware(approval.expires_at) <= utcnow():
        approval.decision = ApprovalDecision.EXPIRED.value
        approval.resolved_at = utcnow()
        await session.flush()
        raise ConflictError("agent task approval has expired")
    if approval.resolved_by_id is None or approval.agent_version_id is None:
        raise ConflictError("agent task approval binding is incomplete")

    task = (
        await session.execute(
            select(AgentTask)
            .where(
                AgentTask.id == approval.agent_task_id,
                AgentTask.organization_id == organization_id,
                AgentTask.run_id == approval.agent_run_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    expected_statuses = {AgentTaskStatus.AWAITING_APPROVAL.value}
    if not manage_task_state:
        expected_statuses.add(AgentTaskStatus.RUNNING.value)
    if task is None or task.status not in expected_statuses:
        raise ConflictError("approved agent task is no longer executable")
    if (
        task.tool_name is None
        or approval.tool_name != task.tool_name
        or approval.tool_version != task.tool_version
        or approval.payload_digest != task_approval_digest(task, approval.agent_version_id)
        or approval.requested_payload != task.input_payload
        or approval.approved_payload != task.input_payload
    ):
        raise ConflictError("approved agent task payload or executor binding changed")
    run = (
        await session.execute(
            select(AgentRun).where(
                AgentRun.id == task.run_id,
                AgentRun.organization_id == organization_id,
            )
        )
    ).scalar_one_or_none()
    if run is None or run.status in {
        "completed",
        "partially_completed",
        "blocked",
        "failed",
        "cancelled",
    }:
        raise ConflictError("approved agent run is no longer executable")

    membership = (
        await session.execute(
            select(Membership).where(
                Membership.organization_id == organization_id,
                Membership.user_id == approval.resolved_by_id,
                Membership.accepted_at.isnot(None),
            )
        )
    ).scalar_one_or_none()
    organization = await session.get(Organization, organization_id)
    version = (
        await session.execute(
            select(AgentDefinitionVersion).where(
                AgentDefinitionVersion.id == approval.agent_version_id,
                AgentDefinitionVersion.organization_id == organization_id,
            )
        )
    ).scalar_one_or_none()
    if membership is None or organization is None or not organization.is_active or version is None:
        raise PermissionDeniedError("approved agent authority is no longer active")
    assignments = list(
        (
            await session.execute(
                select(AgentVersionTool).where(
                    AgentVersionTool.organization_id == organization_id,
                    AgentVersionTool.agent_version_id == version.id,
                )
            )
        )
        .scalars()
        .all()
    )
    human = Principal(
        user_id=approval.resolved_by_id,
        organization_id=organization_id,
        role=Role(membership.role),
    )
    agent_principal = Principal.for_agent(organization_id=organization_id, on_behalf_of=human)
    configured = SimpleNamespace(
        **{column.name: getattr(version, column.name) for column in version.__table__.columns},
        tools=assignments,
    )
    effective = resolve_effective_tools(
        agent_principal,
        configured,
        organization_tool_policy(organization),
    )
    tool = effective.tools.get(task.tool_name)
    if tool is None or tool.spec.version != task.tool_version:
        raise PermissionDeniedError("approved agent tool is no longer permitted")
    try:
        tool.spec.input_model.model_validate(task.input_payload)
    except ValueError as exc:
        raise ConflictError("approved agent task payload no longer matches its schema") from exc

    context = ApprovedTaskExecutionContext(
        organization_id=organization_id,
        run_id=task.run_id,
        task_id=task.id,
        approval_id=approval.id,
        agent_version_id=version.id,
        tool_name=task.tool_name,
        tool_version=task.tool_version,
        input_payload=dict(task.input_payload),
        idempotency_key=task.idempotency_key,
        principal=agent_principal,
        effective_tool=tool,
    )
    if manage_task_state:
        task.status = AgentTaskStatus.RUNNING.value
        task.started_at = task.started_at or utcnow()
    await session.flush()
    try:
        result = await provider(context)
    except Exception as exc:
        if manage_task_state:
            task.status = AgentTaskStatus.FAILED.value
            task.failure_code = type(exc).__name__
            task.failure_detail = "Approved provider execution failed."
            task.settled_at = utcnow()
        await session.flush()
        raise
    if manage_task_state:
        task.status = AgentTaskStatus.COMPLETED.value
        task.output_summary = {"approved_execution": True}
        task.settled_at = utcnow()
    await session.flush()
    return result


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
    result = enforce_task_postconditions(
        result,
        required=task.required,
        criteria=list(task.orchestration.get("success_criteria") or []),
    )
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
    run = (
        await session.execute(
            select(AgentRun)
            .where(
                AgentRun.id == claim.run_id,
                AgentRun.organization_id == claim.organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    input_tokens = max(0, int(result.usage.get("input_tokens", 0) or 0))
    output_tokens = max(0, int(result.usage.get("output_tokens", 0) or 0))
    tool_calls = max(0, int(result.usage.get("tool_calls", 0) or 0))
    spend_micros = max(0, int(result.usage.get("spend_micros", 0) or 0))
    if run is not None:
        run.total_input_tokens += input_tokens
        run.total_output_tokens += output_tokens
        run.tool_call_count += tool_calls
    from app.services.agent_budget import BudgetRequest, record_reserved_usage

    await record_reserved_usage(
        session,
        claim.organization_id,
        claim.run_id,
        actual=BudgetRequest(
            tasks=1,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            spend_micros=spend_micros,
        ),
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
        result = await _execute_with_heartbeat(
            claim,
            session_factory,
            handler,
            lease_seconds=lease_seconds,
        )
    except _TaskLeaseLost:
        return False
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
        await finalize_run_if_settled(
            schedule_session,
            claim.organization_id,
            claim.run_id,
        )
        await schedule_session.commit()
    return True


async def _execute_with_heartbeat(
    claim: TaskClaim,
    session_factory: async_sessionmaker[AsyncSession],
    handler: TaskHandler,
    *,
    lease_seconds: int,
) -> TaskExecutionResult:
    """Run a task while renewing its fenced lease in independent transactions."""

    execution = asyncio.create_task(handler(claim), name=f"agent-task-handler-{claim.task_id}")
    interval = max(0.25, min(float(lease_seconds) / 3.0, 30.0))
    try:
        while True:
            done, _ = await asyncio.wait({execution}, timeout=interval)
            if execution in done:
                return await execution
            async with session_factory() as heartbeat_session:
                owned = await heartbeat_task(
                    heartbeat_session,
                    claim,
                    lease_seconds=lease_seconds,
                )
                if owned:
                    await heartbeat_session.commit()
                else:
                    await heartbeat_session.rollback()
            if not owned:
                execution.cancel()
                await asyncio.gather(execution, return_exceptions=True)
                raise _TaskLeaseLost
    finally:
        if not execution.done():
            execution.cancel()
            await asyncio.gather(execution, return_exceptions=True)


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


async def recover_all_stale_tasks(
    session: AsyncSession,
    *,
    now: dt.datetime | None = None,
    organization_limit: int = 500,
) -> list[AgentTask]:
    """Recover expired task leases for every affected tenant in one maintenance pass."""

    if not 1 <= organization_limit <= 5_000:
        raise ValueError("organization_limit must be between 1 and 5000")
    timestamp = now or utcnow()
    organization_ids = list(
        (
            await session.execute(
                select(AgentTaskAttempt.organization_id)
                .where(
                    AgentTaskAttempt.status == AgentTaskAttemptStatus.RUNNING.value,
                    AgentTaskAttempt.leased_until <= timestamp,
                )
                .distinct()
                .order_by(AgentTaskAttempt.organization_id)
                .limit(organization_limit)
            )
        ).scalars()
    )
    recovered: list[AgentTask] = []
    for organization_id in organization_ids:
        recovered.extend(
            await recover_stale_tasks(
                session,
                organization_id,
                now=timestamp,
            )
        )
    return recovered


__all__ = [
    "ApprovedTaskExecutionContext",
    "ApprovedTaskProvider",
    "TaskClaim",
    "TaskEvidenceRecord",
    "TaskExecutionResult",
    "enforce_task_postconditions",
    "ResultVerification",
    "TaskHandler",
    "claim_task",
    "execute_approved_task",
    "organization_tool_policy",
    "execute_task",
    "heartbeat_task",
    "recover_all_stale_tasks",
    "recover_stale_tasks",
    "settle_task",
    "verify_task_result",
]
