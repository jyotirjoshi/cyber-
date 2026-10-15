"""Validation and deterministic identity for durable automation workflows."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import ConflictError, CynuxError, ResourceNotFoundError
from app.db.base import utcnow
from app.db.enums import Permission
from app.db.models.asset import Asset
from app.db.models.canonical import CanonicalFinding
from app.db.models.workflow import WorkflowDefinition, WorkflowRun, WorkflowStepRun
from app.db.repository import tenant_select
from app.schemas.workflow import WorkflowDefinitionIn, WorkflowNodeIn
from app.services.context import Principal
from app.services.scheduling import next_cron_time

_TRIGGERS = {
    "finding.created",
    "finding.updated",
    "ticket.closed",
    "retest.cleared",
    "sla.breached",
    "cron",
}
_CONDITIONS = {
    "severity_at_least",
    "asset_environment",
    "asset_criticality_at_least",
    "in_kev",
    "asset_group",
    "risk_score_at_least",
    "internet_exposed",
}
_ACTIONS = {
    "create_ticket",
    "notify",
    "request_retest",
    "schedule_retest",
    "assign_owner",
    "assign_codeowner",
    "set_remediation_group",
    "refresh_intelligence",
}


@dataclass(frozen=True, slots=True)
class ValidatedWorkflow:
    definition: WorkflowDefinitionIn
    topological_order: tuple[str, ...]


WorkflowActionExecutor = Callable[
    [str, dict[str, Any], dict[str, Any], str], Awaitable[dict[str, Any]]
]


def validate_workflow_graph(definition: WorkflowDefinitionIn) -> ValidatedWorkflow:
    """Reject executable content and return a stable DAG order."""
    nodes = {node.id: node for node in definition.nodes}
    if len(nodes) != len(definition.nodes):
        raise ValueError("workflow node ids must be unique")
    for node in definition.nodes:
        _validate_node(node)

    outgoing = {node_id: [] for node_id in nodes}
    indegree = {node_id: 0 for node_id in nodes}
    for edge in definition.edges:
        if edge.source not in nodes or edge.target not in nodes:
            raise ValueError("workflow edge references an unknown node")
        if edge.source == edge.target:
            raise ValueError("workflow must be acyclic")
        outgoing[edge.source].append(edge.target)
        indegree[edge.target] += 1

    triggers = [node.id for node in definition.nodes if node.type == "trigger"]
    if len(triggers) != 1:
        raise ValueError("workflow requires exactly one trigger node")
    trigger = triggers[0]
    trigger_indegree = indegree[trigger]

    queue = sorted(node_id for node_id, count in indegree.items() if count == 0)
    order: list[str] = []
    while queue:
        node_id = queue.pop(0)
        order.append(node_id)
        for target in sorted(outgoing[node_id]):
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
                queue.sort()
    if len(order) != len(nodes):
        raise ValueError("workflow must be acyclic")
    if trigger_indegree != 0:
        raise ValueError("trigger node cannot have an incoming edge")

    reachable = {trigger}
    frontier = [trigger]
    while frontier:
        current = frontier.pop()
        for target in outgoing[current]:
            if target not in reachable:
                reachable.add(target)
                frontier.append(target)
    if reachable != set(nodes):
        raise ValueError("workflow contains an orphan node")
    return ValidatedWorkflow(definition=definition, topological_order=tuple(order))


def _validate_node(node: WorkflowNodeIn) -> None:
    config = node.config
    if node.type == "trigger":
        _exact_keys(config, required={"event"}, optional={"cron_expression", "timezone"})
        if config["event"] not in _TRIGGERS:
            raise ValueError("unsupported workflow trigger")
        if config["event"] == "cron":
            expression = config.get("cron_expression")
            timezone = config.get("timezone", "UTC")
            if not isinstance(expression, str) or not expression.strip():
                raise ValueError("cron workflow requires cron_expression")
            if not isinstance(timezone, str) or not timezone.strip():
                raise ValueError("cron workflow requires timezone")
    elif node.type in {"condition", "branch"}:
        _exact_keys(config, required={"condition", "value"})
        if config["condition"] not in _CONDITIONS:
            raise ValueError("unsupported workflow condition")
    elif node.type == "enrichment":
        _exact_keys(config, required={"enrichment"})
        if config["enrichment"] != "refresh_intelligence":
            raise ValueError("unsupported workflow enrichment")
    elif node.type == "action":
        _exact_keys(
            config,
            required={"action"},
            optional={
                "provider",
                "channels",
                "assignee_user_id",
                "remediation_group",
                "authorization_reference",
            },
        )
        if config["action"] not in _ACTIONS:
            raise ValueError("unsupported workflow action")
    elif node.type == "delay":
        _exact_keys(config, required={"seconds"})
        seconds = config["seconds"]
        if (
            not isinstance(seconds, int)
            or isinstance(seconds, bool)
            or not 1 <= seconds <= 2_592_000
        ):
            raise ValueError("workflow delay must be between 1 and 2592000 seconds")
    elif node.type == "approval":
        _exact_keys(config, required={"label"}, optional={"timeout_seconds"})
        if not isinstance(config["label"], str) or not config["label"].strip():
            raise ValueError("workflow approval label is required")


def _exact_keys(
    config: dict[str, Any], *, required: set[str], optional: set[str] | None = None
) -> None:
    allowed = required | (optional or set())
    if not required.issubset(config) or set(config) - allowed:
        raise ValueError("workflow node configuration contains unsupported fields")


def step_idempotency_key(run_id: str, node_id: str, attempt: int) -> str:
    # Retries deliberately present the same key after a worker or provider timeout.
    _ = attempt
    material = f"{run_id}\x1f{node_id}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _safe_context(context: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(context, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode("utf-8")) > 65_536:
        raise ValueError("workflow context exceeds 64 KiB")
    sensitive = {"password", "secret", "token", "api_key", "apikey", "credential"}

    def inspect(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).lower() in sensitive:
                    raise ValueError("workflow context cannot contain credentials")
                inspect(child)
        elif isinstance(value, list):
            for child in value:
                inspect(child)

    inspect(context)
    return json.loads(encoded)


async def list_workflows(
    session: AsyncSession, principal: Principal, *, limit: int = 50, offset: int = 0
) -> tuple[list[WorkflowDefinition], int]:
    principal.require(Permission.ORG_READ)
    base = tenant_select(WorkflowDefinition, principal.organization_id)
    total = (
        await session.execute(
            select(func.count())
            .select_from(WorkflowDefinition)
            .where(WorkflowDefinition.organization_id == principal.organization_id)
        )
    ).scalar_one()
    rows = (
        (
            await session.execute(
                base.order_by(WorkflowDefinition.updated_at.desc(), WorkflowDefinition.id)
                .limit(max(1, min(limit, 100)))
                .offset(max(0, offset))
            )
        )
        .scalars()
        .all()
    )
    return list(rows), int(total)


async def get_workflow(
    session: AsyncSession, principal: Principal, workflow_id: uuid.UUID
) -> WorkflowDefinition:
    principal.require(Permission.ORG_READ)
    row = (
        await session.execute(
            tenant_select(WorkflowDefinition, principal.organization_id).where(
                WorkflowDefinition.id == workflow_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise ResourceNotFoundError("workflow not found")
    return row


async def create_workflow(
    session: AsyncSession, principal: Principal, body: WorkflowDefinitionIn
) -> WorkflowDefinition:
    principal.require(Permission.ORG_MANAGE)
    validated = validate_workflow_graph(body)
    trigger = next(node for node in body.nodes if node.type == "trigger")
    next_run_at = (
        next_cron_time(
            str(trigger.config["cron_expression"]),
            str(trigger.config.get("timezone", "UTC")),
            utcnow(),
        )
        if trigger.config["event"] == "cron"
        else None
    )
    row = WorkflowDefinition(
        organization_id=principal.organization_id,
        name=body.name,
        description=body.description,
        nodes=[node.model_dump(mode="json") for node in validated.definition.nodes],
        edges=[edge.model_dump(mode="json", exclude_none=True) for edge in body.edges],
        is_enabled=body.is_enabled,
        dry_run=body.dry_run,
        next_run_at=next_run_at,
        created_by_id=principal.user_id,
    )
    session.add(row)
    await session.flush()
    return row


async def update_workflow(
    session: AsyncSession,
    principal: Principal,
    workflow_id: uuid.UUID,
    body: WorkflowDefinitionIn,
) -> WorkflowDefinition:
    principal.require(Permission.ORG_MANAGE)
    row = await get_workflow(session, principal, workflow_id)
    validated = validate_workflow_graph(body)
    trigger = next(node for node in body.nodes if node.type == "trigger")
    row.name = body.name
    row.description = body.description
    row.nodes = [node.model_dump(mode="json") for node in validated.definition.nodes]
    row.edges = [edge.model_dump(mode="json", exclude_none=True) for edge in body.edges]
    row.is_enabled = body.is_enabled
    row.dry_run = body.dry_run
    row.next_run_at = (
        next_cron_time(
            str(trigger.config["cron_expression"]),
            str(trigger.config.get("timezone", "UTC")),
            utcnow(),
        )
        if trigger.config["event"] == "cron"
        else None
    )
    row.version += 1
    await session.flush()
    return row


async def delete_workflow(
    session: AsyncSession, principal: Principal, workflow_id: uuid.UUID
) -> None:
    principal.require(Permission.ORG_MANAGE)
    row = await get_workflow(session, principal, workflow_id)
    await session.delete(row)
    await session.flush()


async def list_workflow_runs(
    session: AsyncSession,
    principal: Principal,
    *,
    workflow_id: uuid.UUID | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[WorkflowRun], int]:
    principal.require(Permission.ORG_READ)
    filters = [WorkflowRun.organization_id == principal.organization_id]
    if workflow_id is not None:
        filters.append(WorkflowRun.workflow_id == workflow_id)
    total = (
        await session.execute(select(func.count()).select_from(WorkflowRun).where(*filters))
    ).scalar_one()
    rows = (
        (
            await session.execute(
                select(WorkflowRun)
                .where(*filters)
                .order_by(WorkflowRun.created_at.desc(), WorkflowRun.id.desc())
                .limit(max(1, min(limit, 100)))
                .offset(max(0, offset))
            )
        )
        .scalars()
        .all()
    )
    return list(rows), int(total)


async def get_workflow_run(
    session: AsyncSession, principal: Principal, run_id: uuid.UUID
) -> WorkflowRun:
    principal.require(Permission.ORG_READ)
    row = (
        await session.execute(
            tenant_select(WorkflowRun, principal.organization_id)
            .where(WorkflowRun.id == run_id)
            .options(selectinload(WorkflowRun.steps))
        )
    ).scalar_one_or_none()
    if row is None:
        raise ResourceNotFoundError("workflow run not found")
    return row


async def start_workflow(
    session: AsyncSession,
    principal: Principal,
    workflow_id: uuid.UUID,
    *,
    event_key: str,
    context: dict[str, Any],
    dry_run: bool | None = None,
) -> WorkflowRun:
    principal.require(Permission.FINDING_REMEDIATE)
    workflow = await get_workflow(session, principal, workflow_id)
    if not workflow.is_enabled:
        raise ConflictError("workflow is disabled")
    definition = WorkflowDefinitionIn(
        name=workflow.name,
        description=workflow.description,
        nodes=workflow.nodes,
        edges=workflow.edges,
        is_enabled=workflow.is_enabled,
        dry_run=workflow.dry_run,
    )
    validated = validate_workflow_graph(definition)
    trigger_node = next(node for node in definition.nodes if node.type == "trigger")
    existing = (
        await session.execute(
            tenant_select(WorkflowRun, principal.organization_id).where(
                WorkflowRun.workflow_id == workflow.id, WorkflowRun.event_key == event_key
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    run = WorkflowRun(
        organization_id=principal.organization_id,
        workflow_id=workflow.id,
        definition_version=workflow.version,
        definition=definition.model_dump(mode="json"),
        event_key=event_key,
        trigger=str(trigger_node.config["event"]),
        context=_safe_context(context),
        dry_run=workflow.dry_run if dry_run is None else dry_run,
    )
    session.add(run)
    await session.flush()
    node_by_id = {node.id: node for node in definition.nodes}
    for node_id in validated.topological_order:
        node = node_by_id[node_id]
        session.add(
            WorkflowStepRun(
                organization_id=principal.organization_id,
                run_id=run.id,
                node_id=node.id,
                node_type=node.type,
                idempotency_key=step_idempotency_key(str(run.id), node.id, 1),
                input=node.config,
            )
        )
    await session.flush()
    return run


def _condition_matches(config: dict[str, Any], context: dict[str, Any]) -> bool:
    condition, expected = config["condition"], config["value"]
    if condition == "severity_at_least":
        levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return levels.get(str(context.get("severity", "info")).lower(), -1) >= levels.get(
            str(expected).lower(), 99
        )
    key_map = {
        "asset_environment": "asset_environment",
        "asset_criticality_at_least": "asset_criticality",
        "in_kev": "in_kev",
        "asset_group": "asset_groups",
        "risk_score_at_least": "risk_score",
        "internet_exposed": "internet_exposed",
    }
    value = context.get(key_map[condition])
    if condition == "risk_score_at_least":
        return float(value or 0) >= float(expected)
    if condition == "asset_criticality_at_least":
        levels = {"low": 0, "normal": 1, "high": 2, "critical": 3}
        return levels.get(str(value).lower(), -1) >= levels.get(str(expected).lower(), 99)
    if condition == "asset_group":
        return str(expected) in set(value or [])
    return value == expected


def _edge_selected(edge: Any, source: WorkflowStepRun) -> bool:
    if source.status == "skipped":
        return False
    branch = edge.branch or "always"
    if branch == "always":
        return True
    return bool(source.output.get("result")) is (branch == "true")


async def resume_workflow(
    session: AsyncSession,
    principal: Principal,
    run_id: uuid.UUID,
    *,
    action_executor: WorkflowActionExecutor,
    now: Any | None = None,
) -> WorkflowRun:
    """Resume one run under a row lock; completed steps are never replayed."""
    principal.require(Permission.FINDING_REMEDIATE)
    current = now or utcnow()
    run = (
        await session.execute(
            tenant_select(WorkflowRun, principal.organization_id)
            .where(WorkflowRun.id == run_id)
            .options(selectinload(WorkflowRun.workflow), selectinload(WorkflowRun.steps))
            .with_for_update()
        )
    ).scalar_one_or_none()
    if run is None:
        raise ResourceNotFoundError("workflow run not found")
    if run.status in {"succeeded", "failed", "cancelled", "dry_run"}:
        return run
    definition = WorkflowDefinitionIn.model_validate(run.definition)
    validated = validate_workflow_graph(definition)
    nodes = {node.id: node for node in definition.nodes}
    steps = {step.node_id: step for step in run.steps}
    incoming = {node_id: [] for node_id in nodes}
    for edge in definition.edges:
        incoming[edge.target].append(edge)
    run.status = "running"
    run.started_at = run.started_at or current
    run.attempts += 1
    waiting = False
    terminal = {"succeeded", "skipped"}
    for node_id in validated.topological_order:
        step, node = steps[node_id], nodes[node_id]
        if step.status in terminal:
            continue
        predecessors = [steps[edge.source] for edge in incoming[node_id]]
        if any(source.status not in terminal for source in predecessors):
            waiting = True
            continue
        selected = not incoming[node_id] or any(
            _edge_selected(edge, steps[edge.source]) for edge in incoming[node_id]
        )
        if not selected:
            step.status = "skipped"
            step.completed_at = current
            continue
        if step.status == "waiting_approval":
            waiting = True
            continue
        if step.status == "waiting_delay":
            if step.available_at is not None and step.available_at > current:
                waiting = True
                continue
            step.status = "succeeded"
            step.completed_at = current
            continue
        if (
            step.status == "pending"
            and step.available_at is not None
            and step.available_at > current
        ):
            waiting = True
            continue
        step.status = "running"
        step.started_at = step.started_at or current
        try:
            if node.type == "trigger":
                output = {"event": node.config["event"]}
            elif node.type in {"condition", "branch"}:
                output = {"result": _condition_matches(node.config, run.context)}
            elif node.type == "delay":
                step.status = "waiting_delay"
                step.available_at = current + timedelta(seconds=int(node.config["seconds"]))
                run.next_resume_at = step.available_at
                waiting = True
                continue
            elif node.type == "approval":
                step.status = "waiting_approval"
                waiting = True
                continue
            else:
                action = (
                    str(node.config.get("action"))
                    if node.type == "action"
                    else str(node.config.get("enrichment"))
                )
                if run.dry_run:
                    output = {"dry_run": True, "action": action}
                else:
                    output = await action_executor(
                        action, node.config, run.context, step.idempotency_key
                    )
            step.output = output
            step.status = "succeeded"
            step.completed_at = current
            step.error_code = None
            step.error_detail = None
        except Exception as exc:
            step.attempt += 1
            step.error_code = getattr(exc, "code", "workflow_action_failed")
            step.error_detail = str(exc)[:500]
            retryable = isinstance(exc, CynuxError) and exc.retryable
            if retryable and step.attempt <= step.max_attempts:
                step.status = "pending"
                step.available_at = current + timedelta(seconds=min(300, 2**step.attempt * 5))
                run.next_resume_at = step.available_at
                waiting = True
                break
            step.status = "failed"
            run.status = "failed"
            run.error_code = step.error_code
            run.completed_at = current
            await session.flush()
            return run
    if all(step.status in terminal for step in steps.values()):
        run.status = "dry_run" if run.dry_run else "succeeded"
        run.completed_at = current
        run.next_resume_at = None
    elif waiting:
        run.status = "waiting"
    await session.flush()
    return run


async def approve_workflow_step(
    session: AsyncSession,
    principal: Principal,
    run_id: uuid.UUID,
    node_id: str,
) -> WorkflowStepRun:
    principal.require(Permission.ASSESSMENT_APPROVE)
    step = (
        await session.execute(
            tenant_select(WorkflowStepRun, principal.organization_id)
            .where(WorkflowStepRun.run_id == run_id, WorkflowStepRun.node_id == node_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if step is None:
        raise ResourceNotFoundError("workflow step not found")
    if step.status != "waiting_approval":
        raise ConflictError("workflow step is not waiting for approval")
    step.status = "succeeded"
    step.output = {"approved": True, "approved_by": str(principal.user_id)}
    step.completed_at = utcnow()
    await session.flush()
    return step


async def queue_finding_workflows(
    session: AsyncSession,
    *,
    finding: CanonicalFinding,
    asset: Asset,
    trigger: str,
    event_key_suffix: str = "",
) -> int:
    """Create at-most-one durable run for every enabled workflow matching an event."""
    if finding.organization_id != asset.organization_id:
        raise ValueError("finding and asset belong to different organizations")
    definitions = (
        await session.execute(
            tenant_select(WorkflowDefinition, finding.organization_id).where(
                WorkflowDefinition.is_enabled.is_(True)
            )
        )
    ).scalars().all()
    principal = Principal.for_system(organization_id=finding.organization_id)
    event_key = f"{trigger}:{finding.id}{event_key_suffix}"
    context = {
        "finding_id": str(finding.id),
        "asset_id": str(asset.id),
        "severity": finding.severity,
        "risk_score": float(finding.risk_score or 0),
        "in_kev": bool(finding.custom_fields.get("in_kev", False)),
        "asset_environment": asset.environment,
        "asset_criticality": asset.criticality,
        "asset_groups": list(asset.groups or []),
        "internet_exposed": asset.internet_exposed,
    }
    queued = 0
    for workflow in definitions:
        definition = WorkflowDefinitionIn(
            name=workflow.name,
            description=workflow.description,
            nodes=workflow.nodes,
            edges=workflow.edges,
            is_enabled=workflow.is_enabled,
            dry_run=workflow.dry_run,
        )
        trigger_node = next(
            (node for node in definition.nodes if node.type == "trigger"), None
        )
        if trigger_node is None or trigger_node.config.get("event") != trigger:
            continue
        existed = (
            await session.execute(
                tenant_select(WorkflowRun, finding.organization_id).where(
                    WorkflowRun.workflow_id == workflow.id,
                    WorkflowRun.event_key == event_key,
                )
            )
        ).scalar_one_or_none()
        if existed is not None:
            continue
        await start_workflow(
            session,
            principal,
            workflow.id,
            event_key=event_key,
            context=context,
        )
        queued += 1
    return queued


async def execute_due_workflows(
    session: AsyncSession,
    *,
    settings: Any,
    redis: Any | None,
    limit: int = 20,
) -> int:
    """Resume due workflow runs using tenant-bound system principals."""
    from app.services import automation as automation_service

    current = utcnow()
    due = (
        (
            await session.execute(
                select(WorkflowRun)
                .where(
                    WorkflowRun.status.in_(("pending", "waiting")),
                    or_(
                        WorkflowRun.status == "pending",
                        WorkflowRun.next_resume_at <= current,
                    ),
                )
                .order_by(WorkflowRun.created_at, WorkflowRun.id)
                .limit(max(1, min(limit, 100)))
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    for candidate in due:
        principal = Principal.for_system(organization_id=candidate.organization_id)

        async def execute_action(
            action: str,
            config: dict[str, Any],
            context: dict[str, Any],
            idempotency_key: str,
            *,
            _principal: Principal = principal,
        ) -> dict[str, Any]:
            raw_finding_id = context.get("finding_id")
            finding_id = uuid.UUID(str(raw_finding_id)) if raw_finding_id else None
            payload = {
                "type": action,
                **{key: value for key, value in config.items() if key != "action"},
            }
            return await automation_service.execute_declarative_action(
                session,
                _principal,
                finding_id=finding_id,
                action=payload,
                settings=settings,
                redis=redis,
                idempotency_key=idempotency_key,
            )

        await resume_workflow(
            session,
            principal,
            candidate.id,
            action_executor=execute_action,
            now=current,
        )
    return len(due)


async def queue_due_workflow_schedules(
    session: AsyncSession, *, now: Any | None = None, limit: int = 50
) -> int:
    """Materialize due cron workflows once and advance their durable schedule cursor."""
    current = now or utcnow()
    definitions = (
        (
            await session.execute(
                select(WorkflowDefinition)
                .where(
                    WorkflowDefinition.is_enabled.is_(True),
                    WorkflowDefinition.next_run_at.is_not(None),
                    WorkflowDefinition.next_run_at <= current,
                )
                .order_by(WorkflowDefinition.next_run_at, WorkflowDefinition.id)
                .limit(max(1, min(limit, 100)))
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    queued = 0
    for workflow in definitions:
        due_at = workflow.next_run_at
        if due_at is None:
            continue
        definition = WorkflowDefinitionIn(
            name=workflow.name,
            description=workflow.description,
            nodes=workflow.nodes,
            edges=workflow.edges,
            is_enabled=workflow.is_enabled,
            dry_run=workflow.dry_run,
        )
        trigger = next(node for node in definition.nodes if node.type == "trigger")
        if trigger.config.get("event") != "cron":
            workflow.next_run_at = None
            continue
        principal = Principal.for_system(organization_id=workflow.organization_id)
        await start_workflow(
            session,
            principal,
            workflow.id,
            event_key=f"cron:{workflow.id}:{due_at.isoformat()}",
            context={"scheduled_at": due_at.isoformat()},
        )
        workflow.next_run_at = next_cron_time(
            str(trigger.config["cron_expression"]),
            str(trigger.config.get("timezone", "UTC")),
            due_at,
        )
        queued += 1
    return queued


__all__ = [
    "ValidatedWorkflow",
    "WorkflowActionExecutor",
    "approve_workflow_step",
    "create_workflow",
    "delete_workflow",
    "execute_due_workflows",
    "get_workflow",
    "get_workflow_run",
    "list_workflow_runs",
    "list_workflows",
    "queue_finding_workflows",
    "queue_due_workflow_schedules",
    "resume_workflow",
    "start_workflow",
    "step_idempotency_key",
    "update_workflow",
    "validate_workflow_graph",
]
