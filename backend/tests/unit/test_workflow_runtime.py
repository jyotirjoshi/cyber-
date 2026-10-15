"""Safety and recovery contracts for durable automation workflows."""

from __future__ import annotations

import uuid

import pytest

from app.db.enums import Role
from app.db.models.workflow import WorkflowDefinition, WorkflowRun, WorkflowStepRun
from app.schemas.workflow import WorkflowDefinitionIn
from app.services.context import Principal
from app.services.workflow import resume_workflow, step_idempotency_key, validate_workflow_graph


def _definition(*, nodes: list[dict], edges: list[dict]) -> WorkflowDefinitionIn:
    return WorkflowDefinitionIn(name="Critical remediation", nodes=nodes, edges=edges)


def test_cycle_is_rejected() -> None:
    graph = _definition(
        nodes=[
            {"id": "trigger", "type": "trigger", "config": {"event": "finding.created"}},
            {"id": "notify", "type": "action", "config": {"action": "notify"}},
        ],
        edges=[
            {"source": "trigger", "target": "notify"},
            {"source": "notify", "target": "trigger"},
        ],
    )

    with pytest.raises(ValueError, match="acyclic"):
        validate_workflow_graph(graph)


def test_orphan_unknown_reference_and_arbitrary_code_are_rejected() -> None:
    with pytest.raises(ValueError, match="orphan"):
        validate_workflow_graph(
            _definition(
                nodes=[
                    {
                        "id": "trigger",
                        "type": "trigger",
                        "config": {
                            "event": "cron",
                            "cron_expression": "0 9 * * *",
                            "timezone": "UTC",
                        },
                    },
                    {"id": "unused", "type": "delay", "config": {"seconds": 30}},
                ],
                edges=[],
            )
        )
    with pytest.raises(ValueError, match="unknown node"):
        validate_workflow_graph(
            _definition(
                nodes=[
                    {
                        "id": "trigger",
                        "type": "trigger",
                        "config": {
                            "event": "cron",
                            "cron_expression": "0 9 * * *",
                            "timezone": "UTC",
                        },
                    }
                ],
                edges=[{"source": "trigger", "target": "missing"}],
            )
        )
    with pytest.raises(ValueError):
        WorkflowDefinitionIn.model_validate(
            {
                "name": "Unsafe",
                "nodes": [
                    {
                        "id": "trigger",
                        "type": "code",
                        "config": {"script": "fetch('https://evil.example')"},
                    }
                ],
                "edges": [],
            }
        )


def test_valid_graph_has_stable_topological_order_and_step_key() -> None:
    graph = _definition(
        nodes=[
            {"id": "trigger", "type": "trigger", "config": {"event": "finding.created"}},
            {
                "id": "critical",
                "type": "condition",
                "config": {"condition": "severity_at_least", "value": "critical"},
            },
            {"id": "ticket", "type": "action", "config": {"action": "create_ticket"}},
        ],
        edges=[
            {"source": "trigger", "target": "critical"},
            {"source": "critical", "target": "ticket", "branch": "true"},
        ],
    )

    validated = validate_workflow_graph(graph)

    assert validated.topological_order == ("trigger", "critical", "ticket")
    assert step_idempotency_key("run-1", "ticket", 1) == step_idempotency_key("run-1", "ticket", 1)
    assert step_idempotency_key("run-1", "ticket", 1) == step_idempotency_key("run-1", "ticket", 2)


class _Scalars:
    def __init__(self, value: WorkflowRun) -> None:
        self.value = value

    def scalar_one_or_none(self) -> WorkflowRun:
        return self.value


class _Session:
    def __init__(self, value: WorkflowRun) -> None:
        self.value = value

    async def execute(self, _statement: object) -> _Scalars:
        return _Scalars(self.value)

    async def flush(self) -> None:
        return None


@pytest.mark.asyncio
async def test_resume_never_replays_succeeded_side_effects() -> None:
    organization_id = uuid.uuid4()
    workflow_id = uuid.uuid4()
    run_id = uuid.uuid4()
    definition = _definition(
        nodes=[
            {"id": "trigger", "type": "trigger", "config": {"event": "finding.created"}},
            {"id": "notify", "type": "action", "config": {"action": "notify"}},
        ],
        edges=[{"source": "trigger", "target": "notify"}],
    )
    workflow = WorkflowDefinition(
        id=workflow_id,
        organization_id=organization_id,
        name=definition.name,
        version=1,
        nodes=[node.model_dump() for node in definition.nodes],
        edges=[edge.model_dump(exclude_none=True) for edge in definition.edges],
    )
    run = WorkflowRun(
        id=run_id,
        organization_id=organization_id,
        workflow_id=workflow_id,
        definition_version=1,
        definition=definition.model_dump(mode="json"),
        event_key="finding.created:123",
        trigger="finding.created",
        context={"finding_id": str(uuid.uuid4())},
        attempts=0,
        workflow=workflow,
        steps=[
            WorkflowStepRun(
                organization_id=organization_id,
                node_id=node_id,
                node_type=node_type,
                status="succeeded",
                idempotency_key=step_idempotency_key(str(run_id), node_id, 1),
                output={"already": "done"},
            )
            for node_id, node_type in (("trigger", "trigger"), ("notify", "action"))
        ],
    )
    calls: list[str] = []

    async def execute(action: str, *_args: object) -> dict[str, str]:
        calls.append(action)
        return {"type": action}

    resumed = await resume_workflow(
        _Session(run),  # type: ignore[arg-type]
        Principal(user_id=uuid.uuid4(), organization_id=organization_id, role=Role.ADMIN),
        run_id,
        action_executor=execute,  # type: ignore[arg-type]
    )

    assert calls == []
    assert resumed.status == "succeeded"
