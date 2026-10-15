"""Policy tests for evidence-driven adaptive agent decisions."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import CheckConstraint, UniqueConstraint

from app.agent.graph import build_graph, route_after_decision
from app.agent.nodes.decide_next import planner_proposal_or_stop, planning_run_query
from app.core.config import AgentSettings
from app.core.errors import ModelUnavailableError, ResourceNotFoundError
from app.db.enums import Role
from app.db.models.agent import AgentDecision
from app.services.agent_planner import (
    DecisionCandidate,
    choose_actions,
    decision_fingerprint,
    match_approved_jobs,
    propose_next_actions,
    validate_decision,
)
from app.services.context import Principal

RUN_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")


def test_unknown_or_out_of_scope_tool_is_rejected() -> None:
    result = validate_decision(
        candidate={"tool": "shell", "targets": ["other.example"]},
        allowed_tools={"nuclei"},
        allowed_targets={"app.example"},
    )

    assert result.accepted is False
    assert result.reason_code == "policy_rejected"
    assert set(result.violations) == {"unknown_tool", "out_of_scope_target"}


def test_completed_fingerprint_is_not_dispatched_twice() -> None:
    candidate = DecisionCandidate(tool="nuclei", targets=["app.example"])
    completed = {decision_fingerprint(RUN_ID, candidate)}

    batch = choose_actions(
        run_id=RUN_ID,
        candidates=[candidate],
        allowed_tools={"nuclei"},
        allowed_targets={"app.example"},
        completed_fingerprints=completed,
        max_actions=3,
    )

    assert batch.actions == ()
    assert batch.stop_reason == "no_new_actions"
    assert batch.rejections[0].reason_code == "already_completed"


def test_fingerprint_is_order_independent_and_includes_parameters() -> None:
    first = DecisionCandidate(
        tool="nuclei",
        targets=["b.example", "a.example", "a.example"],
        parameters={"tags": ["cve", "misconfig"], "rate_limit": 20},
    )
    reordered = DecisionCandidate(
        tool="nuclei",
        targets=["a.example", "b.example"],
        parameters={"rate_limit": 20, "tags": ["cve", "misconfig"]},
    )
    changed = DecisionCandidate(
        tool="nuclei",
        targets=["a.example", "b.example"],
        parameters={"rate_limit": 5, "tags": ["cve", "misconfig"]},
    )

    assert decision_fingerprint(RUN_ID, first) == decision_fingerprint(RUN_ID, reordered)
    assert decision_fingerprint(RUN_ID, first) != decision_fingerprint(RUN_ID, changed)
    assert "example" not in decision_fingerprint(RUN_ID, first)


def test_action_budget_is_enforced_deterministically() -> None:
    batch = choose_actions(
        run_id=RUN_ID,
        candidates=[
            DecisionCandidate(tool="nuclei", targets=["app.example"]),
            DecisionCandidate(tool="zap", targets=["app.example"]),
        ],
        allowed_tools={"nuclei", "zap"},
        allowed_targets={"app.example"},
        completed_fingerprints=set(),
        max_actions=1,
    )

    assert [action.tool for action in batch.actions] == ["nuclei"]
    assert batch.rejections[0].reason_code == "action_budget_exhausted"


def test_adaptive_jobs_are_intersected_with_scanner_specific_approval() -> None:
    selected = match_approved_jobs(
        actions=(
            DecisionCandidate(tool="nuclei", targets=["a.example"]),
            DecisionCandidate(tool="zap", targets=["a.example", "cloud:account"]),
        ),
        approved_jobs=(
            ("nuclei", ["a.example", "b.example"]),
            ("zap", ["a.example"]),
        ),
    )

    assert selected == (("nuclei", ["a.example"]),)


def test_empty_or_malformed_candidate_fails_closed() -> None:
    empty = validate_decision(
        candidate={"tool": "nuclei", "targets": []},
        allowed_tools={"nuclei"},
        allowed_targets={"app.example"},
    )
    malformed = validate_decision(
        candidate={"tool": "nuclei", "targets": "app.example"},
        allowed_tools={"nuclei"},
        allowed_targets={"app.example"},
    )

    assert empty.accepted is False
    assert empty.reason_code == "invalid_candidate"
    assert malformed.accepted is False
    assert malformed.reason_code == "invalid_candidate"


def test_agent_decision_is_a_durable_ordered_run_record() -> None:
    table = AgentDecision.__table__

    assert {
        "organization_id",
        "run_id",
        "sequence",
        "hypothesis",
        "candidate_actions",
        "accepted_actions",
        "rejections",
        "input_evidence_ids",
        "status",
        "stop_reason",
    } <= set(table.columns.keys())
    assert any(
        isinstance(constraint, UniqueConstraint)
        and {column.name for column in constraint.columns} == {"run_id", "sequence"}
        for constraint in table.constraints
    )
    checks = {
        constraint.name
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }
    assert "ck_agent_decisions_valid_agent_decision_sequence" in checks
    assert "ck_agent_decisions_valid_agent_decision_status" in checks


def test_planning_run_lookup_is_tenant_scoped() -> None:
    org_id = uuid.UUID("33333333-3333-4333-8333-333333333333")
    statement = planning_run_query(org_id, RUN_ID)

    where = str(statement.whereclause)
    assert "agent_runs.organization_id" in where
    assert "agent_runs.id" in where


@pytest.mark.asyncio
async def test_planning_provider_failure_stops_adaptation_as_degraded() -> None:
    class _UnavailableGateway:
        async def complete_json(self, *args, **kwargs):
            raise ModelUnavailableError("provider timeout")

    proposal, degraded = await planner_proposal_or_stop(_UnavailableGateway(), [])

    assert degraded is True
    assert proposal.coverage_complete is True
    assert proposal.actions == []
    assert proposal.stop_reason == "planning_provider_unavailable"


class _Result:
    def __init__(self, value: object | None) -> None:
        self.value = value

    def scalar_one_or_none(self) -> object | None:
        return self.value


class _Scalars:
    def __init__(self, values: list[object]) -> None:
        self.values = values

    def all(self) -> list[object]:
        return self.values


class _PlannerSession:
    def __init__(self, run: object | None, decisions: list[object] | None = None) -> None:
        self.run = run
        self.decisions = decisions or []
        self.statement = None
        self.added: AgentDecision | None = None

    async def execute(self, statement):
        self.statement = statement
        return _Result(self.run)

    async def scalars(self, statement):
        return _Scalars(self.decisions)

    def add(self, value: AgentDecision) -> None:
        self.added = value

    async def flush(self) -> None:
        if self.added is not None and self.added.id is None:
            self.added.id = uuid.UUID("22222222-2222-4222-8222-222222222222")


def _principal(organization_id: uuid.UUID) -> Principal:
    return Principal(user_id=uuid.uuid4(), organization_id=organization_id, role=Role.OWNER)


@pytest.mark.asyncio
async def test_proposal_lookup_is_tenant_scoped_and_hides_foreign_run() -> None:
    org_id = uuid.UUID("33333333-3333-4333-8333-333333333333")
    session = _PlannerSession(run=None)

    with pytest.raises(ResourceNotFoundError):
        await propose_next_actions(
            session,
            _principal(org_id),
            RUN_ID,
            candidates=[DecisionCandidate(tool="nuclei", targets=["app.example"])],
            allowed_tools={"nuclei"},
            allowed_targets={"app.example"},
        )

    where = str(session.statement.whereclause)
    assert "agent_runs.organization_id" in where
    assert "agent_runs.id" in where


@pytest.mark.asyncio
async def test_proposal_is_persisted_with_dispatch_fingerprint() -> None:
    org_id = uuid.UUID("33333333-3333-4333-8333-333333333333")
    run = SimpleNamespace(id=RUN_ID, organization_id=org_id)
    session = _PlannerSession(run=run)

    batch = await propose_next_actions(
        session,
        _principal(org_id),
        RUN_ID,
        candidates=[DecisionCandidate(tool="nuclei", targets=["app.example"])],
        allowed_tools={"nuclei"},
        allowed_targets={"app.example"},
        hypothesis="The exposed HTTP service may have a known vulnerable template.",
        input_evidence_ids=["artifact:one"],
    )

    assert batch.decision_id == uuid.UUID("22222222-2222-4222-8222-222222222222")
    assert batch.sequence == 1
    assert session.added is not None
    assert session.added.status == "dispatched"
    assert session.added.input_evidence_ids == ["artifact:one"]
    assert session.added.accepted_actions[0]["fingerprint"] == batch.fingerprints[0]


def test_decision_router_runs_only_accepted_adaptive_actions() -> None:
    assert route_after_decision({"adaptive_actions": []}) == "enrich_intelligence"
    assert (
        route_after_decision(
            {"adaptive_actions": [{"tool": "nuclei", "targets": ["app.example"]}]}
        )
        == "execute_adaptive_scanners"
    )


def test_adaptive_loop_has_bounded_configurable_budgets() -> None:
    settings = AgentSettings()

    assert settings.adaptive_max_rounds == 3
    assert settings.adaptive_max_actions_per_round == 3
    assert settings.adaptive_max_elapsed_seconds == 7_200


def test_assessment_graph_compiles_with_bounded_adaptive_loop() -> None:
    compiled = build_graph(None)  # type: ignore[arg-type]
    edges = {(edge.source, edge.target) for edge in compiled.get_graph().edges}

    assert ("verify_specialists", "decide_next") in edges
    assert ("decide_next", "execute_adaptive_scanners") in edges
    assert ("decide_next", "enrich_intelligence") in edges
    assert ("execute_adaptive_scanners", "import_findings") in edges
