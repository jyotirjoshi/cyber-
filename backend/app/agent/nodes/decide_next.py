"""Adaptive supervisor node constrained by live approval and durable evidence."""

from __future__ import annotations

import datetime as dt
import json
import uuid
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from app.agent.nodes._common import principal_from, record_step
from app.agent.nodes.scan import approved_scan_jobs
from app.agent.registry import AgentDeps
from app.agent.state import AssessmentState, state_uuid
from app.core.errors import AIError
from app.db.models.agent import AgentDecision, AgentRun, AgentSpecialistTask
from app.db.repository import tenant_select
from app.db.session import session_scope
from app.llm.base import LLMMessage
from app.services.agent_planner import DecisionCandidate, propose_next_actions

log = structlog.get_logger(__name__)

_NODE = "decide_next"


class PlannerProposal(BaseModel):
    """Strict model output; deterministic policy still decides what may execute."""

    model_config = ConfigDict(extra="forbid", strict=True)

    hypothesis: str = Field(default="", max_length=4_000)
    actions: list[DecisionCandidate] = Field(default_factory=list, max_length=12)
    coverage_complete: bool = False
    stop_reason: str | None = Field(default=None, max_length=200)


async def decide_next(state: AssessmentState, *, deps: AgentDeps) -> dict[str, object]:
    """Select a bounded follow-up round, or terminate adaptation with an explanation."""
    round_number = int(state.get("adaptive_rounds") or 0)
    principal = principal_from(state)
    provider_degraded = False

    async with record_step(
        deps,
        state,
        node=_NODE,
        stage=None,
        label="Reviewing evidence and deciding the next specialist actions",
        tool_name="adaptive_supervisor",
    ) as step:
        async with session_scope(deps.settings) as session:
            run = (
                await session.execute(
                    planning_run_query(
                        state_uuid(state, "organization_id"), state_uuid(state, "run_id")
                    )
                )
            ).scalar_one_or_none()
            tasks = list(
                (
                    await session.scalars(
                        select(AgentSpecialistTask)
                        .where(
                            AgentSpecialistTask.organization_id
                            == state_uuid(state, "organization_id"),
                            AgentSpecialistTask.run_id == state_uuid(state, "run_id"),
                        )
                        .order_by(AgentSpecialistTask.plan_index, AgentSpecialistTask.id)
                    )
                ).all()
            )
            approved_jobs = await approved_scan_jobs(session, state, deps.settings)

        elapsed = 0
        if run is not None and run.started_at is not None:
            elapsed = max(0, int((dt.datetime.now(dt.UTC) - run.started_at).total_seconds()))
        budget_reason = _budget_stop_reason(round_number, elapsed, deps)
        allowed_tools = {scanner.value for scanner, _ in approved_jobs}
        allowed_targets = {target for _, targets in approved_jobs for target in targets}
        evidence = _evidence_summary(tasks)

        proposal = PlannerProposal(coverage_complete=True, stop_reason=budget_reason)
        if budget_reason is None and allowed_tools and allowed_targets:
            proposal, provider_degraded = await planner_proposal_or_stop(
                deps.gateway,
                [
                        LLMMessage(
                            role="system",
                            content=(
                                "You are the bounded security assessment supervisor. Choose only "
                                "from the provided tools and exact targets. Propose follow-up work "
                                "only when the evidence supports a new hypothesis. Never request a "
                                "shell, exploit payload, credential use, persistence, destructive "
                                "action, or a target not listed. Set coverage_complete=true when no "
                                "new evidence-producing action is justified."
                            ),
                        ),
                        LLMMessage(
                            role="user",
                            content=json.dumps(
                                {
                                    "round": round_number + 1,
                                    "allowed_tools": sorted(allowed_tools),
                                    "allowed_targets": sorted(allowed_targets)[:500],
                                    "evidence": evidence,
                                },
                                ensure_ascii=True,
                                separators=(",", ":"),
                            ),
                        ),
                ],
            )

        candidates = [] if proposal.coverage_complete else proposal.actions
        async with session_scope(deps.settings) as session:
            batch = await propose_next_actions(
                session,
                principal,
                state_uuid(state, "run_id"),
                candidates=list(candidates),
                allowed_tools=allowed_tools,
                allowed_targets=allowed_targets,
                hypothesis=proposal.hypothesis,
                input_evidence_ids=[str(task.id) for task in tasks],
                max_actions=deps.settings.agent.adaptive_max_actions_per_round,
                max_rounds=deps.settings.agent.adaptive_max_rounds,
            )
            if provider_degraded and batch.decision_id is not None:
                decision = await session.get(AgentDecision, batch.decision_id)
                if decision is not None:
                    decision.status = "degraded"
                    decision.stop_reason = proposal.stop_reason

        stop_reason = proposal.stop_reason or batch.stop_reason
        actions = [action.model_dump(mode="json") for action in batch.actions]
        step.record_output(
            {
                "round": round_number + 1,
                "evidence_items": len(evidence),
                "accepted_actions": len(actions),
                "rejected_actions": len(batch.rejections),
                "stop_reason": stop_reason,
            }
        )
        if provider_degraded:
            step.degrade("Adaptive planning was skipped because the configured model was unavailable.")

    return {
        "adaptive_actions": actions,
        "adaptive_rounds": round_number + 1,
        "adaptive_stop_reason": stop_reason,
    }


def _budget_stop_reason(round_number: int, elapsed_seconds: int, deps: AgentDeps) -> str | None:
    if round_number >= deps.settings.agent.adaptive_max_rounds:
        return "decision_budget_exhausted"
    if elapsed_seconds >= deps.settings.agent.adaptive_max_elapsed_seconds:
        return "time_budget_exhausted"
    return None


def planning_run_query(organization_id: uuid.UUID, run_id: uuid.UUID):
    """Build the tenant-filtered supervisor run lookup used by the node."""
    return tenant_select(AgentRun, organization_id).where(AgentRun.id == run_id)


async def planner_proposal_or_stop(
    gateway: Any, messages: list[LLMMessage]
) -> tuple[PlannerProposal, bool]:
    """Convert a provider failure into an explicit, non-looping degraded decision."""
    try:
        proposal = await gateway.complete_json(
            "planning",
            messages,
            schema=PlannerProposal.model_json_schema(),
            model_cls=PlannerProposal,
        )
    except AIError as exc:
        log.warning("agent.adaptive_planner.degraded", error=exc.code)
        return (
            PlannerProposal(
                coverage_complete=True,
                stop_reason="planning_provider_unavailable",
            ),
            True,
        )
    return proposal, False


def _evidence_summary(tasks: list[AgentSpecialistTask]) -> list[dict[str, object]]:
    return [
        {
            "evidence_id": str(task.id),
            "specialist": task.specialist,
            "scanner": task.scanner,
            "status": task.status,
            "artifact_count": int((task.evidence or {}).get("artifact_count") or 0),
            "imported_finding_count": int(
                (task.evidence or {}).get("imported_finding_count") or 0
            ),
            "failure_code": task.failure_code,
        }
        for task in tasks[:100]
    ]


__all__ = [
    "PlannerProposal",
    "decide_next",
    "planner_proposal_or_stop",
    "planning_run_query",
]
