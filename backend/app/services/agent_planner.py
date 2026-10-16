"""Deterministic policy boundary for model-proposed assessment actions.

The model may suggest a scanner and targets, but this module decides whether that
suggestion can become work.  It deliberately has no network or LLM dependency so the
same validation runs when a fresh proposal is received and when a worker resumes.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, replace
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.agent import AgentDecision, AgentRun
from app.db.repository import tenant_select
from app.services.agent_supervisor import decide_next_wave, plan_objective
from app.services.context import Principal


class DecisionCandidate(BaseModel):
    """A bounded scanner action parsed from untrusted planner output."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    tool: str = Field(min_length=1, max_length=40)
    targets: list[str] = Field(min_length=1, max_length=100)
    parameters: dict[str, Any] = Field(default_factory=dict)
    rationale: str | None = Field(default=None, max_length=1_000)

    @field_validator("targets")
    @classmethod
    def normalize_targets(cls, values: list[str]) -> list[str]:
        normalized = sorted({value.strip() for value in values if value.strip()})
        if not normalized:
            raise ValueError("at least one non-empty target is required")
        return normalized


@dataclass(frozen=True, slots=True)
class DecisionValidation:
    accepted: bool
    reason_code: str
    violations: tuple[str, ...] = ()
    action: DecisionCandidate | None = None


@dataclass(frozen=True, slots=True)
class DecisionRejection:
    reason_code: str
    violations: tuple[str, ...]
    tool: str | None = None


@dataclass(frozen=True, slots=True)
class DecisionBatch:
    actions: tuple[DecisionCandidate, ...]
    rejections: tuple[DecisionRejection, ...]
    fingerprints: tuple[str, ...]
    stop_reason: str | None = None
    decision_id: uuid.UUID | None = None
    sequence: int | None = None


def validate_decision(
    *,
    candidate: DecisionCandidate | dict[str, Any],
    allowed_tools: set[str] | frozenset[str],
    allowed_targets: set[str] | frozenset[str],
) -> DecisionValidation:
    """Fail closed unless the proposal is well formed and wholly allow-listed."""
    try:
        parsed = (
            candidate
            if isinstance(candidate, DecisionCandidate)
            else DecisionCandidate.model_validate(candidate)
        )
    except (ValidationError, TypeError, ValueError):
        return DecisionValidation(accepted=False, reason_code="invalid_candidate")

    violations: list[str] = []
    if parsed.tool not in allowed_tools:
        violations.append("unknown_tool")
    if any(target not in allowed_targets for target in parsed.targets):
        violations.append("out_of_scope_target")
    if violations:
        return DecisionValidation(
            accepted=False,
            reason_code="policy_rejected",
            violations=tuple(violations),
            action=parsed,
        )
    return DecisionValidation(accepted=True, reason_code="accepted", action=parsed)


def decision_fingerprint(run_id: uuid.UUID, candidate: DecisionCandidate) -> str:
    """Hash the complete executable intent without persisting targets in the key."""
    material = {
        "run_id": str(run_id),
        "tool": candidate.tool,
        "targets": sorted(set(candidate.targets)),
        "parameters": candidate.parameters,
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def choose_actions(
    *,
    run_id: uuid.UUID,
    candidates: list[DecisionCandidate | dict[str, Any]],
    allowed_tools: set[str] | frozenset[str],
    allowed_targets: set[str] | frozenset[str],
    completed_fingerprints: set[str] | frozenset[str],
    max_actions: int,
) -> DecisionBatch:
    """Select novel allowed work in proposal order under a hard action budget."""
    accepted: list[DecisionCandidate] = []
    fingerprints: list[str] = []
    rejections: list[DecisionRejection] = []
    seen = set(completed_fingerprints)

    for raw in candidates:
        validation = validate_decision(
            candidate=raw,
            allowed_tools=allowed_tools,
            allowed_targets=allowed_targets,
        )
        tool = validation.action.tool if validation.action is not None else None
        if not validation.accepted or validation.action is None:
            rejections.append(
                DecisionRejection(validation.reason_code, validation.violations, tool=tool)
            )
            continue

        fingerprint = decision_fingerprint(run_id, validation.action)
        if fingerprint in seen:
            rejections.append(DecisionRejection("already_completed", (), tool=tool))
            continue
        if len(accepted) >= max(0, max_actions):
            rejections.append(DecisionRejection("action_budget_exhausted", (), tool=tool))
            continue

        seen.add(fingerprint)
        accepted.append(validation.action)
        fingerprints.append(fingerprint)

    return DecisionBatch(
        actions=tuple(accepted),
        rejections=tuple(rejections),
        fingerprints=tuple(fingerprints),
        stop_reason="no_new_actions" if not accepted else None,
    )


def match_approved_jobs(
    *,
    actions: tuple[DecisionCandidate, ...] | list[DecisionCandidate],
    approved_jobs: tuple[tuple[str, list[str]], ...] | list[tuple[str, list[str]]],
) -> tuple[tuple[str, list[str]], ...]:
    """Return only actions wholly contained in the scanner-specific live scope.

    Partial narrowing is intentionally rejected. If a model mixes an approved web
    target with an incompatible cloud target, silently dropping one would execute a
    different action from the one reviewed and fingerprinted.
    """
    approved = {tool: frozenset(targets) for tool, targets in approved_jobs}
    selected: list[tuple[str, list[str]]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for action in actions:
        permitted = approved.get(action.tool)
        targets = tuple(sorted(set(action.targets)))
        key = (action.tool, targets)
        if not targets or permitted is None or not set(targets).issubset(permitted) or key in seen:
            continue
        seen.add(key)
        selected.append((action.tool, list(targets)))
    return tuple(selected)


async def propose_next_actions(
    session: AsyncSession,
    principal: Principal,
    run_id: uuid.UUID,
    *,
    candidates: list[DecisionCandidate | dict[str, Any]] | None = None,
    allowed_tools: set[str] | frozenset[str] | None = None,
    allowed_targets: set[str] | frozenset[str] | None = None,
    hypothesis: str | None = None,
    input_evidence_ids: list[str] | tuple[str, ...] = (),
    max_actions: int = 3,
    max_rounds: int = 6,
) -> DecisionBatch:
    """Validate and durably record one tenant-scoped supervisor decision.

    The accepted action fingerprint is persisted in the same transaction as the
    decision. A resumed worker therefore treats it as already dispatched and relies on
    the specialist task/job idempotency path to recover the work rather than proposing
    the same side effect again.
    """
    principal.require(Permission.ASSESSMENT_CREATE)
    run = (
        await session.execute(
            tenant_select(AgentRun, principal.organization_id).where(AgentRun.id == run_id)
        )
    ).scalar_one_or_none()
    if run is None:
        raise ResourceNotFoundError("Agent run not found")

    previous = list(
        (
            await session.scalars(
                tenant_select(AgentDecision, principal.organization_id)
                .where(AgentDecision.run_id == run_id)
                .order_by(AgentDecision.sequence)
            )
        ).all()
    )
    if previous and previous[-1].status in {"stopped", "degraded"}:
        terminal = previous[-1]
        return DecisionBatch(
            actions=(),
            rejections=(),
            fingerprints=(),
            stop_reason=terminal.stop_reason or terminal.status,
            decision_id=terminal.id,
            sequence=terminal.sequence,
        )

    known_fingerprints = {
        str(action.get("fingerprint"))
        for decision in previous
        for action in (decision.accepted_actions or [])
        if isinstance(action, dict) and action.get("fingerprint")
    }
    sequence = max((int(decision.sequence) for decision in previous), default=0) + 1
    round_budget_exhausted = sequence > max(1, max_rounds)
    batch = choose_actions(
        run_id=run_id,
        candidates=list(candidates or []),
        allowed_tools=frozenset(allowed_tools or ()),
        allowed_targets=frozenset(allowed_targets or ()),
        completed_fingerprints=known_fingerprints,
        max_actions=0 if round_budget_exhausted else max_actions,
    )
    if round_budget_exhausted:
        batch = replace(batch, stop_reason="decision_budget_exhausted")

    accepted_actions = [
        {
            **action.model_dump(mode="json"),
            "fingerprint": fingerprint,
        }
        for action, fingerprint in zip(batch.actions, batch.fingerprints, strict=True)
    ]
    row = AgentDecision(
        organization_id=principal.organization_id,
        run_id=run_id,
        sequence=sequence,
        hypothesis=(hypothesis or "").strip()[:4_000] or None,
        candidate_actions=[
            candidate.model_dump(mode="json")
            if isinstance(candidate, DecisionCandidate)
            else _bounded_candidate(candidate)
            for candidate in (candidates or [])[:20]
        ],
        accepted_actions=accepted_actions,
        rejections=[
            {
                "reason_code": rejection.reason_code,
                "violations": list(rejection.violations),
                "tool": rejection.tool,
            }
            for rejection in batch.rejections
        ],
        input_evidence_ids=[str(value)[:200] for value in input_evidence_ids[:100]],
        status="dispatched" if batch.actions else "stopped",
        stop_reason=batch.stop_reason,
    )
    session.add(row)
    await session.flush()
    return replace(batch, decision_id=row.id, sequence=sequence)


def _bounded_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    """Keep rejected model output reviewable without persisting an unbounded blob."""
    return {
        "tool": str(candidate.get("tool") or "")[:40],
        "targets": [str(value)[:500] for value in candidate.get("targets", [])[:100]]
        if isinstance(candidate.get("targets"), list)
        else [],
        "parameters": candidate.get("parameters", {})
        if isinstance(candidate.get("parameters"), dict)
        else {},
        "rationale": str(candidate.get("rationale") or "")[:1_000] or None,
    }


__all__ = [
    "DecisionBatch",
    "DecisionCandidate",
    "DecisionRejection",
    "DecisionValidation",
    "choose_actions",
    "decide_next_wave",
    "decision_fingerprint",
    "match_approved_jobs",
    "plan_objective",
    "propose_next_actions",
    "validate_decision",
]
