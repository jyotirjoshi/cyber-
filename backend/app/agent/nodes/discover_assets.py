"""Node: discover_assets -- score the recon inventory and propose a scan scope (FR-010).

Reconnaissance (the ``recon`` node) has already written every discovered asset to the
database.  This node does not discover anything; it *selects*.  It hands the inventory to
:func:`app.services.asset.score_and_select`, which deterministically assigns each asset a
criticality, a risk score and a one-line ``selection_rationale``, then marks the top slice
-- bounded by the operator's scope budget -- as ``selected_for_scanning``.  That selection,
not this node, is what the operator approves next, and every selected asset carries the
reason it was chosen (FR-010: an explainable scope).

Three deliberate choices, each mirroring an established node:

*   **The selection is deterministic; only its explanation is the model's.**  Like the
    plan skeleton in :mod:`app.agent.nodes.plan`, the scope is computed in code so it is
    reproducible and auditable.  The planning model is asked only for a couple of sentences
    of prose framing (:class:`~app.agent.schemas.ScopeNarrative`), and an
    :class:`~app.core.errors.AIError` degrades that prose to a deterministic summary (FR-039)
    rather than failing the run -- while a :class:`~app.core.errors.ConfigurationError`,
    which is not an ``AIError``, propagates.
*   **The narration sees counts, never names.**  Asset names, HTTP titles and TLS subjects
    are attacker-influenced (SEC-005); the scope summary is built from aggregate statistics
    and the (wrapped) interpreted objective alone, so no untrusted asset string reaches the
    prompt here.
*   **Stage advances, status does not.**  The assessment is already ``DISCOVERY`` (recon
    moved it there); this node advances only the *stage* to ``asset_analysis`` via the
    idempotent no-op branch of :func:`app.services.assessment.transition`, so a checkpoint
    re-run after a crash re-selects harmlessly instead of tripping the state machine.
"""

from __future__ import annotations

from dataclasses import dataclass

import structlog

from app.agent.nodes._common import load_assessment, record_step
from app.agent.registry import AgentDeps
from app.agent.schemas import ScopeNarrative
from app.agent.state import AssessmentState
from app.core.config import Settings
from app.core.errors import AIError
from app.db.enums import AssessmentStage, AssessmentStatus
from app.db.models.assessment import Assessment
from app.db.models.asset import Asset
from app.db.session import session_scope
from app.llm.base import LLMMessage
from app.llm.prompts import ASSET_ANALYSIS_SYSTEM, wrap_untrusted
from app.services.assessment import record_degradation, transition
from app.services.asset import score_and_select

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class _ScopeStats:
    """Trusted, name-free aggregates of a selection, safe to put in a prompt (SEC-005)."""

    discovered: int
    selected: int
    by_criticality: dict[str, int]
    internet_exposed: int
    top_score: float
    cutoff_score: float


@dataclass(frozen=True, slots=True)
class _Selection:
    """What the DB write produced: the selected ids for the channel, and the stats to narrate."""

    ids: list[str]
    stats: _ScopeStats


async def discover_assets(state: AssessmentState, *, deps: AgentDeps) -> dict[str, object]:
    """Select the scan scope from the recon inventory and stage it for approval."""
    budget = _budget(state, deps.settings)

    async with record_step(
        deps,
        state,
        node="discover_assets",
        stage=AssessmentStage.ASSET_ANALYSIS,
        label="Selecting the scan scope",
        input_digest={"scope_budget": budget},
    ) as step:
        selection = await _select_scope(deps, state, budget)
        narrative, degradation = await _narrate(deps, state, selection.stats)

        await step.thinking(narrative)
        if degradation:
            await _record_scope_degradation(deps, state, degradation)
            step.degrade(degradation)

        step.record_output(
            {
                "assets_discovered": selection.stats.discovered,
                "assets_selected": selection.stats.selected,
                "internet_exposed": selection.stats.internet_exposed,
                "scope_budget": budget,
            }
        )

    return {
        "stage": AssessmentStage.ASSET_ANALYSIS.value,
        "selected_asset_ids": selection.ids,
    }


async def _select_scope(deps: AgentDeps, state: AssessmentState, budget: int) -> _Selection:
    """Run the deterministic selection and advance the stage, in one transaction.

    ``score_and_select`` re-queries the assets under a tenant filter, writes each asset's
    criticality, risk score and ``selection_rationale``, marks the chosen slice, sets
    ``assessment.assets_in_scope`` and audits the decision itself -- so this node adds no
    audit of its own.  The returned rows are read for their ids and aggregates *before* the
    scope closes; ``transition`` then advances only the stage, because the assessment is
    already ``DISCOVERY``.
    """
    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        selected = await score_and_select(
            session, assessment, budget=budget, settings=deps.settings
        )
        stats = _stats(assessment, selected)
        ids = [str(asset.id) for asset in selected]
        await transition(
            session,
            assessment,
            AssessmentStatus.DISCOVERY,
            stage=AssessmentStage.ASSET_ANALYSIS,
        )
        return _Selection(ids=ids, stats=stats)


async def _narrate(
    deps: AgentDeps, state: AssessmentState, stats: _ScopeStats
) -> tuple[str, str | None]:
    """A scope explanation and an optional degradation note.

    Skips the model when there is nothing to explain -- no assets, or none selected -- for
    the same reason ``understand`` skips it for an empty objective: there is no round trip
    worth spending.  An :class:`~app.core.errors.AIError` falls back to the deterministic
    summary and reports the degradation; anything else (a misconfigured model) propagates.
    """
    if stats.discovered == 0:
        return (
            "Reconnaissance surfaced no assets, so there is nothing to scope for scanning.",
            None,
        )
    if stats.selected == 0:
        return (_static_summary(stats), None)

    try:
        narrative = await _ask_scope_model(deps, state, stats)
    except AIError as exc:
        log.warning(
            "agent.discover_assets.degraded",
            error=exc.code,
            assessment_id=state.get("assessment_id"),
        )
        return (
            _static_summary(stats),
            "I could not generate a tailored explanation of the proposed scope, so I am "
            "showing a standard summary; the selection itself is unaffected.",
        )

    return (narrative.approach.strip() or _static_summary(stats), None)


async def _ask_scope_model(
    deps: AgentDeps, state: AssessmentState, stats: _ScopeStats
) -> ScopeNarrative:
    """Ask the planning model to frame the selection in prose (aggregates only, SEC-005)."""
    messages = [
        LLMMessage(role="system", content=ASSET_ANALYSIS_SYSTEM),
        LLMMessage(role="user", content=_prompt(state, stats)),
    ]
    result: ScopeNarrative = await deps.gateway.complete_json(
        "planning",
        messages,
        schema=ScopeNarrative.model_json_schema(),
        model_cls=ScopeNarrative,
    )
    return result


def _prompt(state: AssessmentState, stats: _ScopeStats) -> str:
    """The narration user turn: trusted aggregates, then the fenced interpreted objective.

    Only counts and scores are stated as fact -- Cynux computed them.  The objective summary
    is derived from operator free-text and is therefore fenced; nothing after the fence can
    be read as instruction (the ordering :func:`wrap_untrusted` relies on).
    """
    instruction = (
        f"A deterministic risk model examined {stats.discovered} discovered asset(s) and "
        f"selected {stats.selected} for the proposed scan scope "
        f"(by criticality: {_breakdown(stats)}; {stats.internet_exposed} internet-exposed; "
        f"risk scores from {stats.cutoff_score:.2f} to {stats.top_score:.2f}). Write two or "
        "three sentences an operator can read before approving this scope, explaining its "
        "shape in plain terms. Do not invent asset names, do not authorize the scan, and do "
        "not claim anything has been scanned yet. Return the structured narrative."
    )
    return f"{instruction}\n\n{wrap_untrusted('interpreted objective', _objective_summary(state))}"


async def _record_scope_degradation(deps: AgentDeps, state: AssessmentState, reason: str) -> None:
    """Persist the FR-039 degradation for a failed narration, in its own transaction."""
    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        await record_degradation(
            session,
            assessment,
            stage=AssessmentStage.ASSET_ANALYSIS,
            component="scope narration",
            reason=reason,
            impact="The proposed scope is unchanged; only its written explanation is the fallback.",
        )


def _budget(state: AssessmentState, settings: Settings) -> int:
    """The selection budget: the run's channel value if positive, else the configured default.

    ``score_and_select`` raises on a non-positive budget and clamps to
    ``agent.max_scope_budget``; this guarantees the positive precondition and leaves the
    ceiling to the service.
    """
    raw = state.get("scope_budget")
    if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0:
        return raw
    return settings.agent.default_scope_budget


def _stats(assessment: Assessment, selected: list[Asset]) -> _ScopeStats:
    """Reduce the selected rows to name-free aggregates while the session is still open."""
    by_criticality: dict[str, int] = {}
    exposed = 0
    scores: list[float] = []
    for asset in selected:
        label = str(asset.criticality)
        by_criticality[label] = by_criticality.get(label, 0) + 1
        if asset.internet_exposed:
            exposed += 1
        scores.append(float(asset.risk_score))
    return _ScopeStats(
        discovered=int(assessment.assets_discovered),
        selected=len(selected),
        by_criticality=by_criticality,
        internet_exposed=exposed,
        top_score=max(scores) if scores else 0.0,
        cutoff_score=min(scores) if scores else 0.0,
    )


def _breakdown(stats: _ScopeStats) -> str:
    """A stable ``"2 high, 1 normal"`` rendering of the criticality histogram."""
    parts = [f"{count} {label}" for label, count in sorted(stats.by_criticality.items())]
    return ", ".join(parts) if parts else "none"


def _objective_summary(state: AssessmentState) -> str:
    """The operator's interpreted objective, for context; a neutral line when there is none."""
    interpretation = state.get("request_interpretation")
    if isinstance(interpretation, dict):
        summary = interpretation.get("summary")
        if isinstance(summary, str) and summary.strip():
            return summary.strip()
    objective = state.get("objective")
    if isinstance(objective, str) and objective.strip():
        return objective.strip()
    return "No written objective was provided; scope was derived from the targets and depth."


def _static_summary(stats: _ScopeStats) -> str:
    """The deterministic scope explanation, used when the model is skipped or degrades."""
    if stats.selected == 0:
        return (
            f"Reconnaissance discovered {stats.discovered} asset(s); none were selected for "
            "scanning under the current scope budget."
        )
    exposure = (
        f", of which {stats.internet_exposed} are internet-exposed"
        if stats.internet_exposed
        else ""
    )
    return (
        f"Selected {stats.selected} of {stats.discovered} discovered asset(s) for the proposed "
        f"scan scope (by criticality: {_breakdown(stats)}){exposure}. Risk scores range from "
        f"{stats.cutoff_score:.2f} to {stats.top_score:.2f}. A human approves this scope next."
    )


__all__ = ["discover_assets"]
