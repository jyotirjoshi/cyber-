"""Node: plan -- declare the ordered plan the assessment will follow (FR-036).

The plan an operator sees has two independent jobs, and this node keeps them apart on
purpose:

*   **Its structure is deterministic.**  Which stages run, in what order, and which of them
    require approval is derived from the assessment depth and the fixed pipeline -- not from
    the model.  A plan the LLM could author at will could omit the approval gate, invent a
    scanner, or reorder recon after scanning; deriving the skeleton from
    :func:`~app.scanners.registry.active_scanners` and the pipeline means the declared plan
    is exactly what the graph will execute, and :mod:`app.services.progress` can score it
    against the same :data:`~app.db.enums.STAGE_ORDER`.
*   **Its prose is the model's.**  The planning model supplies an overall approach and a
    one-sentence rationale per stage (:class:`~app.agent.schemas.PlanNarrative`), so the
    operator reads *why* each step is there in the context of their objective.  That is the
    only part that can fail, and it degrades to standard rationales (FR-039) rather than
    failing the run -- the plan structure stands without it.

The node does not touch any target.  It reads the interpretation understand produced, writes
the plan onto the assessment, and sets the stage to ``planning``; the status is already
``PLANNING`` from understand, so the transition here only advances the stage.
"""

from __future__ import annotations

import structlog

from app.agent.nodes._common import load_assessment, record_step
from app.agent.registry import AgentDeps
from app.agent.schemas import PlanNarrative
from app.agent.state import AssessmentState
from app.core.errors import AIError
from app.db.enums import AssessmentDepth, AssessmentStage, AssessmentStatus, ScannerName
from app.db.session import session_scope
from app.llm.base import LLMMessage
from app.llm.prompts import PLANNING_SYSTEM, wrap_untrusted
from app.scanners.registry import active_scanners
from app.schemas.assessment import PlanStepOut
from app.services.assessment import record_degradation, transition
from app.services.progress import STAGE_LABELS

log = structlog.get_logger(__name__)

#: The active-scan stages, keyed by the scanner whose presence at a depth pulls them in.
#: The set of *values* here is also what marks a plan step ``requires_approval``.
_SCAN_STAGE: dict[ScannerName, AssessmentStage] = {
    ScannerName.NMAP: AssessmentStage.SCAN_NMAP,
    ScannerName.NUCLEI: AssessmentStage.SCAN_NUCLEI,
    ScannerName.ZAP: AssessmentStage.SCAN_ZAP,
}

#: Stages that touch a target actively and therefore sit behind the FR-011 approval gate.
_APPROVAL_STAGES: frozenset[AssessmentStage] = frozenset(_SCAN_STAGE.values())

#: The tool label shown on a plan step, where one drives it. Cognitive stages (analysis,
#: prioritization) run on the model, not a named tool, and carry no label.
_STAGE_TOOL: dict[AssessmentStage, str] = {
    AssessmentStage.RECON: "reconftw",
    AssessmentStage.SCAN_NMAP: "nmap",
    AssessmentStage.SCAN_NUCLEI: "nuclei",
    AssessmentStage.SCAN_ZAP: "zap",
    AssessmentStage.IMPORT: "defectdojo",
}

#: The fallback rationale for a stage when the model supplies none (an empty objective, or a
#: degraded narration). Deliberately generic: the model's job is to make these specific to
#: the operator's request, and their absence should read as plain, not broken.
_STATIC_RATIONALE: dict[AssessmentStage, str] = {
    AssessmentStage.RECON: "Map the attack surface from public sources before touching anything.",
    AssessmentStage.ASSET_ANALYSIS: "Rank what reconnaissance found so scanning focuses on what matters.",
    AssessmentStage.APPROVAL: "Active scanning proceeds only after you approve the proposed scope.",
    AssessmentStage.SCAN_NMAP: "Enumerate open ports and services on the approved assets.",
    AssessmentStage.SCAN_NUCLEI: "Check the approved assets against known-vulnerability templates.",
    AssessmentStage.SCAN_ZAP: "Probe approved web applications for common weaknesses.",
    AssessmentStage.IMPORT: "Consolidate every scanner's output into DefectDojo as the record of truth.",
    AssessmentStage.ENRICH: "Add exploitation and exposure intelligence to each finding.",
    AssessmentStage.AI_ANALYSIS: "Explain each finding in the context of the asset it affects.",
    AssessmentStage.PRIORITIZE: "Rank findings by real-world risk, not raw scanner severity.",
    AssessmentStage.REMEDIATION: "Produce concrete, verifiable fixes for the findings that matter.",
    AssessmentStage.ACTIONS: "Open the tickets and send the notifications you asked for.",
    AssessmentStage.REPORT: "Assemble the findings, intelligence and fixes into one report.",
}


async def plan(state: AssessmentState, *, deps: AgentDeps) -> dict[str, object]:
    """Build the declared plan, persist it, and set the stage to ``planning``."""
    depth = _depth_from(state)
    stages = _plan_stages(depth)

    async with record_step(
        deps,
        state,
        node="plan",
        stage=AssessmentStage.PLANNING,
        label="Planning the assessment",
        input_digest={"depth": depth.value, "stages": len(stages)},
    ) as step:
        interpretation = state.get("request_interpretation") or {}
        narrative, degradation = await _narrate(deps, state, interpretation, depth, stages)
        steps = _build_steps(stages, narrative)
        plan_payload = [item.model_dump(mode="json") for item in steps]

        if narrative is not None and narrative.approach.strip():
            await step.thinking(narrative.approach.strip())

        async with session_scope(deps.settings) as session:
            assessment = await load_assessment(session, state)
            assessment.plan = plan_payload
            await transition(
                session,
                assessment,
                AssessmentStatus.PLANNING,
                stage=AssessmentStage.PLANNING,
            )
            if degradation:
                await record_degradation(
                    session,
                    assessment,
                    stage=AssessmentStage.PLANNING,
                    component="plan narration",
                    reason=degradation,
                    impact="The plan uses standard step descriptions instead of tailored ones.",
                )

        if degradation:
            step.degrade(degradation)
        step.record_output({"steps": len(steps), "narrated": narrative is not None})

    return {"stage": AssessmentStage.PLANNING.value, "plan": plan_payload}


def _plan_stages(depth: AssessmentDepth) -> list[AssessmentStage]:
    """The ordered stages this depth will run, as the plan declares them.

    Recon and asset analysis always run.  The active block -- approval, the depth's
    scanners, import, enrichment -- is present only when the depth offers any active
    scanner, which is exactly the ``passive`` distinction.  The cognitive tail (analysis
    through report) always runs: a passive assessment still produces an analyzed,
    prioritized report of what recon found.
    """
    stages = [AssessmentStage.RECON, AssessmentStage.ASSET_ANALYSIS]
    scanners = active_scanners(depth)
    if scanners:
        stages.append(AssessmentStage.APPROVAL)
        stages.extend(_SCAN_STAGE[name] for name in scanners if name in _SCAN_STAGE)
        stages.append(AssessmentStage.IMPORT)
        stages.append(AssessmentStage.ENRICH)
    stages.extend(
        (
            AssessmentStage.AI_ANALYSIS,
            AssessmentStage.PRIORITIZE,
            AssessmentStage.REMEDIATION,
            AssessmentStage.ACTIONS,
            AssessmentStage.REPORT,
        )
    )
    return stages


def _build_steps(
    stages: list[AssessmentStage],
    narrative: PlanNarrative | None,
) -> list[PlanStepOut]:
    """Turn the fixed stage list into declared plan steps, prose from the model where offered."""
    steps: list[PlanStepOut] = []
    for index, stage in enumerate(stages):
        rationale = None
        if narrative is not None:
            rationale = narrative.rationale_for(stage.value)
        steps.append(
            PlanStepOut(
                index=index,
                stage=stage,
                title=STAGE_LABELS[stage],
                tool=_STAGE_TOOL.get(stage),
                rationale=rationale or _STATIC_RATIONALE.get(stage),
                requires_approval=stage in _APPROVAL_STAGES,
            )
        )
    return steps


async def _narrate(
    deps: AgentDeps,
    state: AssessmentState,
    interpretation: dict[str, object],
    depth: AssessmentDepth,
    stages: list[AssessmentStage],
) -> tuple[PlanNarrative | None, str | None]:
    """Ask the planning model for the approach and per-stage rationale.

    Returns ``(narrative, None)`` on success or ``(None, note)`` on any AI failure -- the
    caller degrades to static rationales rather than failing.  A misconfigured model raises
    :class:`~app.core.errors.ConfigurationError`, which is not an ``AIError`` and so
    propagates: that is a deploy fault, not a run-time degradation.
    """
    try:
        messages = [
            LLMMessage(role="system", content=PLANNING_SYSTEM),
            LLMMessage(
                role="user",
                content=_narration_prompt(interpretation, depth, state.get("scope"), stages),
            ),
        ]
        narrative: PlanNarrative = await deps.gateway.complete_json(
            "planning",
            messages,
            schema=PlanNarrative.model_json_schema(),
            model_cls=PlanNarrative,
        )
        return narrative, None
    except AIError as exc:
        log.warning("agent.plan.degraded", error=exc.code, assessment_id=state.get("assessment_id"))
        return (
            None,
            "I could not generate a tailored plan narrative, so I am using standard step descriptions.",
        )


def _narration_prompt(
    interpretation: dict[str, object],
    depth: AssessmentDepth,
    scope: str | None,
    stages: list[AssessmentStage],
) -> str:
    """Assemble the planning user turn.

    The instruction is entirely platform-authored -- the fixed depth, scope and stage list,
    and the ask.  The one piece of operator-derived text (the interpreted objective) is
    fenced last with :func:`wrap_untrusted` (SEC-005): understand records injections rather
    than obeying them, but a summary can still echo attacker text, so it stays data here too.
    """
    stage_lines = "\n".join(_stage_line(index, stage) for index, stage in enumerate(stages))
    instruction = (
        f"Assessment depth: {depth.value}. Scope: {scope or 'external'}.\n\n"
        "The stage sequence below is FIXED by the platform. You cannot add, remove, reorder "
        "or rename stages, and you must not invent targets or tools. Write a two-to-three "
        "sentence overall approach in `approach`, then one sentence of rationale per stage in "
        "`step_rationales`, each keyed by the stage value shown.\n\n"
        f"Stages:\n{stage_lines}"
    )
    return f"{instruction}\n\n{wrap_untrusted('interpreted request', _context(interpretation))}"


def _stage_line(index: int, stage: AssessmentStage) -> str:
    parts = [f"{index + 1}. {STAGE_LABELS[stage]} (stage={stage.value}"]
    if stage in _STAGE_TOOL:
        parts.append(f", tool={_STAGE_TOOL[stage]}")
    if stage in _APPROVAL_STAGES:
        parts.append(", requires approval")
    parts.append(")")
    return "".join(parts)


def _context(interpretation: dict[str, object]) -> str:
    """The operator-derived planning context, as fenced data."""
    summary = str(interpretation.get("summary") or "").strip()
    lines = [
        summary or "No written objective was provided; the targets and depth define the scope."
    ]
    focus = interpretation.get("focus_areas")
    if isinstance(focus, list) and focus:
        lines.append("Focus areas: " + ", ".join(str(item) for item in focus[:12]))
    out_of_scope = interpretation.get("out_of_scope")
    if isinstance(out_of_scope, list) and out_of_scope:
        lines.append(
            "Explicitly out of scope: " + ", ".join(str(item) for item in out_of_scope[:12])
        )
    return "\n".join(lines)


def _depth_from(state: AssessmentState) -> AssessmentDepth:
    try:
        return AssessmentDepth(state.get("depth") or AssessmentDepth.STANDARD.value)
    except ValueError:
        return AssessmentDepth.STANDARD


__all__ = ["plan"]
