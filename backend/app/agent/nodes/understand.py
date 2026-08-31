"""Node: understand -- turn the operator's free-text objective into structured intent (FR-004).

This is the graph's first node.  The assessment, its validated targets and the human
authorization already exist -- the API caller wrote them before the run started -- so this
node does *not* create, validate or re-authorize anything.  It reads the objective the
operator typed and asks the planning model what it *means*: the themes to weight, the
assumptions the request forces, the questions it leaves open, and whether the text tried to
instruct the agent rather than describe an assessment (SEC-005).

Two deliberate choices:

*   **The objective is untrusted.**  It is fenced with :func:`wrap_untrusted` before it
    reaches the prompt, and :data:`UNDERSTAND_REQUEST_SYSTEM` tells the model that fenced
    instructions are to be reported, not obeyed.  A detected injection is persisted on the
    interpretation, surfaced to the operator, and recorded as a refused action -- never
    acted on.
*   **Interpretation is best-effort.**  The targets and depth define the scope; this reading
    only guides it.  So an :class:`~app.core.errors.AIError` degrades to an objective-only
    interpretation (FR-039) rather than failing the run -- while a
    :class:`~app.core.errors.ConfigurationError`, which is not an ``AIError``, propagates and
    fails fast, because a misconfigured model is a deploy problem, not a run-time one.
"""

from __future__ import annotations

import structlog

from app.agent.nodes._common import load_assessment, principal_from, record_step
from app.agent.registry import AgentDeps
from app.agent.schemas import RequestInterpretation
from app.agent.state import AssessmentState
from app.core.errors import AIError
from app.db.enums import AssessmentStage, AssessmentStatus
from app.db.session import session_scope
from app.llm.base import LLMMessage
from app.llm.prompts import UNDERSTAND_REQUEST_SYSTEM, wrap_untrusted
from app.services import audit as audit_service
from app.services.assessment import record_degradation, transition

log = structlog.get_logger(__name__)

#: The user turn's instruction, kept above the fenced objective so nothing after the fence
#: can be mistaken for part of the task (the ordering :func:`wrap_untrusted` depends on).
_INSTRUCTION = (
    "Interpret the security assessment request below. Extract only what it actually says; "
    "where it is silent, leave the field empty rather than guessing. Return the structured "
    "interpretation."
)


async def understand(state: AssessmentState, *, deps: AgentDeps) -> dict[str, object]:
    """Interpret the objective, persist the reading, and move CREATED -> PLANNING."""
    objective = (state.get("objective") or "").strip()

    async with record_step(
        deps,
        state,
        node="understand",
        stage=AssessmentStage.UNDERSTANDING,
        label="Understanding the request",
        input_digest={"objective_present": bool(objective)},
    ) as step:
        degradation: str | None = None
        try:
            interpretation = await _interpret(deps, objective)
        except AIError as exc:
            interpretation = _fallback(objective)
            degradation = (
                "I could not fully interpret the written objective, so I am proceeding "
                "from the targets and depth alone."
            )
            log.warning(
                "agent.understand.degraded",
                error=exc.code,
                assessment_id=state.get("assessment_id"),
            )

        payload = interpretation.to_payload(objective=state.get("objective") or "")

        if interpretation.summary:
            await step.thinking(interpretation.summary)
        if interpretation.injection_suspected:
            await step.thinking(
                "The request contained instructions aimed at me rather than a description of "
                "an assessment. I have ignored them and interpreted only the legitimate part."
            )

        async with session_scope(deps.settings) as session:
            assessment = await load_assessment(session, state)
            assessment.request_interpretation = payload
            await transition(
                session,
                assessment,
                AssessmentStatus.PLANNING,
                stage=AssessmentStage.UNDERSTANDING,
            )
            if degradation:
                await record_degradation(
                    session,
                    assessment,
                    stage=AssessmentStage.UNDERSTANDING,
                    component="request interpretation",
                    reason=degradation,
                    impact="Scope guidance was derived from the targets without the objective.",
                )
            if interpretation.injection_suspected:
                # A refused instruction, kept as a security event (FR-032). It commits with
                # the interpretation above; the operator sees the same fact in the detail view.
                await audit_service.record_denial(
                    session,
                    action=audit_service.AuditAction.UNSAFE_INVOCATION,
                    principal=principal_from(state),
                    reason="prompt-injection attempt detected in the assessment objective",
                    resource_type="assessment",
                    resource_id=assessment.id,
                    detail={"injection_detail": (interpretation.injection_detail or "")[:500]},
                )

        if degradation:
            step.degrade(degradation)
        step.record_output(
            {
                "focus_areas": len(interpretation.focus_areas),
                "clarifications_needed": len(interpretation.clarifications_needed),
                "injection_suspected": interpretation.injection_suspected,
            }
        )

    return {
        "stage": AssessmentStage.UNDERSTANDING.value,
        "request_interpretation": payload,
    }


async def _interpret(deps: AgentDeps, objective: str) -> RequestInterpretation:
    """Ask the planning model to read the objective, or synthesize a reading for an empty one.

    An assessment created from a bare target carries no objective text; there is nothing to
    interpret, so this skips the model call rather than spend a round trip asking it to
    describe silence.
    """
    if not objective:
        return _fallback(objective)

    messages = [
        LLMMessage(role="system", content=UNDERSTAND_REQUEST_SYSTEM),
        LLMMessage(
            role="user",
            content=f"{_INSTRUCTION}\n\n{wrap_untrusted('assessment request', objective)}",
        ),
    ]
    result: RequestInterpretation = await deps.gateway.complete_json(
        "planning",
        messages,
        schema=RequestInterpretation.model_json_schema(),
        model_cls=RequestInterpretation,
    )
    return result


def _fallback(objective: str) -> RequestInterpretation:
    """A minimal interpretation for an empty or un-interpretable objective."""
    if objective:
        summary = "The written objective could not be interpreted; the targets and depth define the scope."
    else:
        summary = "No written objective was provided; the assessment's targets and depth define its scope."
    return RequestInterpretation(summary=summary)


__all__ = ["understand"]
