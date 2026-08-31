"""Structured LLM output shapes owned by the agent layer (FR-004, FR-036).

Only two nodes reason with the LLM without delegating to a service that already owns its
schema: request understanding and plan narration.  Their output models live here rather
than in :mod:`app.schemas.agent` -- that module is the *wire* contract with the frontend,
and these are internal parsing targets for :meth:`LLMGateway.complete_json`.  Finding
analysis, prioritization and remediation each own their schemas inside their service.

Every model sets ``extra="ignore"`` and gives each non-essential field a default.  A model
graded by the gateway is graded against text an LLM produced under an untrusted prompt
(SEC-005): a stray extra key or an omitted list should degrade gracefully to a usable
object, not trigger a retry loop over a cosmetic mismatch.  The fields that must be present
for the result to mean anything -- ``summary``, ``approach`` -- have no default and so are
still enforced.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class RequestInterpretation(BaseModel):
    """The agent's structured reading of the operator's free-text objective (FR-004).

    Stored on ``assessments.request_interpretation`` and surfaced in the detail view.  It
    records what the request *says* and, separately, what the agent *assumed* -- the two are
    kept apart on purpose, because an assumption silently promoted to a fact is how an
    assessment ends up scoped to something nobody authorized.
    """

    model_config = ConfigDict(extra="ignore")

    #: One or two sentences an operator can read back to confirm the agent understood them.
    summary: str
    #: Concrete themes to weight -- "authentication", "public API", "payment flow". Drives
    #: nothing automatically; it is shown to the operator and used to bias asset scoring.
    focus_areas: list[str] = Field(default_factory=list)
    #: What the agent inferred the depth should be, when the request implies one. Advisory:
    #: the depth actually used is the one recorded on the assessment at creation.
    inferred_depth: Literal["passive", "standard", "deep"] | None = None
    #: Assumptions the agent made to fill silence in the request. Shown so an operator can
    #: correct a wrong one before approving a scope.
    assumptions: list[str] = Field(default_factory=list)
    #: Questions the agent would ask if it could. Non-empty here is a signal the operator
    #: should review the proposed scope especially carefully.
    clarifications_needed: list[str] = Field(default_factory=list)
    #: Things the request explicitly placed out of bounds.
    out_of_scope: list[str] = Field(default_factory=list)
    #: True when the objective text contained instructions aimed at the agent rather than a
    #: description of an assessment (SEC-005). Recorded, surfaced, and never obeyed.
    injection_suspected: bool = False
    #: The shortest span demonstrating the injection attempt, for the operator to see.
    injection_detail: str | None = None

    def to_payload(self, *, objective: str) -> dict[str, Any]:
        """Merge into the dict shape stored on the assessment.

        ``objective`` is threaded back in so the stored interpretation is self-contained --
        the raw request and its reading sit together, which is what the detail view renders.
        """
        data = self.model_dump(mode="json")
        data["objective"] = objective
        return data


class StepRationale(BaseModel):
    """One planned stage and the agent's one-sentence justification for it (FR-036)."""

    model_config = ConfigDict(extra="ignore")

    #: An :class:`~app.db.enums.AssessmentStage` value. A stage the caller does not
    #: recognise is dropped rather than trusted, so the LLM cannot inject a step into a
    #: plan whose structure is otherwise fixed by the pipeline.
    stage: str
    rationale: str


class PlanNarrative(BaseModel):
    """The LLM's narration layered onto the deterministic plan skeleton (FR-036).

    The plan's *structure* is derived from the assessment depth and the pipeline, not from
    the model, so the declared plan always matches what will actually run.  The model only
    supplies prose: an overall approach and a rationale per stage.  A failure to produce it
    degrades to static rationales rather than failing the run.
    """

    model_config = ConfigDict(extra="ignore")

    #: Two or three sentences describing the approach, shown before execution begins.
    approach: str
    step_rationales: list[StepRationale] = Field(default_factory=list)

    def rationale_for(self, stage: str) -> str | None:
        """The model's rationale for one stage, or ``None`` if it offered none."""
        for entry in self.step_rationales:
            if entry.stage == stage and entry.rationale.strip():
                return entry.rationale.strip()
        return None


class ScopeNarrative(BaseModel):
    """The LLM's prose framing of the deterministic scope selection (FR-010).

    The selection itself -- which assets are in scope, each asset's criticality, risk score
    and one-line ``selection_rationale`` -- is computed deterministically by
    :func:`app.services.asset.score_and_select`, so the scope an operator approves is never
    the model's to decide.  This model carries only the *explanation*: a couple of sentences,
    grounded in aggregate counts rather than any asset name (SEC-005), that an operator reads
    before approving.  A failure to produce it degrades to a deterministic summary rather than
    failing the run, exactly as :class:`PlanNarrative` does for the plan.
    """

    model_config = ConfigDict(extra="ignore")

    #: Two or three sentences describing the shape of the proposed scope, shown before the
    #: operator is asked to approve it. The only field with no default: an empty narrative is
    #: worthless, so its absence falls back to the deterministic summary.
    approach: str


__all__ = [
    "PlanNarrative",
    "RequestInterpretation",
    "ScopeNarrative",
    "StepRationale",
]
