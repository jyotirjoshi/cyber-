"""Node: remediate_findings -- generate advisory remediation guidance (FR-025, FR-026, FR-034).

The findings are analyzed and ranked; this node asks the code-remediation model for a concrete fix
for the worst of them -- an upgrade, a configuration change, a compensating control, and, where a
component and version are known, a patch a human could review.  It runs during the ``remediating``
status at stage ``remediation`` and is the point at which the pipeline crosses from
``analyzing`` into ``remediating``.

**The node is a thin orchestrator; every guard rail lives in the service.**  That a patch is never
applied (FR-034 -- no code path here writes to a repository), that an invented CVE or CVSS score is
rejected outright, that a sentence no collected source supports is stripped, that an empty
``references`` list is surfaced as "unverified" rather than hidden (FR-024) -- all of it is enforced
inside :func:`app.services.remediation.generate_remediation`, which also self-audits every attempt.
This node's job is narrow: pick the findings worth a fix, resolve the per-tenant knowledge-base
client, and walk the batch.

**A finding at a time, each in its own transaction.**  Remediation is the most expensive per-finding
call in the system, so -- like AI analysis -- the node commits per finding rather than holding one
connection across the run.  :func:`remediation_candidates` already excludes findings that carry a
remediation, so ``generate_remediation``'s idempotency is real across a crash: a resumed run selects
only the findings still missing guidance and never bills the operator for the same fix twice.

**A model outage degrades the run; it does not fail it (FR-040).**  ``generate_remediation`` returns
``None`` -- not an exception -- when a fix would be wrong to write (a false positive) or already
exists, so a healthy no-op never looks like an error.  What can still escape is infrastructure:
:class:`ModelUnavailableError` if the provider is down, or a per-finding :class:`AIError` (a reply
too large for the budget, a malformed response after retries).  A provider that is down will fail
every remaining finding identically, so the node stops early and records one degradation rather than
hammering it N times.  A per-finding error simply leaves that finding without a remediation row --
which is the ordinary state of an un-remediated finding, so unlike analysis there is nothing to
compensate -- and the batch continues.  Either way the run reaches the report, because remediation is
advisory: the assessment's value does not hinge on it.

Every summary and note is counts-only: never a finding title, a hostname, a CVE's affected product,
or a credential (SEC-002).
"""

from __future__ import annotations

import structlog

from app.agent.nodes._common import (
    StepHandle,
    load_assessment,
    principal_from,
    record_step,
)
from app.agent.registry import AgentDeps
from app.agent.state import AssessmentState, state_uuid
from app.core.errors import AIError, ModelUnavailableError
from app.db.enums import AssessmentStage, AssessmentStatus, IntegrationKind
from app.db.session import session_scope
from app.integrations.dify import DifyClient
from app.services.assessment import record_degradation, transition
from app.services.context import Principal
from app.services.integration import resolve_settings
from app.services.remediation import generate_remediation, remediation_candidates

log = structlog.get_logger(__name__)

#: The graph node name. Matches the key ``build_graph`` registers for this node.
_NODE = "remediate_findings"

_DEGRADE_NOTE = "Remediation was incomplete: the code-remediation model was unavailable."

_IMPACT_MODEL = (
    "The code-remediation model could not be reached, so some findings have no suggested fix. Their "
    "deterministic risk ranking is unaffected, but the remediation guidance is missing."
)


async def remediate_findings(state: AssessmentState, *, deps: AgentDeps) -> dict[str, object]:
    """Generate an advisory fix for every high-risk candidate finding (FR-025, FR-026)."""
    await _advance_to_remediate(state, deps=deps)

    async with record_step(
        deps,
        state,
        node=_NODE,
        stage=AssessmentStage.REMEDIATION,
        label="Generating remediation guidance",
    ) as step:
        await _remediate(state, deps=deps, step=step)

    return {"stage": AssessmentStage.REMEDIATION.value}


async def _advance_to_remediate(state: AssessmentState, *, deps: AgentDeps) -> None:
    """Carry the assessment from ``analyzing`` into ``remediating`` at stage ``remediation``.

    This is the one real status change in the analysis tail: prioritisation left the assessment
    ``analyzing``, and this node advances it to ``remediating`` (an allowed transition).  It runs
    unconditionally -- before the candidate count is known -- so the pipeline status is monotonic:
    every assessment that reaches this node is ``remediating`` and the report node completes it,
    even when there was nothing high-risk enough to remediate.  Idempotent on a resumed run
    (``remediating -> remediating`` only re-sets the stage); a terminal or cancelling status raises
    :class:`ConflictError`, which correctly refuses to remediate an assessment being torn down.
    """
    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        await transition(
            session, assessment, AssessmentStatus.REMEDIATING, stage=AssessmentStage.REMEDIATION
        )


async def _remediate(state: AssessmentState, *, deps: AgentDeps, step: StepHandle) -> None:
    """Select the worst-first candidates, then generate a fix for each in its own transaction.

    ``remediation_candidates`` is bounded and severity-floored (remediation is the costliest call
    per finding) and excludes findings that already carry guidance, so ``limit`` counts work
    actually done and a resumed run does not repeat it.  The selection is read in its own
    transaction; the connection is then released while the model works.
    """
    principal = principal_from(state)
    assessment_id = state_uuid(state, "assessment_id")

    async with session_scope(deps.settings) as session:
        candidates = await remediation_candidates(session, principal, assessment_id)
        candidate_ids = [finding.id for finding in candidates]

    if not candidate_ids:
        await step.thinking("No findings met the remediation threshold; nothing to remediate.")
        step.record_output({"candidates": 0, "remediated": 0})
        return

    dify = await _dify_client(state, deps=deps, principal=principal)
    await step.thinking(f"Generating remediation guidance for {len(candidate_ids)} finding(s).")

    remediated = 0
    skipped = 0
    failed = 0
    model_unavailable = False
    for finding_id in candidate_ids:
        try:
            async with session_scope(deps.settings) as session:
                remediation = await generate_remediation(
                    session,
                    principal,
                    finding_id,
                    gateway=deps.gateway,
                    dify=dify,
                    settings=deps.settings,
                    by_agent=True,
                )
            if remediation is not None:
                remediated += 1
            else:
                # A correct no-op: the service declined to write a fix (a false positive, or a
                # candidate that already had one). Not an error -- count it apart from failures.
                skipped += 1
        except ModelUnavailableError as exc:
            # The provider is down; every remaining finding would fail identically. Stop and
            # degrade rather than issue N doomed calls.
            model_unavailable = True
            log.warning("agent.remediate.model_unavailable", error=exc.code)
            break
        except AIError as exc:
            # A per-finding failure (budget/malformed). The finding simply keeps no remediation
            # row -- the ordinary state of an un-remediated finding -- so nothing to compensate;
            # one finding must not abort the batch.
            log.warning("agent.remediate.finding_skipped", error=exc.code)
            failed += 1

    if model_unavailable:
        await _degrade(state, deps=deps)
        step.degrade(_DEGRADE_NOTE)

    step.record_output(
        {
            "candidates": len(candidate_ids),
            "remediated": remediated,
            "skipped": skipped,
            "failed": failed,
            "model_unavailable": model_unavailable,
        }
    )


async def _dify_client(
    state: AssessmentState, *, deps: AgentDeps, principal: Principal
) -> DifyClient | None:
    """The per-tenant knowledge-base client, or ``None`` when no KB is configured.

    A missing knowledge base is not an error (``require=False``): ``generate_remediation`` treats
    ``None`` as "no KB chunks in the evidence" and grounds its guidance on the scanner observation
    and intelligence enrichment alone.
    """
    async with session_scope(deps.settings) as session:
        scoped = await resolve_settings(
            session, principal, IntegrationKind.DIFY, settings=deps.settings
        )
    client = DifyClient(scoped, deps.redis)
    return client if client.configured else None


async def _degrade(state: AssessmentState, *, deps: AgentDeps) -> None:
    """Record an FR-039 degradation for an unavailable model; never fail the run over it.

    ``record_degradation`` writes its own ASSESSMENT_DEGRADED audit row.  ``except Exception``
    leaves a ``CancelledError`` to propagate untouched (mirrors :mod:`app.agent.nodes.analyze`).
    """
    reason = (
        "The code-remediation model was unavailable; some findings have no remediation guidance."
    )
    try:
        async with session_scope(deps.settings) as session:
            assessment = await load_assessment(session, state)
            await record_degradation(
                session,
                assessment,
                stage=AssessmentStage.REMEDIATION,
                component="remediation",
                reason=reason,
                impact=_IMPACT_MODEL,
            )
    except Exception as exc:
        log.warning("agent.remediate.degrade_record_failed", error=type(exc).__name__)


__all__ = ["remediate_findings"]
