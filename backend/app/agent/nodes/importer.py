"""Node: import_findings -- push raw scanner output to DefectDojo and project it back (FR-016..018).

This node sits between the active scan (:mod:`app.agent.nodes.scan`) and analysis.  Its whole
job is to make DefectDojo the system of record for every vulnerability the scanners produced,
and to mirror just enough of that back into Cynux's own tables for the dashboard and the later
analysis nodes to read.

**DefectDojo owns the finding; Cynux never parses one (FR-016, FR-017).**  Each completed
scanner left exactly one machine-readable artifact in object storage (an Nmap XML, a Nuclei
JSON, a ZAP XML).  This node uploads that file *verbatim* to DefectDojo's own parser via
``import-scan`` and lets DefectDojo decide what is a finding, what its severity is and whether it
duplicates one already seen.  Cynux does not read the file, does not dedup, does not compute a
delta -- doing any of that would fork the truth away from the system of record.

**Re-running reconciles rather than duplicates (FR-018).**  A job that already carries a
``defectdojo_test_id`` (a crash-resume, or a re-scan of the same assessment) is *re-imported*
against that test, so DefectDojo closes findings that no longer appear and reopens ones that
returned.  The test id is committed to the job row *before* the projection step, so a failure to
project cannot strand us into uploading a second, duplicate test on the next attempt.

**The node is the orchestrator, because no service ties transport to projection.**  The
DefectDojo client (:mod:`app.integrations.defectdojo`) is pure transport; the projection
(:func:`app.services.finding.import_from_defectdojo`) is pure persistence.  Nothing wires the
product -> engagement -> import -> project sequence together, so this node does -- exactly as
:mod:`app.agent.nodes.scan` drives ``execute_job`` directly.  The per-tenant client is resolved
inside the node from its own session (:func:`app.services.integration.resolve_settings`), so a
run can never act through another organization's DefectDojo credentials (SEC-003).

**A DefectDojo failure is fatal; a missing scanner artifact is not (FR-040 boundary).**  Most of
the pipeline degrades on a fault, but not this node's core: an unreachable or unconfigured
DefectDojo means there is *nowhere* for findings to live, so reporting an empty result would be a
lie -- :class:`~app.core.errors.DefectDojoError` is left to propagate and fail the run.  The
narrow, genuinely-degradable case is a single scanner whose output is missing or empty in
storage: that scanner's findings are simply absent (FR-039), and the rest of the import proceeds.

The node advances the assessment ``scanning -> analyzing`` at stage ``importing_findings`` and
records one step per scanner.  Every summary and degradation note carries counts and scanner
names only -- never a hostname, a finding title or a credential (SEC-002).
"""

from __future__ import annotations

import datetime as dt
import time
import uuid
from dataclasses import dataclass
from typing import Literal

import structlog

from app.agent.nodes._common import (
    StepHandle,
    load_assessment,
    principal_from,
    record_step,
)
from app.agent.registry import AgentDeps
from app.agent.state import AssessmentState, state_uuid
from app.core.errors import DefectDojoError, ResourceNotFoundError
from app.db.enums import (
    ArtifactKind,
    AssessmentStage,
    AssessmentStatus,
    IntegrationKind,
    JobStatus,
    ScannerName,
)
from app.db.models.identity import Organization
from app.db.models.scanner import ScannerJob
from app.db.session import session_scope
from app.integrations.defectdojo import DDImportResult, DefectDojoClient, scan_type_for
from app.services.assessment import record_degradation, transition
from app.services.finding import import_from_defectdojo
from app.services.integration import resolve_settings
from app.services.job import jobs_for_assessment

log = structlog.get_logger(__name__)

#: The graph node name. Matches the key ``build_graph`` registers for this node.
_NODE = "import_findings"

#: The tool label every DefectDojo activity event carries (SEC-002: a free string, never argv).
_TOOL = "defectdojo"

#: The scanners whose output DefectDojo can parse. ReconFTW is deliberately absent -- it has no
#: DefectDojo scan-type mapping (``scan_type_for`` raises for it), because recon is asset
#: discovery, not vulnerability detection. This is the allow-list the job worklist is filtered by.
_ACTIVE_SCANNERS: frozenset[ScannerName] = frozenset(
    {ScannerName.NMAP, ScannerName.NUCLEI, ScannerName.ZAP}
)

#: Operator-facing scanner names for labels, summaries and degradation notes.
_SCANNER_LABELS: dict[ScannerName, str] = {
    ScannerName.NMAP: "Nmap",
    ScannerName.NUCLEI: "Nuclei",
    ScannerName.ZAP: "OWASP ZAP",
}

# -- user-safe degradation impacts (SEC-002: counts and scanner names only, never hosts) ------

_IMPACT_NO_OUTPUT = (
    "This scanner completed but produced no parseable output, so its findings are not included."
)
_IMPACT_MISSING = (
    "This scanner's stored output could not be retrieved, so its findings are not included."
)

_EMPTY_NOTE = "No completed scanner produced output to import into DefectDojo."


@dataclass(frozen=True, slots=True)
class _Artifact:
    """The one DefectDojo-parseable file a completed scanner left in object storage.

    Reduced to the two primitives the upload needs so it can outlive the read transaction that
    found it -- the ORM row and its session are gone by the time the file is fetched.
    """

    storage_key: str
    filename: str


@dataclass(frozen=True, slots=True)
class _JobPlan:
    """One completed scanner job to import, carried out of the read transaction as plain data.

    ``artifact`` is ``None`` when the job completed but left nothing importable -- an anomaly
    that degrades that one scanner rather than the run.
    """

    job_id: uuid.UUID
    scanner: ScannerName
    artifact: _Artifact | None

    @property
    def label(self) -> str:
        return _SCANNER_LABELS[self.scanner]


@dataclass(frozen=True, slots=True)
class _Prep:
    """The per-tenant DefectDojo context resolved before any upload.

    Holds the transport client (safe to reuse across transactions -- it binds no session) and the
    product/engagement identifiers the ``ensure_*`` calls need. Built by :func:`_prepare`.
    """

    client: DefectDojoClient
    product_name: str
    product_description: str
    engagement_name: str
    target_start: str
    target_end: str


@dataclass(frozen=True, slots=True)
class _DDContext:
    """The resolved DefectDojo engagement each per-job import uploads into."""

    client: DefectDojoClient
    engagement_id: int


async def import_findings(state: AssessmentState, *, deps: AgentDeps) -> dict[str, object]:
    """Upload each scanner's output to DefectDojo and project the findings back (FR-016..018)."""
    org_id = state_uuid(state, "organization_id")

    # 1. Resolve the tenant's DefectDojo client and ensure the product/engagement exist. A
    #    DefectDojoError or a missing-configuration error here is fatal and propagates.
    prep = await _prepare(state, deps=deps)
    product = await prep.client.ensure_product(
        prep.product_name, description=prep.product_description
    )
    engagement = await prep.client.ensure_engagement(
        product_id=product.id,
        name=prep.engagement_name,
        target_start=prep.target_start,
        target_end=prep.target_end,
        tags=["cynux"],
    )

    # 2. Persist the DefectDojo linkage and advance scanning -> analyzing (idempotent on resume).
    await _persist_context(state, deps=deps, product_id=product.id, engagement_id=engagement.id)

    # 3. Import each completed scanner's artifact. Nothing to import is a normal outcome when
    #    every scanner degraded during the scan phase.
    plans = await _plan_imports(state, deps=deps, org_id=org_id)
    if not plans:
        await _record_empty(state, deps=deps)
        total = await _final_total(state, deps=deps)
        return {"findings_total": total, "stage": AssessmentStage.IMPORT.value}

    ctx = _DDContext(client=prep.client, engagement_id=engagement.id)
    for plan in plans:
        async with record_step(
            deps,
            state,
            node=_NODE,
            stage=AssessmentStage.IMPORT,
            label=f"Importing {plan.label} findings",
            tool_name=_TOOL,
            input_digest={"scanner": plan.scanner.value},
        ) as step:
            # A DefectDojoError inside here is *meant* to escape: record_step marks the step
            # failed and re-raises, and the runner fails the run (FR-040 boundary).
            await _import_job(state, deps=deps, ctx=ctx, plan=plan, step=step, org_id=org_id)

    total = await _final_total(state, deps=deps)
    return {"findings_total": total, "stage": AssessmentStage.IMPORT.value}


# ---------------------------------------------------------------------------
# Preparation: resolve the tenant client, ensure product/engagement, advance status
# ---------------------------------------------------------------------------


async def _prepare(state: AssessmentState, *, deps: AgentDeps) -> _Prep:
    """Resolve the per-tenant DefectDojo client and the product/engagement naming, read-only.

    ``resolve_settings(require=True)`` raises :class:`IntegrationNotConfiguredError` if the
    organization has no DefectDojo credentials -- fatal, because there is nowhere to send
    findings.  The product name is namespaced ``org-{slug}`` (SEC-003: two tenants that both
    named a product "Website" would otherwise collide in DefectDojo's global product namespace),
    and the engagement name is keyed on the immutable assessment id so a resume finds the same
    engagement rather than creating a second one.
    """
    principal = principal_from(state)
    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        organization = await session.get(Organization, assessment.organization_id)
        if organization is None:  # pragma: no cover - the assessment's tenant always exists
            raise ResourceNotFoundError(
                "organization not found for assessment",
                context={"assessment_id": str(assessment.id)},
            )
        scoped = await resolve_settings(
            session,
            principal,
            IntegrationKind.DEFECTDOJO,
            settings=deps.settings,
            require=True,
        )
        client = DefectDojoClient(scoped, deps.redis)

        now = dt.datetime.now(dt.UTC)
        started = assessment.started_at or assessment.created_at or now
        return _Prep(
            client=client,
            product_name=f"org-{organization.slug}",
            product_description=f"Cynux-managed product for {organization.name}.",
            engagement_name=f"Cynux Assessment #{assessment.reference} [{assessment.id}]",
            target_start=started.date().isoformat(),
            target_end=now.date().isoformat(),
        )


async def _persist_context(
    state: AssessmentState, *, deps: AgentDeps, product_id: int, engagement_id: int
) -> None:
    """Store the DefectDojo linkage on the assessment and advance ``scanning -> analyzing``.

    The transition is idempotent when a crash-resume finds the assessment already ``analyzing``;
    a terminal or cancelling status raises :class:`ConflictError`, which correctly refuses to
    import findings into an assessment that is being torn down.
    """
    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        assessment.defectdojo_product_id = product_id
        assessment.defectdojo_engagement_id = engagement_id
        await transition(
            session, assessment, AssessmentStatus.ANALYZING, stage=AssessmentStage.IMPORT
        )


# ---------------------------------------------------------------------------
# Planning: the completed active-scanner jobs whose output is importable
# ---------------------------------------------------------------------------


async def _plan_imports(
    state: AssessmentState, *, deps: AgentDeps, org_id: uuid.UUID
) -> list[_JobPlan]:
    """The completed Nmap/Nuclei/ZAP jobs to import, reduced to plain data in one read.

    Jobs that never completed are skipped without a step: the scan node already recorded their
    degradation (FR-040), so re-noting it here would double-count.  A completed job with no
    importable artifact is still returned (with ``artifact=None``) so the import loop can degrade
    that one scanner visibly.
    """
    assessment_id = state_uuid(state, "assessment_id")
    async with session_scope(deps.settings) as session:
        jobs = await jobs_for_assessment(session, assessment_id, organization_id=org_id)
        plans: list[_JobPlan] = []
        for job in jobs:
            try:
                scanner = ScannerName(job.scanner)
            except ValueError:  # pragma: no cover - scanner column is CHECK-constrained
                continue
            if scanner not in _ACTIVE_SCANNERS:
                continue
            if job.status != JobStatus.COMPLETED.value:
                continue
            plans.append(
                _JobPlan(job_id=job.id, scanner=scanner, artifact=_importable_artifact(job))
            )
        return plans


def _importable_artifact(job: ScannerJob) -> _Artifact | None:
    """The job's parseable RAW_OUTPUT artifact, or ``None`` if it produced none.

    ``jobs_for_assessment`` eager-loads ``artifacts``, so this touches no database.  A zero-byte
    file is treated as no artifact: an empty upload is anomalous, not a valid empty result.
    """
    for artifact in job.artifacts:
        if artifact.kind == ArtifactKind.RAW_OUTPUT.value and (artifact.size_bytes or 0) > 0:
            return _Artifact(storage_key=artifact.storage_key, filename=artifact.filename)
    return None


# ---------------------------------------------------------------------------
# Import: upload one scanner's artifact, then project its findings back
# ---------------------------------------------------------------------------


async def _import_job(
    state: AssessmentState,
    *,
    deps: AgentDeps,
    ctx: _DDContext,
    plan: _JobPlan,
    step: StepHandle,
    org_id: uuid.UUID,
) -> None:
    """Fetch one scanner's artifact and import it into DefectDojo, then project the findings.

    Degrades this one scanner (never the run) when its output is missing or empty; lets a
    :class:`DefectDojoError` escape to fail the run.  Fetches the artifact bytes *before* opening
    any transaction, so a slow download never holds a database connection.
    """
    artifact = plan.artifact
    if artifact is None:
        reason = f"{plan.label} completed but left no parseable output to import."
        step.degrade(reason)
        await _degrade(
            state, deps=deps, component=plan.scanner.value, reason=reason, impact=_IMPACT_NO_OUTPUT
        )
        step.record_output({"scanner": plan.scanner.value, "imported": 0})
        return

    try:
        data = await deps.storage.get_bytes(artifact.storage_key, organization_id=org_id)
    except ResourceNotFoundError:
        reason = f"{plan.label} output could not be retrieved from storage."
        step.degrade(reason)
        await _degrade(
            state, deps=deps, component=plan.scanner.value, reason=reason, impact=_IMPACT_MISSING
        )
        step.record_output({"scanner": plan.scanner.value, "imported": 0})
        return

    await _emit(step, status="started", summary=f"Importing {plan.label} output into DefectDojo")
    started = time.monotonic()
    try:
        count, result = await _upload_and_project(
            state, deps=deps, ctx=ctx, plan=plan, artifact=artifact, data=data
        )
    except DefectDojoError:
        duration_ms = int((time.monotonic() - started) * 1000)
        await _emit(
            step,
            status="failed",
            summary=f"DefectDojo import of {plan.label} output failed.",
            duration_ms=duration_ms,
        )
        raise

    duration_ms = int((time.monotonic() - started) * 1000)
    await _emit(
        step,
        status="succeeded",
        summary=_import_summary(plan, result, count),
        duration_ms=duration_ms,
    )
    step.relabel(f"Imported {plan.label} findings")
    step.record_output(
        {
            "scanner": plan.scanner.value,
            "imported": count,
            "created": result.findings_created,
            "reactivated": result.findings_reactivated,
            "closed": result.findings_closed,
        }
    )


async def _upload_and_project(
    state: AssessmentState,
    *,
    deps: AgentDeps,
    ctx: _DDContext,
    plan: _JobPlan,
    artifact: _Artifact,
    data: bytes,
) -> tuple[int, DDImportResult]:
    """Upload the artifact to DefectDojo, then project the resulting test's findings back.

    Two transactions on purpose.  The first uploads and commits the ``defectdojo_test_id`` onto
    the job row: once that id is durable, a failure in the second transaction resumes as a
    *re-import* against the same test rather than a fresh ``import-scan`` that would create a
    duplicate test (FR-018).  The second re-reads the job by that committed id inside
    :func:`app.services.finding.import_from_defectdojo`, which is why the id must be flushed
    before it runs -- ``autoflush`` is off on the session.
    """
    scan_type = scan_type_for(plan.scanner)

    async with session_scope(deps.settings) as session:
        job = await session.get(ScannerJob, plan.job_id)
        if job is None:  # pragma: no cover - the job was just listed in _plan_imports
            raise ResourceNotFoundError(
                "scanner job not found for import", context={"job_id": str(plan.job_id)}
            )
        existing_test_id = job.defectdojo_test_id
        if existing_test_id is None:
            result = await ctx.client.import_scan(
                engagement_id=ctx.engagement_id,
                scan_type=scan_type,
                file=data,
                filename=artifact.filename,
            )
        else:
            result = await ctx.client.reimport_scan(
                test_id=existing_test_id,
                engagement_id=ctx.engagement_id,
                scan_type=scan_type,
                file=data,
                filename=artifact.filename,
            )
        job.defectdojo_test_id = result.test_id

    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        findings = await import_from_defectdojo(
            session, assessment, client=ctx.client, test_id=result.test_id
        )
        return len(findings), result


# ---------------------------------------------------------------------------
# Bookkeeping: the empty case, the final count, and degradations
# ---------------------------------------------------------------------------


async def _record_empty(state: AssessmentState, *, deps: AgentDeps) -> None:
    """Record one completed step for the ``importing_findings`` stage when there was nothing to import.

    Not a degradation: an assessment whose scanners all degraded legitimately reaches import with
    no artifacts, and the scan node already recorded those degradations.  The step keeps the
    FR-038 checklist honest -- the stage ran, it simply had no input.
    """
    async with record_step(
        deps, state, node=_NODE, stage=AssessmentStage.IMPORT, label="Importing findings"
    ) as step:
        await step.thinking(_EMPTY_NOTE)
        step.record_output({"imported": 0, "jobs": 0})


async def _final_total(state: AssessmentState, *, deps: AgentDeps) -> int:
    """Read the assessment's authoritative finding total after all imports.

    Uses the counter :func:`app.services.finding.import_from_defectdojo` refreshed on each import
    rather than summing per-test counts: a finding seen by two scanners is one row, so summing
    the tests would over-count it.
    """
    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        return int(assessment.findings_total)


async def _degrade(
    state: AssessmentState,
    *,
    deps: AgentDeps,
    component: str,
    reason: str,
    impact: str,
) -> None:
    """Record an FR-039 degradation in its own transaction; never fail the run over it.

    ``record_degradation`` writes its own ASSESSMENT_DEGRADED audit row.  Bookkeeping, so a
    failure to persist the note degrades to a log line; ``except Exception`` leaves a
    ``CancelledError`` to propagate untouched (mirrors :mod:`app.agent.nodes.scan`).
    """
    try:
        async with session_scope(deps.settings) as session:
            assessment = await load_assessment(session, state)
            await record_degradation(
                session,
                assessment,
                stage=AssessmentStage.IMPORT,
                component=component,
                reason=reason,
                impact=impact,
            )
    except Exception as exc:
        log.warning("agent.import.degrade_record_failed", error=type(exc).__name__)


async def _emit(
    step: StepHandle,
    *,
    status: Literal["started", "succeeded", "failed"],
    summary: str,
    duration_ms: int | None = None,
) -> None:
    """Emit an FR-002 DefectDojo activity event through the step's emitter (counts only, SEC-002).

    Best-effort by construction: :meth:`EventEmitter.tool_call` publishes through the event bus,
    which swallows a Redis outage, so this never fails the import.
    """
    await step.emitter.tool_call(
        tool=_TOOL,
        status=status,
        summary=summary,
        duration_ms=duration_ms,
    )


def _import_summary(plan: _JobPlan, result: DDImportResult, count: int) -> str:
    """A counts-only, host-free summary line for the timeline (SEC-002)."""
    parts = [f"{count} {plan.label} finding{'' if count == 1 else 's'}"]
    if result.findings_created:
        parts.append(f"{result.findings_created} new")
    if result.findings_reactivated:
        parts.append(f"{result.findings_reactivated} reactivated")
    if result.findings_closed:
        parts.append(f"{result.findings_closed} closed")
    return "Imported " + ", ".join(parts) + " via DefectDojo."


__all__ = ["import_findings"]
