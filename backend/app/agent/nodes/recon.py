"""Node: recon -- passive reconnaissance and the first asset inventory (FR-007, FR-008).

Recon is the one node before the approval gate that runs a container, and it is deliberately
*passive*: ReconFTW is driven in its ``-p`` profile behind :func:`app.scanners.reconftw`'s
``_assert_passive`` guard, so nothing here sends a packet to a target -- only public sources
(DNS, certificate transparency, archives) are queried.  The active scanners wait behind the
FR-011 approval this stage's output populates.

**Why this node orchestrates the Docker runner itself instead of calling
:func:`app.services.job.execute_job`.**  ``execute_job`` is built for a fire-and-forget
worker: it purges the per-job workdir and commits its own session before returning, and it
exposes no seam between "the container finished" and "the output directory was deleted".
Recon needs exactly that seam -- it must read ReconFTW's ``out/`` tree with
:func:`~app.scanners.recon_assets.parse_recon_output` *before* the workdir is purged, because
recon's product is an **asset inventory**, not DefectDojo findings
(``ReconFTWAdapter.defectdojo_scan_type`` is ``None``).  So this node reuses every public
helper (:func:`~app.services.job.enqueue_job`, the slot primitives, the artifact helpers,
:func:`~app.scanners.registry.get_adapter`) and *replicates* the handful of private
job-lifecycle steps it needs -- each such helper below names the ``app.services.job._X`` it
mirrors, because that module is frozen and its underscored functions must not be imported.

**A failed recon is not a failed assessment (FR-040).**  Everything the scanner or its
bookkeeping can do wrong -- no capacity, a refused invocation, a crash, a timeout, a lost
upload -- is recorded on the job row and folded into an FR-039 degradation note; the run
proceeds to ``discovery`` with whatever inventory it has, which is at minimum the targets the
operator named.  Only a failure to persist that inventory or advance the state machine is
fatal, and that is left to :func:`record_step` to turn into a failed run.

The node transitions the assessment ``planning -> discovery`` with stage ``recon``.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import uuid
from dataclasses import dataclass
from pathlib import Path

import structlog
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from app.agent.nodes._common import load_assessment, record_step
from app.agent.registry import AgentDeps
from app.agent.state import AssessmentState, state_uuid
from app.core.config import Settings
from app.core.errors import ScannerError, StorageError
from app.core.targets import TargetType
from app.db.enums import (
    AssessmentStage,
    AssessmentStatus,
    AuditOutcome,
    JobStatus,
    RiskLevel,
    ScannerName,
)
from app.db.models.assessment import Assessment, AssessmentTarget
from app.db.models.scanner import ScannerArtifact, ScannerJob
from app.db.session import session_scope
from app.scanners.artifacts import (
    StoredArtifact,
    purge_workdir,
    upload_artifacts,
    write_stream_artifacts,
)
from app.scanners.base import ScannerRequest, ScannerResult
from app.scanners.recon_assets import (
    ASSET_TYPE_DOMAIN,
    ASSET_TYPE_HOST,
    ASSET_TYPE_SUBDOMAIN,
    MAX_NAME,
    DiscoveredAsset,
    clean,
    is_hostname,
    parse_recon_output,
)
from app.scanners.registry import get_adapter
from app.services import audit as audit_service
from app.services.assessment import record_degradation, transition
from app.services.asset import upsert_assets
from app.services.job import claim_slot, enqueue_job, release_slot

log = structlog.get_logger(__name__)

#: The most hostnames recon will dispatch in one run. ``ReconFTWAdapter.validate`` refuses
#: more than 50 targets (raising an ``UnsafeScannerInvocationError``); capping here keeps that
#: an invariant the node upholds rather than an error it has to catch and degrade on.
_MAX_RECON_HOSTS = 50

#: Restated from :data:`app.services.job._MAX_FAILURE_DETAIL`: the operator-facing tail of a
#: failure, bounded because the full stream is an authenticated-download artifact (SEC-002).
_MAX_FAILURE_DETAIL = 4000

#: Restated from :data:`app.services.job._HEARTBEAT_INTERVAL_SECONDS`. The heartbeat must beat
#: faster than :func:`app.services.job.reclaim_orphans`'s 300s stale window, or a healthy but
#: long recon would be reclaimed out from under itself.
_HEARTBEAT_INTERVAL_SECONDS = 30.0

#: How long to wait for a free concurrency slot before giving up and degrading. A minute of
#: bounded polling lets transient contention clear without blocking the graph indefinitely.
_SLOT_WAIT_SECONDS = 60.0
_SLOT_POLL_SECONDS = 3.0

#: Evidence stamped on a seed asset, matching the marker
#: :func:`~app.scanners.recon_assets.parse_recon_output` puts on its root-domain asset, so a
#: seed and its recon-discovered twin merge into one row with identical provenance.
_SEED_EVIDENCE: dict[str, str] = {"name": "assessment_target"}

_CAPACITY_NOTE = (
    "Passive reconnaissance was skipped because no scanner capacity was free; the inventory "
    "contains only the targets you named."
)
_FATAL_NOTE = (
    "Passive reconnaissance could not run, so asset discovery is limited to the targets you "
    "named."
)
_PARTIAL_NOTE = (
    "Passive reconnaissance ended early, so the discovered asset list may be incomplete."
)
_ARCHIVE_NOTE = (
    "Reconnaissance output could not be saved to storage; the discovered assets were kept "
    "but the raw files were not retained."
)


@dataclass(frozen=True, slots=True)
class _ReconPlan:
    """What the seeding transaction decided, carried into the runner phase without an ORM row.

    ``job_id`` is ``None`` when no target is passively recon-able (only IPs, CIDRs, repos):
    the container is skipped and the inventory is the seeds alone.
    """

    seeds: list[DiscoveredAsset]
    hosts: list[str]
    primary_domain: str | None
    job_id: uuid.UUID | None
    timeout_seconds: int


@dataclass(frozen=True, slots=True)
class _ReconOutcome:
    """The runner phase's result: assets parsed from ``out/`` and an optional degradation."""

    assets: list[DiscoveredAsset]
    degradation: str | None


async def recon(state: AssessmentState, *, deps: AgentDeps) -> dict[str, object]:
    """Run passive reconnaissance and record the discovered inventory (FR-007, FR-008)."""
    async with record_step(
        deps,
        state,
        node="recon",
        stage=AssessmentStage.RECON,
        label="Passive reconnaissance",
        tool_name="reconftw",
        input_digest={"depth": state.get("depth"), "scope": state.get("scope")},
    ) as step:
        plan = await _plan_recon(deps, state)
        await step.thinking(_intro(plan))

        outcome = _ReconOutcome(assets=[], degradation=None)
        if plan.job_id is not None:
            step.relabel(f"Passive reconnaissance of {len(plan.hosts)} target(s)")
            outcome = await _execute_recon(deps, state, step, plan)

        discovered = await _record_inventory(
            deps,
            state,
            seeds=plan.seeds,
            recon_assets=outcome.assets,
            degradation=outcome.degradation,
        )

        if outcome.degradation:
            step.degrade(outcome.degradation)
        step.record_output(
            {
                "seeded": len(plan.seeds),
                "recon_hosts": len(plan.hosts),
                "discovered": discovered,
            }
        )

    return {"stage": AssessmentStage.RECON.value}


# ---------------------------------------------------------------------------
# Planning: seed the named targets, enqueue recon on the recon-able hosts
# ---------------------------------------------------------------------------


async def _plan_recon(deps: AgentDeps, state: AssessmentState) -> _ReconPlan:
    """Seed the operator's targets and enqueue passive recon on the domain/URL hosts.

    One transaction: load the assessment with its targets, derive the seed asset set and the
    recon host list, and -- when any host is recon-able -- create the QUEUED job row (which
    audits the enqueue).  The job id and timeout are captured before the scope closes so the
    runner phase can work without holding a live ORM row across a multi-minute container.
    """
    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state, selectinload(Assessment.targets))
        targets = list(assessment.targets)
        seeds = [seed for seed in map(_seed_from_target, targets) if seed is not None]
        hosts = _recon_hosts(targets)
        primary = _primary_domain(targets)

        job_id: uuid.UUID | None = None
        timeout = 0
        if hosts:
            job = await enqueue_job(
                session, assessment, scanner=ScannerName.RECONFTW, targets=hosts
            )
            job_id = job.id
            timeout = job.timeout_seconds

    return _ReconPlan(
        seeds=seeds,
        hosts=hosts,
        primary_domain=primary,
        job_id=job_id,
        timeout_seconds=timeout,
    )


def _seed_from_target(target: AssessmentTarget) -> DiscoveredAsset | None:
    """Turn one validated target into a seed asset, or ``None`` for a non-network target.

    Every domain, URL, IP and CIDR target the operator named becomes an asset, so the
    inventory always contains what they asked about even when passive recon is skipped or
    fails.  Repository and container-image targets have no network identity and seed nothing.
    Hostnames are normalized exactly as :func:`parse_recon_output` normalizes them --
    ``clean(host.lower(), MAX_NAME)`` -- so a seed and a recon-discovered asset for the same
    host share the ``(name, port, protocol)`` key and merge into a single row.
    """
    ttype = target.target_type
    if ttype == TargetType.DOMAIN.value:
        name = _norm_host(target.host)
        if name:
            return DiscoveredAsset(
                name=name, asset_type=ASSET_TYPE_DOMAIN, evidence=dict(_SEED_EVIDENCE)
            )
    elif ttype == TargetType.URL.value:
        name = _norm_host(target.host)
        if name and is_hostname(name):
            return DiscoveredAsset(
                name=name, asset_type=ASSET_TYPE_SUBDOMAIN, evidence=dict(_SEED_EVIDENCE)
            )
        if name:
            return DiscoveredAsset(
                name=name,
                asset_type=ASSET_TYPE_HOST,
                ip_address=name,
                evidence=dict(_SEED_EVIDENCE),
            )
    elif ttype == TargetType.IP.value:
        name = _norm_host(target.host)
        if name:
            return DiscoveredAsset(
                name=name,
                asset_type=ASSET_TYPE_HOST,
                ip_address=name,
                evidence=dict(_SEED_EVIDENCE),
            )
    elif ttype == TargetType.CIDR.value:
        name = clean(target.canonical_value or target.host or "", MAX_NAME)
        if name:
            return DiscoveredAsset(
                name=name, asset_type=ASSET_TYPE_HOST, evidence=dict(_SEED_EVIDENCE)
            )
    return None


def _recon_hosts(targets: list[AssessmentTarget]) -> list[str]:
    """Distinct, passively-recon-able hostnames, capped at :data:`_MAX_RECON_HOSTS`.

    Only DOMAIN and URL targets carry a hostname worth passive DNS/certificate
    reconnaissance; an IP or CIDR has no name to enumerate subdomains under, and an IP-literal
    URL host (``is_hostname`` false) is dropped for the same reason.
    """
    hosts: list[str] = []
    for target in targets:
        if target.target_type not in (TargetType.DOMAIN.value, TargetType.URL.value):
            continue
        host = _norm_host(target.host)
        if host and is_hostname(host) and host not in hosts:
            hosts.append(host)
        if len(hosts) >= _MAX_RECON_HOSTS:
            break
    return hosts


def _primary_domain(targets: list[AssessmentTarget]) -> str | None:
    """The first DOMAIN target's hostname, handed to :func:`parse_recon_output` as its root.

    Only a true domain target is used: it is emitted as a ``domain`` asset even when recon
    finds no subdomains, so an assessment of one unremarkable domain still yields the asset
    the operator approved.  A URL host is not promoted to a root domain here.
    """
    for target in targets:
        if target.target_type == TargetType.DOMAIN.value:
            host = _norm_host(target.host)
            if host and is_hostname(host):
                return host
    return None


def _norm_host(value: str | None) -> str | None:
    """Normalize a hostname the way recon does, so seeds and discoveries share a key."""
    if not value:
        return None
    return clean(value.lower(), MAX_NAME)


def _intro(plan: _ReconPlan) -> str:
    """A platform-authored narration line (counts only -- no target names reach the socket)."""
    if plan.job_id is not None:
        return (
            f"Mapping the attack surface of {len(plan.hosts)} target(s) from public sources "
            "only -- nothing is sent to the targets themselves at this stage."
        )
    return (
        "No domain or web targets to map passively, so I am recording the targets you named "
        "as the starting inventory."
    )


# ---------------------------------------------------------------------------
# Execution: drive the runner directly so ``out/`` can be parsed before purge
# ---------------------------------------------------------------------------


async def _execute_recon(
    deps: AgentDeps,
    state: AssessmentState,
    step: object,
    plan: _ReconPlan,
) -> _ReconOutcome:
    """Run the ReconFTW container and return the assets it produced, degrading on any fault.

    Mirrors the shape of :func:`app.services.job.execute_job` -- admit a slot, mark RUNNING
    and commit so the job is observable and cancellable, heartbeat while the container runs,
    fold the result onto the row, archive artifacts, purge -- but parses the output directory
    for assets between the run and the purge, and never re-raises a :class:`ScannerError`
    (FR-040): a scanner fault becomes a recorded job failure and a degradation note.
    """
    settings = deps.settings
    org_id = state_uuid(state, "organization_id")
    assessment_id = state_uuid(state, "assessment_id")
    job_id = plan.job_id
    assert job_id is not None  # noqa: S101 - the caller only enters here with a job
    workdir = _workdir_for(settings, org_id, job_id)
    adapter = get_adapter(ScannerName.RECONFTW)

    if not await _acquire_slot(deps, org_id):
        await _fail_job(
            settings,
            job_id=job_id,
            org_id=org_id,
            code="scanner_no_capacity",
            detail="No scanner capacity was free for reconnaissance; try again shortly.",
        )
        return _ReconOutcome(assets=[], degradation=_CAPACITY_NOTE)

    await _mark_running(settings, job_id=job_id, org_id=org_id, target_count=len(plan.hosts))

    request = ScannerRequest(
        scanner=adapter.name,
        targets=tuple(plan.hosts),
        workdir=workdir,
        timeout_seconds=plan.timeout_seconds,
        options=_options_for(settings),
    )
    heartbeat = asyncio.create_task(_heartbeat(settings, job_id))
    result: ScannerResult | None = None
    fatal: ScannerError | None = None

    await _emit_tool(
        step, status="started", summary=f"Passive reconnaissance of {len(plan.hosts)} target(s)"
    )
    try:
        result = await deps.runner.run(
            adapter, request, cancel=lambda: _cancel_requested(settings, job_id)
        )
    except ScannerError as exc:
        # A refused invocation (>50 targets), an unreachable daemon, a crash or a timeout are
        # all this class. None of them fail the assessment -- they degrade it.
        fatal = exc
    finally:
        heartbeat.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await heartbeat
        await release_slot(deps.redis, settings, org_id)

    if result is None:
        assert fatal is not None  # noqa: S101 - the except above sets it whenever run raised
        await _fail_job(
            settings, job_id=job_id, org_id=org_id, code=fatal.code, detail=fatal.user_message
        )
        await _emit_tool(step, status="failed", summary="Reconnaissance could not run")
        return _ReconOutcome(assets=[], degradation=_FATAL_NOTE)

    # Parse before purge: this is the seam ``execute_job`` does not offer. ReconFTW's output
    # is an asset inventory, and the workdir is deleted two statements from now.
    assets = await asyncio.to_thread(
        parse_recon_output, request.out_dir, root_domain=plan.primary_domain
    )
    stored, archived = await _archive(
        deps,
        org_id=org_id,
        assessment_id=assessment_id,
        job_id=job_id,
        result=result,
        workdir=workdir,
    )
    status = await _finalize_job(
        settings,
        job_id=job_id,
        org_id=org_id,
        result=result,
        stored=stored,
        archived=archived,
        success_codes=adapter.success_exit_codes,
    )
    await asyncio.to_thread(purge_workdir, workdir)

    succeeded = status == JobStatus.COMPLETED.value
    await _emit_tool(
        step,
        status="succeeded" if succeeded else "failed",
        summary=f"Reconnaissance found {len(assets)} asset(s)",
        duration_ms=int(result.duration_seconds * 1000),
    )

    degradation: str | None = None
    if not succeeded:
        degradation = _PARTIAL_NOTE
    elif not archived:
        degradation = _ARCHIVE_NOTE
    return _ReconOutcome(assets=assets, degradation=degradation)


async def _emit_tool(
    step: object,
    *,
    status: str,
    summary: str,
    duration_ms: int | None = None,
) -> None:
    """Emit an FR-002 tool-activity event through the step's emitter (counts only, SEC-002)."""
    await step.emitter.tool_call(  # type: ignore[attr-defined]
        tool="reconftw",
        status=status,
        risk_level=RiskLevel.LOW,
        summary=summary,
        duration_ms=duration_ms,
    )


# ---------------------------------------------------------------------------
# Persistence: merge the inventory and advance to discovery
# ---------------------------------------------------------------------------


async def _record_inventory(
    deps: AgentDeps,
    state: AssessmentState,
    *,
    seeds: list[DiscoveredAsset],
    recon_assets: list[DiscoveredAsset],
    degradation: str | None,
) -> int:
    """Persist the merged inventory, advance to ``discovery``, and record any degradation.

    The durable product of the node.  Unlike the job bookkeeping, a failure here *is* fatal:
    the run cannot proceed without its asset inventory or its state transition, so this does
    not swallow errors -- :func:`record_step` marks the step failed and the runner fails the
    run.  :func:`transition` is idempotent on a no-op, so a re-run after a checkpoint restore
    that already reached ``discovery`` simply re-sets the stage.
    """
    async with session_scope(deps.settings) as session:
        assessment = await load_assessment(session, state)
        await upsert_assets(session, assessment, [*seeds, *recon_assets])
        await transition(
            session, assessment, AssessmentStatus.DISCOVERY, stage=AssessmentStage.RECON
        )
        if degradation:
            await record_degradation(
                session,
                assessment,
                stage=AssessmentStage.RECON,
                component="reconnaissance",
                reason=degradation,
                impact=(
                    "Asset discovery may be incomplete; only the assets observed and the "
                    "targets you named are listed."
                ),
            )
        return assessment.assets_discovered


# ---------------------------------------------------------------------------
# Replicated job-lifecycle steps
#
# Each mirrors a private helper in the frozen ``app.services.job`` module. They are
# reproduced rather than imported because those names are underscored (not part of the
# module's contract) and because recon needs its own session per concurrent user -- the
# heartbeat task and the cancel-check callback run at the same time and must not share one
# ``AsyncSession``.
# ---------------------------------------------------------------------------


def _workdir_for(settings: Settings, org_id: uuid.UUID, job_id: uuid.UUID) -> Path:
    """Per-job host directory, namespaced by org (mirrors ``job._workdir_for``)."""
    return Path(settings.scanner.artifact_workdir) / f"org-{org_id}" / f"job-{job_id}"


def _options_for(settings: Settings) -> dict[str, object]:
    """Adapter options -- scalars only, never a model-supplied passthrough (mirrors
    ``job._options_for``)."""
    return {
        "rate_limit": settings.scanner.max_concurrent_jobs_per_org * 25,
        "out_dir": "out",
    }


async def _acquire_slot(deps: AgentDeps, org_id: uuid.UUID) -> bool:
    """Claim one concurrency slot, waiting briefly for capacity (FR-014).

    :func:`claim_slot` fails closed on a Redis outage; the bounded poll lets transient
    contention clear without holding the graph open indefinitely.
    """
    attempts = max(1, int(_SLOT_WAIT_SECONDS / _SLOT_POLL_SECONDS))
    for attempt in range(attempts):
        if await claim_slot(deps.redis, deps.settings, org_id):
            return True
        if attempt + 1 < attempts:
            await asyncio.sleep(_SLOT_POLL_SECONDS)
    return False


async def _mark_running(
    settings: Settings, *, job_id: uuid.UUID, org_id: uuid.UUID, target_count: int
) -> None:
    """Mark the job RUNNING and audit the start, in its own committed transaction.

    Mirrors the RUNNING mark + ``SCANNER_START`` audit + pre-container commit in
    ``job.execute_job``: the committed RUNNING row is what makes the scan observable to the
    dashboard, reclaimable by :func:`~app.services.job.reclaim_orphans`, and cancellable.
    Best-effort -- a transient failure to flip the flag must not fail the assessment.
    """
    now = _now()
    try:
        async with session_scope(settings) as session:
            job = await session.get(ScannerJob, job_id)
            if job is None:
                return
            job.status = JobStatus.RUNNING.value
            job.started_at = now
            job.claimed_at = now
            job.heartbeat_at = now
            await audit_service.record(
                session,
                action=audit_service.AuditAction.SCANNER_START,
                principal=None,
                organization_id=org_id,
                resource_type="scanner_job",
                resource_id=job_id,
                detail={"scanner": ScannerName.RECONFTW.value, "targets": target_count},
            )
    except Exception as exc:
        log.warning("agent.recon.mark_running_failed", job_id=str(job_id), error=type(exc).__name__)


async def _heartbeat(settings: Settings, job_id: uuid.UUID) -> None:
    """Stamp ``heartbeat_at`` every interval on its own connection.

    Mirrors ``job._heartbeat`` but opens its own session: recon's heartbeat and cancel-check
    run concurrently during ``runner.run`` and cannot share one ``AsyncSession``.  A beat that
    raised would cancel the surrounding scope and kill a healthy scan over a transient blip, so
    per-beat failures are swallowed.
    """
    async with session_scope(settings) as session:
        while True:
            await asyncio.sleep(_HEARTBEAT_INTERVAL_SECONDS)
            try:
                await session.execute(
                    update(ScannerJob).where(ScannerJob.id == job_id).values(heartbeat_at=_now())
                )
                await session.commit()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning(
                    "agent.recon.heartbeat_failed", job_id=str(job_id), error=type(exc).__name__
                )
                with contextlib.suppress(Exception):
                    await session.rollback()


async def _cancel_requested(settings: Settings, job_id: uuid.UUID) -> bool:
    """Read the cancel flag from the database on its own connection.

    Mirrors ``job._cancel_requested``.  A separate short-lived session from the heartbeat's:
    the runner invokes this concurrently with the heartbeat task, and one ``AsyncSession``
    cannot serve two concurrent operations.  A failed read returns ``False`` -- a transient DB
    error must never be read as a cancel and stop a healthy scan.
    """
    try:
        async with session_scope(settings) as session:
            value = (
                await session.execute(
                    select(ScannerJob.cancel_requested).where(ScannerJob.id == job_id)
                )
            ).scalar_one_or_none()
        return bool(value)
    except Exception as exc:
        log.warning("agent.recon.cancel_check_failed", job_id=str(job_id), error=type(exc).__name__)
        return False


async def _archive(
    deps: AgentDeps,
    *,
    org_id: uuid.UUID,
    assessment_id: uuid.UUID,
    job_id: uuid.UUID,
    result: ScannerResult,
    workdir: Path,
) -> tuple[list[StoredArtifact], bool]:
    """Upload every artifact plus the captured streams. Returns ``(stored, archived)``.

    Mirrors ``job._archive`` combined with ``execute_job``'s ``StorageError`` branch: a lost
    upload is a degradation on an otherwise real result (FR-040), not a failure, so it returns
    ``archived=False`` rather than raising.
    """
    if not deps.storage.configured:
        log.warning("agent.recon.storage_unconfigured", job_id=str(job_id))
        return [], False
    try:
        streams = write_stream_artifacts(
            workdir, stdout=result.stdout_tail, stderr=result.stderr_tail
        )
        stored = await upload_artifacts(
            deps.storage,
            organization_id=org_id,
            assessment_id=assessment_id,
            job_id=job_id,
            artifacts=(*result.artifacts, *streams),
        )
    except StorageError as exc:
        log.warning("agent.recon.archive_failed", job_id=str(job_id), error=exc.code)
        return [], False
    return stored, bool(stored)


async def _finalize_job(
    settings: Settings,
    *,
    job_id: uuid.UUID,
    org_id: uuid.UUID,
    result: ScannerResult,
    stored: list[StoredArtifact],
    archived: bool,
    success_codes: frozenset[int],
) -> str:
    """Fold the runner result onto the job row, add artifact rows, write the terminal audit.

    Mirrors the terminal block of ``job.execute_job``.  Best-effort and returns the terminal
    status either way: recon's real product is the parsed assets, so a bookkeeping failure
    here degrades to a log line rather than failing the assessment (FR-040).
    """
    status = _status_for(result, success_codes)
    try:
        async with session_scope(settings) as session:
            job = await session.get(ScannerJob, job_id)
            if job is None:
                return status
            job.artifacts_archived = archived
            _apply_result_to_job(job, result, success_codes)
            for row in stored:
                session.add(
                    ScannerArtifact(
                        organization_id=org_id,
                        job_id=job_id,
                        kind=row.kind.value,
                        filename=row.filename,
                        storage_key=row.storage_key,
                        content_type=row.content_type,
                        size_bytes=row.size_bytes,
                        sha256=row.sha256,
                    )
                )
            await audit_service.record(
                session,
                action=_terminal_action(status),
                principal=None,
                organization_id=org_id,
                resource_type="scanner_job",
                resource_id=job_id,
                outcome=_terminal_outcome(status),
                detail={
                    "scanner": ScannerName.RECONFTW.value,
                    "status": status,
                    "exit_code": result.exit_code,
                    "duration_seconds": int(result.duration_seconds),
                    "artifacts": len(stored),
                },
            )
            return status
    except Exception as exc:
        log.warning("agent.recon.finalize_failed", job_id=str(job_id), error=type(exc).__name__)
        return status


async def _fail_job(
    settings: Settings, *, job_id: uuid.UUID, org_id: uuid.UUID, code: str, detail: str
) -> None:
    """Record a job that produced no result (mirrors ``job._finalize_failure``).

    Best-effort and self-contained: recon records the failure on the row and then degrades the
    assessment rather than propagating (FR-040).
    """
    now = _now()
    try:
        async with session_scope(settings) as session:
            job = await session.get(ScannerJob, job_id)
            if job is None:
                return
            job.status = JobStatus.FAILED.value
            job.completed_at = now
            job.failure_code = code[:60]
            job.failure_detail = detail[:_MAX_FAILURE_DETAIL]
            if job.started_at is not None:
                job.duration_seconds = max(0, int((now - job.started_at).total_seconds()))
            await audit_service.record(
                session,
                action=audit_service.AuditAction.SCANNER_FAIL,
                principal=None,
                organization_id=org_id,
                resource_type="scanner_job",
                resource_id=job_id,
                outcome=AuditOutcome.FAILURE,
                detail={"scanner": ScannerName.RECONFTW.value, "failure_code": code[:60]},
            )
    except Exception as exc:
        log.warning("agent.recon.fail_record_failed", job_id=str(job_id), error=type(exc).__name__)


def _apply_result_to_job(
    job: ScannerJob, result: ScannerResult, success_codes: frozenset[int]
) -> None:
    """Fold a :class:`ScannerResult` onto the job row (mirrors ``job._apply_result``).

    Status precedence is cancelled, then timeout, then exit code -- a cancelled run that also
    timed out is a cancellation, because the operator asked for it and reporting TIMEOUT would
    read as a failure they did not cause.
    """
    job.argv = list(result.argv)
    job.image = result.image
    job.container_id = result.container_id
    job.exit_code = result.exit_code
    job.sandbox = dict(result.sandbox)
    job.completed_at = _now()
    job.duration_seconds = int(result.duration_seconds)

    status = _status_for(result, success_codes)
    job.status = status
    if status == JobStatus.CANCELLED.value:
        job.failure_code = "scanner_cancelled"
        job.failure_detail = "The scan was cancelled by an operator."
    elif status == JobStatus.TIMEOUT.value:
        job.failure_code = "scanner_timeout"
        job.failure_detail = (
            f"The scan exceeded its {job.timeout_seconds}s limit and was stopped. "
            "Any output produced before then was kept."
        )
    elif status == JobStatus.COMPLETED.value:
        job.failure_code = None
        job.failure_detail = None
    else:
        job.failure_code = "scanner_exit_nonzero"
        # The tail, not the whole stream: stderr routinely names target hosts, and the full
        # capture is already an authenticated-download artifact (SEC-002).
        job.failure_detail = (
            f"The scanner exited with code {result.exit_code}.\n{result.stderr_tail}"
        )[:_MAX_FAILURE_DETAIL]


def _status_for(result: ScannerResult, success_codes: frozenset[int]) -> str:
    """The terminal job status for a result, by the precedence in :func:`_apply_result_to_job`."""
    if result.cancelled:
        return JobStatus.CANCELLED.value
    if result.timed_out:
        return JobStatus.TIMEOUT.value
    if result.exit_code in success_codes:
        return JobStatus.COMPLETED.value
    return JobStatus.FAILED.value


def _terminal_action(status: str) -> str:
    """The audit action for a terminal status (mirrors ``job._terminal_audit_action``)."""
    if status == JobStatus.COMPLETED.value:
        return audit_service.AuditAction.SCANNER_COMPLETE
    if status == JobStatus.TIMEOUT.value:
        return audit_service.AuditAction.SCANNER_TIMEOUT
    if status == JobStatus.CANCELLED.value:
        return audit_service.AuditAction.SCANNER_CANCEL
    return audit_service.AuditAction.SCANNER_FAIL


def _terminal_outcome(status: str) -> AuditOutcome:
    """The audit outcome for a terminal status (mirrors ``job._terminal_outcome``)."""
    if status == JobStatus.COMPLETED.value:
        return AuditOutcome.SUCCESS
    if status == JobStatus.CANCELLED.value:
        return AuditOutcome.DENIED
    return AuditOutcome.FAILURE


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = ["recon"]
