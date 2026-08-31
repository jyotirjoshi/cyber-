"""Scanner job lifecycle: enqueue, admission control, execute, cancel (FR-012 .. FR-015).

The module that turns "we are authorized to scan these targets" into a container that ran
and a row that says exactly how.  Four decisions shape it.

**A failed scanner is not a failed assessment.**  :func:`execute_job` catches everything a
scanner can do to itself -- non-zero exit, timeout, crash, missing output -- and records it
on the job row.  It re-raises only for conditions where running at all was wrong: an argv
the sandbox refused, an image outside the allow list, an unreachable Docker daemon.  FR-040
requires the assessment to continue with a degradation note rather than collapsing because
Nuclei hit a rate limit.

**Concurrency is admitted, not queued in memory.**  :func:`claim_slot` takes a Redis counter
per organization and one global.  Bounding it in the worker process would silently allow
``N_workers x limit`` containers on the host, which is how a scan fleet turns into an
outage.  Slots carry a TTL so a worker killed mid-scan leaks a slot for minutes rather than
until someone restarts Redis.

**Artifacts are uploaded before the job is marked complete.**  A COMPLETED job whose output
never reached object storage is worse than a failed one: the import step will read no
findings and report a clean scan.

**Cancellation is cooperative.**  :func:`request_cancel` sets a flag; the runner's poll loop
reads it through the callback :func:`execute_job` supplies.  A cancel that lands after the
container exited is recorded but does not rewrite the terminal status -- FR-039 asks for the
scan to stop, not for history to change.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import shutil
import uuid
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import Any

import structlog
from redis.asyncio import Redis
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.core.errors import (
    ConflictError,
    CynuxError,
    DockerUnavailableError,
    ScannerError,
    StorageError,
    UnsafeScannerInvocationError,
    UserError,
)
from app.db.enums import AuditOutcome, JobStatus, Permission, ScannerName
from app.db.models.assessment import Assessment
from app.db.models.scanner import ScannerArtifact, ScannerJob
from app.db.repository import TenantRepository, tenant_select
from app.integrations.storage import ObjectStorage
from app.scanners.artifacts import StoredArtifact, upload_artifacts, write_stream_artifacts
from app.scanners.base import ScannerRequest, ScannerResult
from app.scanners.registry import get_adapter
from app.scanners.runner import DockerRunner
from app.schemas.common import PaginationParams
from app.schemas.job import JobFilter
from app.services import audit as audit_service
from app.services.context import Principal

log = structlog.get_logger(__name__)

#: Redis key prefix for the admission counters. Separate from the rate-limit namespace so a
#: flush of one cannot silently raise the concurrency ceiling of the other.
_SLOT_NAMESPACE = "cynux:scanner:slots"

#: Slot TTL. Longer than the longest permitted job (6h) plus upload time, so a slot is never
#: reclaimed under a container that is still running; short enough that a worker lost to a
#: SIGKILL does not hold capacity forever.
_SLOT_TTL_SECONDS = 8 * 60 * 60

#: How often the executing job's heartbeat is written. Orphan detection compares this against
#: ``now``, so the interval sets the detection floor.
_HEARTBEAT_INTERVAL_SECONDS = 30.0

#: Cap on ``failure_detail``. The full stream is an artifact; this is the operator-facing tail.
_MAX_FAILURE_DETAIL = 4000


async def enqueue_job(
    session: AsyncSession,
    assessment: Assessment,
    *,
    scanner: ScannerName | str,
    targets: Sequence[str],
    timeout_seconds: int | None = None,
) -> ScannerJob:
    """Create a QUEUED job row.

    ``targets`` must already be canonical strings from
    :func:`app.core.targets.validate_target` -- this function does not re-validate, and must
    not: re-deriving a target from a raw string here would be a second, weaker code path
    around the policy check, which is exactly the shape of bug FR-006 exists to prevent.

    The adapter is resolved eagerly so an unknown scanner name fails here rather than in the
    worker, where the operator has already approved a scan that cannot dispatch.
    """
    adapter = get_adapter(scanner)
    canonical = [t for t in dict.fromkeys(targets) if t]
    if not canonical:
        raise UserError(
            "cannot enqueue a scanner job with no targets",
            user_message="There are no targets in scope for this scan.",
            context={"assessment_id": str(assessment.id), "scanner": str(adapter.name)},
        )

    cfg = _scanner_settings_or_default(timeout_seconds)
    job = ScannerJob(
        organization_id=assessment.organization_id,
        assessment_id=assessment.id,
        scanner=adapter.name.value,
        status=JobStatus.QUEUED.value,
        targets=canonical,
        argv=[],
        sandbox={},
        timeout_seconds=cfg,
    )
    session.add(job)
    await session.flush()

    await audit_service.record(
        session,
        action=audit_service.AuditAction.SCANNER_ENQUEUE,
        principal=None,
        organization_id=assessment.organization_id,
        resource_type="scanner_job",
        resource_id=job.id,
        detail={
            "scanner": job.scanner,
            "assessment_id": str(assessment.id),
            "target_count": len(canonical),
            "timeout_seconds": job.timeout_seconds,
        },
    )
    log.info(
        "job.enqueued",
        job_id=str(job.id),
        scanner=job.scanner,
        assessment_id=str(assessment.id),
        target_count=len(canonical),
    )
    return job


async def claim_slot(redis: Redis, settings: Settings, organization_id: uuid.UUID) -> bool:
    """Try to take one concurrency slot. ``True`` on success.

    Two counters, incremented in one pipeline: the organization's and the deployment's.  Both
    are checked after the increment and rolled back on refusal, which is the standard
    INCR-then-compare admission pattern -- a check-then-increment would let two workers both
    observe capacity and both take the last slot.

    Redis being unreachable returns ``False``.  Failing closed is the only safe direction:
    admitting without a counter means admitting without a limit, on a host whose memory the
    containers share.
    """
    org_key = f"{_SLOT_NAMESPACE}:org:{organization_id}"
    global_key = f"{_SLOT_NAMESPACE}:global"
    cfg = settings.scanner

    try:
        pipe = redis.pipeline()
        pipe.incr(org_key)
        pipe.expire(org_key, _SLOT_TTL_SECONDS)
        pipe.incr(global_key)
        pipe.expire(global_key, _SLOT_TTL_SECONDS)
        org_count, _, global_count, _ = await pipe.execute()
    except Exception as exc:
        log.warning(
            "job.slot_claim_failed",
            organization_id=str(organization_id),
            error=type(exc).__name__,
        )
        return False

    if int(org_count) <= cfg.max_concurrent_jobs_per_org and (
        int(global_count) <= cfg.max_concurrent_jobs_global
    ):
        return True

    # Refused: give both counters back before returning, or the ceiling ratchets downward
    # with every rejected attempt.
    await release_slot(redis, settings, organization_id)
    log.info(
        "job.slot_refused",
        organization_id=str(organization_id),
        org_count=int(org_count),
        org_limit=cfg.max_concurrent_jobs_per_org,
        global_count=int(global_count),
        global_limit=cfg.max_concurrent_jobs_global,
    )
    return False


async def release_slot(redis: Redis, settings: Settings, organization_id: uuid.UUID) -> None:
    """Return one slot. Safe to call twice; never raises.

    Clamped at zero via ``DECR`` followed by a floor check, because a double release that
    drove the counter negative would grant free capacity on the next claim.
    """
    org_key = f"{_SLOT_NAMESPACE}:org:{organization_id}"
    global_key = f"{_SLOT_NAMESPACE}:global"
    try:
        pipe = redis.pipeline()
        pipe.decr(org_key)
        pipe.decr(global_key)
        org_count, global_count = await pipe.execute()
        if int(org_count) < 0:
            await redis.set(org_key, 0)
        if int(global_count) < 0:
            await redis.set(global_key, 0)
    except Exception as exc:  # pragma: no cover - release must never mask the real error
        log.warning(
            "job.slot_release_failed",
            organization_id=str(organization_id),
            error=type(exc).__name__,
        )


async def slot_usage(redis: Redis, organization_id: uuid.UUID) -> tuple[int, int]:
    """``(organization_in_use, global_in_use)``, for the dashboard and for tests."""
    try:
        values = await redis.mget(
            f"{_SLOT_NAMESPACE}:org:{organization_id}", f"{_SLOT_NAMESPACE}:global"
        )
    except Exception:
        return 0, 0
    return tuple(max(0, int(v or 0)) for v in values)  # type: ignore[return-value]


async def execute_job(
    session: AsyncSession,
    job: ScannerJob,
    *,
    runner: DockerRunner,
    storage: ObjectStorage,
    settings: Settings,
    on_log: Callable[[str], Awaitable[None]] | None = None,
    worker_id: str | None = None,
) -> ScannerJob:
    """Run one queued job to a terminal state and persist everything observed.

    Commits at two points -- after marking RUNNING, and at the end -- so a worker that dies
    mid-scan leaves a RUNNING row with a stale heartbeat (visible, reclaimable) rather than a
    QUEUED row that a second worker will happily run again.

    Returns the same job instance, refreshed.  Raises only for the "should not have run"
    conditions listed in the module docstring; every scanner-level failure is on the row.
    """
    if job.status not in (JobStatus.QUEUED.value, JobStatus.RUNNING.value):
        raise ConflictError(
            "job is already terminal",
            user_message="That scan has already finished.",
            context={"job_id": str(job.id), "status": job.status},
        )

    adapter = get_adapter(job.scanner)
    workdir = _workdir_for(settings, job)
    now = _now()

    job.status = JobStatus.RUNNING.value
    job.started_at = now
    job.claimed_at = now
    job.heartbeat_at = now
    job.worker_id = worker_id
    await audit_service.record(
        session,
        action=audit_service.AuditAction.SCANNER_START,
        principal=None,
        organization_id=job.organization_id,
        resource_type="scanner_job",
        resource_id=job.id,
        detail={"scanner": job.scanner, "worker_id": worker_id, "targets": len(job.targets)},
    )
    # Committed before the container starts: the RUNNING row is what makes the scan
    # observable, and a scan nobody can see is a scan nobody can cancel.
    await session.commit()

    request = ScannerRequest(
        scanner=adapter.name,
        targets=tuple(job.targets),
        workdir=workdir,
        timeout_seconds=job.timeout_seconds,
        options=_options_for(job, settings),
    )
    heartbeat = asyncio.create_task(_heartbeat(session, job.id))
    result: ScannerResult | None = None
    fatal: CynuxError | None = None

    try:
        result = await runner.run(
            adapter,
            request,
            on_log=on_log,
            cancel=lambda: _cancel_requested(session, job.id),
        )
    except (UnsafeScannerInvocationError, DockerUnavailableError) as exc:
        # Not a scanner failure -- a refusal to run, or an environment that cannot. Recorded
        # on the row *and* re-raised, because the caller must degrade the assessment rather
        # than treat this as "the scanner found nothing".
        fatal = exc
    except ScannerError as exc:
        fatal = exc
    finally:
        heartbeat.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await heartbeat

    if result is None:
        assert fatal is not None  # noqa: S101 - narrowing; both branches above set one
        await _finalize_failure(session, job, fatal)
        await _purge(workdir)
        await session.commit()
        raise fatal

    try:
        stored = await _archive(storage, job, result, workdir)
    except StorageError as exc:
        # The scan itself succeeded. Losing the upload is a degradation on an otherwise real
        # result, so it is recorded and the job is *not* marked COMPLETED -- see docstring.
        log.warning("job.archive_failed", job_id=str(job.id), error=exc.code)
        stored = []
        job.artifacts_archived = False
    else:
        job.artifacts_archived = bool(stored)

    _apply_result(job, result, adapter_success_codes=adapter.success_exit_codes)
    for row in stored:
        session.add(
            ScannerArtifact(
                organization_id=job.organization_id,
                job_id=job.id,
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
        action=_terminal_audit_action(job),
        principal=None,
        organization_id=job.organization_id,
        resource_type="scanner_job",
        resource_id=job.id,
        outcome=_terminal_outcome(job),
        detail={
            "scanner": job.scanner,
            "status": job.status,
            "exit_code": job.exit_code,
            "duration_seconds": job.duration_seconds,
            "artifacts": len(stored),
        },
    )
    await _purge(workdir)
    await session.commit()
    log.info(
        "job.finished",
        job_id=str(job.id),
        scanner=job.scanner,
        status=job.status,
        exit_code=job.exit_code,
        duration_seconds=job.duration_seconds,
        artifacts=len(stored),
    )
    return job


async def request_cancel(
    session: AsyncSession,
    principal: Principal,
    job_id: uuid.UUID,
) -> ScannerJob:
    """Ask a running job to stop (FR-039).

    Sets the flag with a conditional UPDATE against the active statuses.  A cancel on a job
    that finished a moment ago is a no-op with an audit row rather than an error: from the
    operator's point of view the scan did stop, and an error there would read as "the cancel
    failed" when in fact nothing is still running.
    """
    principal.require(Permission.ASSESSMENT_CANCEL)
    repo: TenantRepository[ScannerJob] = TenantRepository(
        session, ScannerJob, principal.organization_id
    )
    job = await repo.get_or_404(job_id)
    now = _now()

    result = await session.execute(
        update(ScannerJob)
        .where(
            ScannerJob.id == job.id,
            ScannerJob.organization_id == principal.organization_id,
            ScannerJob.status.in_([JobStatus.QUEUED.value, JobStatus.RUNNING.value]),
        )
        .values(
            cancel_requested=True, cancel_requested_at=now, cancel_requested_by_id=principal.user_id
        )
    )
    applied = (result.rowcount or 0) == 1
    if applied:
        # The UPDATE bypassed the identity map, so the in-memory row is stale.
        await session.refresh(job)

    await audit_service.record(
        session,
        action=audit_service.AuditAction.SCANNER_CANCEL,
        principal=principal,
        resource_type="scanner_job",
        resource_id=job.id,
        detail={"scanner": job.scanner, "status": job.status, "applied": applied},
    )
    log.info(
        "job.cancel_requested",
        job_id=str(job.id),
        scanner=job.scanner,
        status=job.status,
        applied=applied,
    )
    return job


async def cancel_jobs_for_assessment(
    session: AsyncSession,
    assessment: Assessment,
    *,
    principal: Principal | None = None,
) -> int:
    """Flag every active job on an assessment. Returns the number flagged.

    Called by the cancel endpoint and by the error node.  One statement rather than a loop:
    the point of cancelling an assessment is that all of its scans stop, and doing it row by
    row leaves a window where some are still starting.
    """
    now = _now()
    result = await session.execute(
        update(ScannerJob)
        .where(
            ScannerJob.assessment_id == assessment.id,
            ScannerJob.organization_id == assessment.organization_id,
            ScannerJob.status.in_([JobStatus.QUEUED.value, JobStatus.RUNNING.value]),
        )
        .values(
            cancel_requested=True,
            cancel_requested_at=now,
            cancel_requested_by_id=principal.user_id if principal else None,
        )
    )
    count = result.rowcount or 0
    if count:
        await audit_service.record(
            session,
            action=audit_service.AuditAction.SCANNER_CANCEL,
            principal=principal,
            organization_id=assessment.organization_id,
            resource_type="assessment",
            resource_id=assessment.id,
            detail={"jobs_flagged": count},
        )
    return count


async def get_job(
    session: AsyncSession,
    principal: Principal,
    job_id: uuid.UUID,
) -> ScannerJob:
    """One job with its artifacts, tenant-scoped."""
    principal.require(Permission.ASSESSMENT_READ)
    repo: TenantRepository[ScannerJob] = TenantRepository(
        session, ScannerJob, principal.organization_id
    )
    return await repo.get_or_404(job_id, selectinload(ScannerJob.artifacts))


async def list_jobs(
    session: AsyncSession,
    principal: Principal,
    *,
    filters: JobFilter | None = None,
    pagination: PaginationParams | None = None,
) -> tuple[Sequence[ScannerJob], int]:
    """Jobs, newest first. Returns ``(rows, total)``."""
    principal.require(Permission.ASSESSMENT_READ)
    filters = filters or JobFilter()
    page = pagination or PaginationParams()

    conditions: list[Any] = []
    if filters.assessment_id is not None:
        conditions.append(ScannerJob.assessment_id == filters.assessment_id)
    if filters.scanner is not None:
        conditions.append(ScannerJob.scanner == filters.scanner.value)
    if filters.status is not None:
        conditions.append(ScannerJob.status == filters.status.value)
    if filters.active is not None:
        active = ScannerJob.status.in_([JobStatus.QUEUED.value, JobStatus.RUNNING.value])
        conditions.append(active if filters.active else ~active)

    total = int(
        (
            await session.execute(
                select(func.count())
                .select_from(ScannerJob)
                .where(ScannerJob.organization_id == principal.organization_id, *conditions)
            )
        ).scalar_one()
    )
    stmt = (
        tenant_select(ScannerJob, principal.organization_id, selectinload(ScannerJob.artifacts))
        .where(*conditions)
        .order_by(ScannerJob.created_at.desc(), ScannerJob.id.desc())
        .limit(page.limit)
        .offset(page.offset)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return rows, total


async def jobs_for_assessment(
    session: AsyncSession,
    assessment_id: uuid.UUID,
    *,
    organization_id: uuid.UUID,
) -> list[ScannerJob]:
    """Every job on an assessment, oldest first, with artifacts eagerly loaded.

    Used by the import and report stages, which need the artifact rows to cite.  Takes an
    organization id rather than a principal: the agent has no user identity, and its
    authority came from the approval row.
    """
    stmt = (
        tenant_select(ScannerJob, organization_id, selectinload(ScannerJob.artifacts))
        .where(ScannerJob.assessment_id == assessment_id)
        .order_by(ScannerJob.created_at, ScannerJob.id)
    )
    return list((await session.execute(stmt)).scalars().all())


async def artifact_download_url(
    session: AsyncSession,
    principal: Principal,
    job_id: uuid.UUID,
    artifact_id: uuid.UUID,
    *,
    storage: ObjectStorage,
    ttl_seconds: int = 300,
) -> str:
    """A short-lived presigned URL for one artifact.

    The tenant check happens twice on purpose: once through the repository, and again inside
    :meth:`ObjectStorage.presign_get`, which verifies the key's ``org/{id}/`` prefix.  The
    second check is what makes a bug in the first one non-exploitable (SEC-003).
    """
    principal.require(Permission.ASSESSMENT_READ)
    job = await get_job(session, principal, job_id)
    artifact = next((a for a in job.artifacts if a.id == artifact_id), None)
    if artifact is None:
        raise ConflictError(
            "artifact does not belong to this job",
            user_message="That file is not part of this scan.",
            context={"job_id": str(job_id), "artifact_id": str(artifact_id)},
        )
    return await storage.presign_get(
        artifact.storage_key,
        ttl_seconds=ttl_seconds,
        organization_id=principal.organization_id,
        download_name=artifact.filename,
    )


async def reclaim_orphans(
    session: AsyncSession,
    *,
    stale_after_seconds: int = 300,
) -> int:
    """Fail jobs whose worker stopped heartbeating. Returns the count.

    A RUNNING job with a heartbeat five minutes old means the worker died; the container is
    either gone with it or orphaned and will be reaped by Docker.  Marked FAILED rather than
    re-queued: the workdir has been purged, so a retry would run against a directory that no
    longer exists, and a scan silently repeating itself is worse than one that visibly failed.
    """
    cutoff = _now() - dt.timedelta(seconds=stale_after_seconds)
    result = await session.execute(
        update(ScannerJob)
        .where(
            ScannerJob.status == JobStatus.RUNNING.value,
            ScannerJob.heartbeat_at.is_not(None),
            ScannerJob.heartbeat_at < cutoff,
        )
        .values(
            status=JobStatus.FAILED.value,
            completed_at=_now(),
            failure_code="scanner_worker_lost",
            failure_detail="The worker running this scan stopped responding.",
        )
    )
    count = result.rowcount or 0
    if count:
        log.warning("job.orphans_reclaimed", count=count, stale_after_seconds=stale_after_seconds)
    return count


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _scanner_settings_or_default(timeout_seconds: int | None) -> int:
    """Clamp a requested timeout into the ``timeout_bounds`` CHECK range.

    Clamped rather than rejected: the caller is the planning node, and a plan asking for
    eight hours should produce a six-hour scan, not a failed assessment.  The DB constraint
    is the backstop, not the validator.
    """
    if timeout_seconds is None:
        return 1800
    return max(1, min(int(timeout_seconds), 21_600))


def _workdir_for(settings: Settings, job: ScannerJob) -> Path:
    """Per-job host directory. Namespaced by organization so a path traversal in one
    tenant's scanner output cannot reach another's."""
    return Path(settings.scanner.artifact_workdir) / f"org-{job.organization_id}" / f"job-{job.id}"


def _options_for(job: ScannerJob, settings: Settings) -> dict[str, Any]:
    """Adapter options derived from the job row and settings.

    Only ever carries scalars the adapters declare. Notably *not* a passthrough of anything
    model-supplied: an option dict wide enough to hold a flag is a way to smuggle one past
    the argv allow-list.
    """
    return {
        "rate_limit": settings.scanner.max_concurrent_jobs_per_org * 25,
        "out_dir": "out",
    }


async def _heartbeat(session: AsyncSession, job_id: uuid.UUID) -> None:
    """Stamp ``heartbeat_at`` while the container runs.

    Uses its own short transaction per beat and swallows failures: a heartbeat that raised
    would cancel the surrounding task group and kill a healthy scan over a transient DB blip.
    """
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
            log.warning("job.heartbeat_failed", job_id=str(job_id), error=type(exc).__name__)
            with contextlib.suppress(Exception):
                await session.rollback()


async def _cancel_requested(session: AsyncSession, job_id: uuid.UUID) -> bool:
    """Read the cancel flag straight from the database.

    Deliberately not from the in-memory row: the flag is set by the API process, so the
    worker's copy would never change.  A failed read returns ``False`` -- a transient DB
    error must not be interpreted as a cancel and kill a running scan.
    """
    try:
        value = (
            await session.execute(
                select(ScannerJob.cancel_requested).where(ScannerJob.id == job_id)
            )
        ).scalar_one_or_none()
    except Exception as exc:
        log.warning("job.cancel_check_failed", job_id=str(job_id), error=type(exc).__name__)
        return False
    return bool(value)


def _apply_result(
    job: ScannerJob,
    result: ScannerResult,
    *,
    adapter_success_codes: frozenset[int],
) -> None:
    """Fold a :class:`ScannerResult` onto the job row.

    Status precedence is cancelled, then timeout, then exit code.  A cancelled run that also
    hit its timeout is a cancellation: the operator asked for it, and reporting TIMEOUT would
    tell them their scan failed when in fact they stopped it.
    """
    job.argv = list(result.argv)
    job.image = result.image
    job.container_id = result.container_id
    job.exit_code = result.exit_code
    job.sandbox = dict(result.sandbox)
    job.completed_at = _now()
    job.duration_seconds = int(result.duration_seconds)

    if result.cancelled:
        job.status = JobStatus.CANCELLED.value
        job.failure_code = "scanner_cancelled"
        job.failure_detail = "The scan was cancelled by an operator."
        return
    if result.timed_out:
        job.status = JobStatus.TIMEOUT.value
        job.failure_code = "scanner_timeout"
        job.failure_detail = (
            f"The scan exceeded its {job.timeout_seconds}s limit and was stopped. "
            "Any output produced before then was kept."
        )
        return
    if result.exit_code in adapter_success_codes:
        job.status = JobStatus.COMPLETED.value
        job.failure_code = None
        job.failure_detail = None
        return

    job.status = JobStatus.FAILED.value
    job.failure_code = "scanner_exit_nonzero"
    # The tail, not the whole stream: stderr routinely contains target hostnames, and the
    # full capture is already an artifact behind an authenticated download (SEC-002).
    job.failure_detail = (
        f"The scanner exited with code {result.exit_code}.\n{result.stderr_tail}"
    )[:_MAX_FAILURE_DETAIL]


async def _finalize_failure(session: AsyncSession, job: ScannerJob, error: CynuxError) -> None:
    """Record a job that never produced a result."""
    job.status = JobStatus.FAILED.value
    job.completed_at = _now()
    job.failure_code = error.code
    job.failure_detail = error.user_message[:_MAX_FAILURE_DETAIL]
    if job.started_at is not None:
        job.duration_seconds = max(0, int((job.completed_at - job.started_at).total_seconds()))
    await audit_service.record(
        session,
        action=audit_service.AuditAction.SCANNER_FAIL,
        principal=None,
        organization_id=job.organization_id,
        resource_type="scanner_job",
        resource_id=job.id,
        outcome=AuditOutcome.FAILURE,
        detail={"scanner": job.scanner, "failure_code": error.code},
    )
    log.warning(
        "job.failed_before_result",
        job_id=str(job.id),
        scanner=job.scanner,
        failure_code=error.code,
    )


async def _archive(
    storage: ObjectStorage,
    job: ScannerJob,
    result: ScannerResult,
    workdir: Path,
) -> list[StoredArtifact]:
    """Upload every artifact plus the captured streams.

    Streams are written to disk first so they travel the same code path as scanner output --
    one uploader, one hashing routine, one place where a key is namespaced by tenant.
    """
    if not storage.configured:
        log.warning("job.storage_unconfigured", job_id=str(job.id))
        return []
    streams = write_stream_artifacts(workdir, stdout=result.stdout_tail, stderr=result.stderr_tail)
    return await upload_artifacts(
        storage,
        organization_id=job.organization_id,
        assessment_id=job.assessment_id,
        job_id=job.id,
        artifacts=(*result.artifacts, *streams),
    )


async def _purge(workdir: Path) -> None:
    """Delete the per-job host directory.

    Unconditional and best-effort. Scanner output describes a target's exposure, and leaving
    it on a shared worker disk after upload is a data-retention problem with no upside.
    """
    with contextlib.suppress(Exception):
        await asyncio.to_thread(shutil.rmtree, workdir, True)


def _terminal_audit_action(job: ScannerJob) -> str:
    if job.status == JobStatus.COMPLETED.value:
        return audit_service.AuditAction.SCANNER_COMPLETE
    if job.status == JobStatus.TIMEOUT.value:
        return audit_service.AuditAction.SCANNER_TIMEOUT
    if job.status == JobStatus.CANCELLED.value:
        return audit_service.AuditAction.SCANNER_CANCEL
    return audit_service.AuditAction.SCANNER_FAIL


def _terminal_outcome(job: ScannerJob) -> AuditOutcome:
    if job.status == JobStatus.COMPLETED.value:
        return AuditOutcome.SUCCESS
    if job.status == JobStatus.CANCELLED.value:
        return AuditOutcome.DENIED
    return AuditOutcome.FAILURE


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = [
    "artifact_download_url",
    "cancel_jobs_for_assessment",
    "claim_slot",
    "enqueue_job",
    "execute_job",
    "get_job",
    "jobs_for_assessment",
    "list_jobs",
    "reclaim_orphans",
    "release_slot",
    "request_cancel",
    "slot_usage",
]
