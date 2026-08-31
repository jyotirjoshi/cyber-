"""Scanner job endpoints (FR-013, FR-014, FR-015, FR-019).

WHY the projection is not ``model_validate``: a job's wire shape names two fields for the PRD
contract rather than the column (``finished_at`` -> ``completed_at``, ``error_message`` -> the
user-safe ``failure_detail``), and every artifact carries a ``download_url`` presigned per
request -- a link minted from object storage, never stored. That mapping lives in
:mod:`app.api.v1.projections`; this module is the transport around it.

Cancellation (FR-019) is cooperative: the endpoint records the request and returns the job as it
stands. The runner observes the flag and kills the container; writing the terminal status is the
worker's job, so a cancel that races a completion is recorded without rewriting history.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query
from fastapi.responses import RedirectResponse

from app.api.deps import DbSession, PaginationDep, PrincipalDep, StorageDep
from app.api.v1.projections import job_out
from app.schemas.common import Page
from app.schemas.job import JobFilter, ScannerJobOut
from app.services import job as job_service

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("", response_model=Page[ScannerJobOut])
async def list_jobs(
    principal: PrincipalDep,
    session: DbSession,
    storage: StorageDep,
    pagination: PaginationDep,
    filters: Annotated[JobFilter, Query()],
) -> Page[ScannerJobOut]:
    """A page of scanner jobs, newest first (FR-013). Filter by assessment, scanner or status."""
    rows, total = await job_service.list_jobs(
        session, principal, filters=filters, pagination=pagination
    )
    items = [
        await job_out(row, storage=storage, organization_id=principal.organization_id)
        for row in rows
    ]
    return Page.build(items, total=total, limit=pagination.limit, offset=pagination.offset)


@router.get("/{job_id}", response_model=ScannerJobOut)
async def get_job(
    job_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
    storage: StorageDep,
) -> ScannerJobOut:
    """One scanner job: its canonical targets, the sandbox profile it ran with, its artifacts."""
    job = await job_service.get_job(session, principal, job_id)
    return await job_out(job, storage=storage, organization_id=principal.organization_id)


@router.post("/{job_id}/cancel", response_model=ScannerJobOut)
async def cancel_job(
    job_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
    storage: StorageDep,
) -> ScannerJobOut:
    """Request cancellation of a running job (FR-019).

    Sets the cooperative cancel flag and commits; the runner stops the container at its next
    check. A no-op on an already-terminal job -- the request is recorded, the status is not
    rewritten. The job is re-read after the commit so the returned row carries its artifacts.
    """
    await job_service.request_cancel(session, principal, job_id)
    await session.commit()
    job = await job_service.get_job(session, principal, job_id)
    return await job_out(job, storage=storage, organization_id=principal.organization_id)


@router.get("/{job_id}/artifacts/{artifact_id}/download")
async def download_artifact(
    job_id: uuid.UUID,
    artifact_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
    storage: StorageDep,
) -> RedirectResponse:
    """Redirect to a freshly presigned link for one artifact (FR-015).

    The bytes never pass through the API: a scanner output can be hundreds of megabytes, so the
    caller is sent straight to object storage with a short-lived signature. Read-only -- there
    is no unit of work to commit. A cross-tenant job, or an artifact that is not on this job, is
    a 404.
    """
    url = await job_service.artifact_download_url(
        session, principal, job_id, artifact_id, storage=storage
    )
    return RedirectResponse(url, status_code=307)


__all__ = ["router"]
