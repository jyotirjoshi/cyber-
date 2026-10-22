"""Assessment lifecycle endpoints (FR-005, FR-006, FR-011, FR-033, FR-038).

WHY this router carries wiring the service does not: :func:`app.services.assessment.
create_assessment` validates targets, records the authorization attestation, and writes the
assessment row -- but it deliberately stops there.  It does not commit (the route owns the
unit of work), and it does not enqueue anything (a service has no Redis).  Starting the agent
is a *produce a run request* step, and that step needs three things a service call cannot
give it: the conversation row the event stream is keyed on, the run row the worker loads, and
the Redis client to publish onto.  So this module is where an assessment becomes a running
agent.

The producer sequence is exact and load-bearing:

1.  ``create_assessment`` writes the assessment (flushed, so its id exists).
2.  An :class:`AgentSession` and an :class:`AgentRun` are created here -- nothing else in the
    system creates them.  The run is what the worker's :class:`~app.agent.runner.AgentRunner`
    loads by id; it refuses a run whose ``assessment_id`` or ``session_id`` is null
    (``_run_identity``), so both are set now.  The ids are *minted* rather than
    server-defaulted so ``thread_id`` can be ``str(run_id)`` -- one value, unique for the life
    of the run, which is what makes a resume after the approval interrupt a re-entry.
3.  The unit of work is committed -- the run must be durable before the worker can see it.
4.  Only then is ``RunRequest.START`` published, carrying the initiating principal so the
    seed state inherits the operator's authority (the agent principal is a downgrade of it).

Publishing after the commit is not incidental: under at-least-once delivery a worker can pick
up the message the instant it lands, and a run that is not yet committed would be a missing
row.  Resume is the approvals router's job, not this one's.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query, status
from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import DbSession, PrincipalDep, RedisDep, SettingsDep
from app.api.v1.projections import assessment_detail_out, assessment_out
from app.core.errors import InvalidConfigurationError, ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.agent import AgentRun, RunDispatch
from app.db.models.assessment import Assessment, RecurringScan, ScanProfile
from app.db.models.notification import Notification
from app.db.models.scanner import ScannerJob
from app.db.repository import tenant_select
from app.schemas.assessment import (
    AssessmentCreateIn,
    AssessmentDetailOut,
    AssessmentFilter,
    AssessmentListQuery,
    AssessmentOut,
    CancelIn,
    EngagementChecklistUpdateIn,
    RecurringScanCreateIn,
    RecurringScanOut,
    ScanProfileCreateIn,
    ScanProfileOut,
    WorkerMetricsOut,
)
from app.schemas.common import Page, PaginationParams, SortParams
from app.services import assessment as assessment_service
from app.services import audit as audit_service
from app.services import recurring_scan as recurring_scan_service
from app.services.context import Principal
from app.worker.dispatch import deliver_run_dispatch, stage_assessment_run

router = APIRouter(prefix="/assessments", tags=["assessments"])


@router.get("/worker/metrics", response_model=WorkerMetricsOut)
async def worker_metrics(principal: PrincipalDep, session: DbSession) -> WorkerMetricsOut:
    principal.require(Permission.ASSESSMENT_READ)
    org_id = principal.organization_id
    run_rows = (
        await session.execute(
            tenant_select(AgentRun, org_id)
            .with_only_columns(AgentRun.status, func.count())
            .where(AgentRun.graph == "assessment")
            .group_by(AgentRun.status)
        )
    ).all()
    dispatch_rows = (
        await session.execute(
            tenant_select(RunDispatch, org_id)
            .with_only_columns(RunDispatch.status, func.count())
            .group_by(RunDispatch.status)
        )
    ).all()
    scanner_rows = (
        await session.execute(
            tenant_select(ScannerJob, org_id)
            .with_only_columns(ScannerJob.status, func.count())
            .group_by(ScannerJob.status)
        )
    ).all()
    notification_rows = (
        await session.execute(
            tenant_select(Notification, org_id)
            .with_only_columns(Notification.status, func.count())
            .where(Notification.channel.in_(("slack", "email", "pagerduty", "webhook")))
            .group_by(Notification.status)
        )
    ).all()
    notification_retries_due = await session.scalar(
        tenant_select(Notification, org_id)
        .with_only_columns(func.count())
        .where(
            Notification.status == "pending",
            Notification.next_retry_at.is_not(None),
            Notification.next_retry_at <= func.now(),
        )
    )
    return WorkerMetricsOut(
        runs={row[0]: row[1] for row in run_rows},
        pending_dispatches=next((row[1] for row in dispatch_rows if row[0] == "pending"), 0),
        scanner_jobs={row[0]: row[1] for row in scanner_rows},
        notification_deliveries={row[0]: row[1] for row in notification_rows},
        notification_retries_due=int(notification_retries_due or 0),
    )


@router.get("/profiles", response_model=list[ScanProfileOut])
async def list_scan_profiles(principal: PrincipalDep, session: DbSession) -> list[ScanProfile]:
    principal.require(Permission.ASSESSMENT_READ)
    return list(
        (
            await session.scalars(
                tenant_select(ScanProfile, principal.organization_id)
                .order_by(ScanProfile.name)
                .limit(200)
            )
        ).all()
    )


@router.post("/profiles", response_model=ScanProfileOut, status_code=status.HTTP_201_CREATED)
async def create_scan_profile(
    payload: ScanProfileCreateIn, principal: PrincipalDep, session: DbSession
) -> ScanProfile:
    profile = await recurring_scan_service.create_scan_profile(session, principal, payload)
    await session.commit()
    return profile


@router.post("/profiles/{profile_id}/deactivate", response_model=ScanProfileOut)
async def deactivate_scan_profile(
    profile_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> ScanProfile:
    profile, disabled_schedules = await recurring_scan_service.deactivate_scan_profile(
        session,
        principal,
        profile_id,
    )
    await audit_service.record(
        session,
        action=audit_service.AuditAction.SCAN_PROFILE_DEACTIVATE,
        principal=principal,
        resource_type="scan_profile",
        resource_id=profile.id,
        detail={"disabled_recurring_schedules": disabled_schedules},
    )
    await session.commit()
    return profile


@router.get("/schedules", response_model=list[RecurringScanOut])
async def list_recurring_scans(principal: PrincipalDep, session: DbSession) -> list[RecurringScan]:
    principal.require(Permission.ASSESSMENT_READ)
    return list(
        (
            await session.scalars(
                tenant_select(RecurringScan, principal.organization_id)
                .order_by(RecurringScan.created_at.desc())
                .limit(200)
            )
        ).all()
    )


@router.post("/schedules", response_model=RecurringScanOut, status_code=status.HTTP_201_CREATED)
async def create_recurring_scan(
    payload: RecurringScanCreateIn,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
) -> RecurringScan:
    schedule = await recurring_scan_service.create_recurring_scan(
        session, principal, payload, settings
    )
    await session.commit()
    return schedule


@router.post("/schedules/{schedule_id}/pause", response_model=RecurringScanOut)
async def pause_recurring_scan(
    schedule_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> RecurringScan:
    principal.require(Permission.ASSESSMENT_CREATE)
    schedule = (
        await session.execute(
            tenant_select(RecurringScan, principal.organization_id)
            .where(RecurringScan.id == schedule_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if schedule is None:
        raise ResourceNotFoundError("Recurring scan not found")
    schedule.enabled = False
    await session.commit()
    return schedule


@router.post("/schedules/{schedule_id}/resume", response_model=RecurringScanOut)
async def resume_recurring_scan(
    schedule_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> RecurringScan:
    """Resume a paused schedule only when its original authorization is still valid."""
    principal.require(Permission.ASSESSMENT_CREATE)
    schedule = (
        await session.execute(
            tenant_select(RecurringScan, principal.organization_id)
            .where(RecurringScan.id == schedule_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if schedule is None:
        raise ResourceNotFoundError("Recurring scan not found")
    from app.db.base import utcnow

    now = utcnow()
    if schedule.authorization_expires_at <= now:
        raise InvalidConfigurationError(
            "Recurring scan authorization has expired",
            user_message="Renew the authorization before resuming this schedule.",
        )
    try:
        next_run_at = recurring_scan_service.next_scan_time(
            schedule.cron_expression, schedule.timezone, now
        )
    except ValueError as exc:
        raise InvalidConfigurationError(str(exc), user_message="The stored schedule is invalid.") from exc
    if next_run_at >= schedule.authorization_expires_at:
        raise InvalidConfigurationError(
            "Recurring scan authorization expires before the next run",
            user_message="Renew the authorization before resuming this schedule.",
        )
    schedule.enabled = True
    schedule.next_run_at = next_run_at
    schedule.last_error_code = None
    await session.commit()
    return schedule


def _seed_agent_run(
    session: AsyncSession, principal: Principal, assessment: Assessment
) -> tuple[uuid.UUID, uuid.UUID]:
    """Create the conversation and run rows the worker will drive, and return the run id.

    Both ids are minted here so ``thread_id`` can be ``str(run_id)`` -- the LangGraph
    checkpoint key, unique for the life of the run -- without a second flush to read a
    server-generated default back.  The assessment is linked to its session so a later
    ``GET`` can surface ``agent_session_id`` and the socket knows which channel to stream.
    ``organization_id`` is stamped on the constructor, matching the service's own idiom, so
    both rows are tenant-owned before they are staged.

    Staged, not committed: the caller commits the whole unit of work, then publishes the
    ``START`` request -- the run must be durable before the worker can load it.
    """
    return stage_assessment_run(session, principal, assessment)


@router.get("", response_model=Page[AssessmentOut])
async def list_assessments(
    principal: PrincipalDep,
    session: DbSession,
    query: Annotated[AssessmentListQuery, Query()],
) -> Page[AssessmentOut]:
    """A page of the organization's assessments, newest first (FR-037)."""
    pagination = PaginationParams(limit=query.limit, offset=query.offset)
    filters = AssessmentFilter.model_validate(
        query.model_dump(include=set(AssessmentFilter.model_fields))
    )
    rows, total = await assessment_service.list_assessments(
        session,
        principal,
        filters=filters,
        pagination=pagination,
        sorting=SortParams(sort_by=query.sort_by, sort_dir=query.sort_dir),
    )
    return Page.build(
        [assessment_out(row) for row in rows],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.post("", response_model=AssessmentDetailOut, status_code=status.HTTP_201_CREATED)
async def create_assessment(
    payload: AssessmentCreateIn,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> AssessmentDetailOut:
    """Create an assessment and start its agent run (FR-005, FR-006, FR-033).

    The authorization attestation is mandatory and checked in the service before any target
    is parsed; an unconfirmed one is a 403 that writes nothing.  On success the assessment,
    its conversation, and its queued run are committed as one unit, and only then is the
    ``START`` request published -- so the worker never sees a run that is not yet durable.
    """
    assessment = await assessment_service.create_assessment(session, principal, payload, settings)
    _, dispatch_id = _seed_agent_run(session, principal, assessment)
    await session.commit()

    await deliver_run_dispatch(
        session,
        organization_id=principal.organization_id,
        dispatch_id=dispatch_id,
        redis=redis,
        settings=settings,
    )
    await session.commit()
    detail = await assessment_service.get_assessment(session, principal, assessment.id, detail=True)
    return await assessment_detail_out(session, detail)


@router.get("/{assessment_id}", response_model=AssessmentDetailOut)
async def get_assessment(
    assessment_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> AssessmentDetailOut:
    """The full assessment: plan, FR-038 stage checklist, degradations and any pending gate."""
    assessment = await assessment_service.get_assessment(
        session, principal, assessment_id, detail=True
    )
    return await assessment_detail_out(session, assessment)


@router.patch("/{assessment_id}/engagement-checklist/{key}", response_model=AssessmentDetailOut)
async def update_engagement_checklist(
    assessment_id: uuid.UUID,
    key: str,
    payload: EngagementChecklistUpdateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> AssessmentDetailOut:
    assessment = await assessment_service.update_engagement_checklist(
        session,
        principal,
        assessment_id,
        key,
        completed=payload.completed,
        evidence_reference=payload.evidence_reference,
    )
    await session.commit()
    detail = await assessment_service.get_assessment(session, principal, assessment.id, detail=True)
    return await assessment_detail_out(session, detail)


@router.post("/{assessment_id}/cancel", response_model=AssessmentDetailOut)
async def cancel_assessment(
    assessment_id: uuid.UUID,
    payload: CancelIn,
    principal: PrincipalDep,
    session: DbSession,
) -> AssessmentDetailOut:
    """Request cancellation (FR-019): move the assessment to ``cancelling``.

    Cooperative by design -- the run observes the status at its next node boundary and
    settles, rather than being killed mid-scanner.  No run request is published: cancellation
    is a state the agent reads, not a message it is sent.
    """
    await assessment_service.cancel_assessment(session, principal, assessment_id, payload)
    await session.commit()
    detail = await assessment_service.get_assessment(session, principal, assessment_id, detail=True)
    return await assessment_detail_out(session, detail)


__all__ = ["router"]
