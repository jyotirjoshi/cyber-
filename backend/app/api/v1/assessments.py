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
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import DbSession, PaginationDep, PrincipalDep, RedisDep, SettingsDep
from app.api.v1.projections import assessment_detail_out, assessment_out
from app.db.enums import AgentRunStatus
from app.db.models.agent import AgentRun, AgentSession
from app.db.models.assessment import Assessment
from app.schemas.assessment import (
    AssessmentCreateIn,
    AssessmentDetailOut,
    AssessmentFilter,
    AssessmentOut,
    CancelIn,
)
from app.schemas.common import Page
from app.services import assessment as assessment_service
from app.services.context import Principal
from app.worker import RunAction, RunRequest, publish_run_request

router = APIRouter(prefix="/assessments", tags=["assessments"])


def _seed_agent_run(
    session: AsyncSession, principal: Principal, assessment: Assessment
) -> uuid.UUID:
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
    session_id = uuid.uuid4()
    run_id = uuid.uuid4()
    session.add(
        AgentSession(
            id=session_id,
            organization_id=principal.organization_id,
            user_id=principal.user_id,
            title=assessment.title,
        )
    )
    assessment.agent_session_id = session_id
    session.add(
        AgentRun(
            id=run_id,
            organization_id=principal.organization_id,
            session_id=session_id,
            assessment_id=assessment.id,
            triggered_by_id=principal.user_id,
            thread_id=str(run_id),
            graph="assessment",
            status=AgentRunStatus.QUEUED.value,
        )
    )
    return run_id


@router.get("", response_model=Page[AssessmentOut])
async def list_assessments(
    principal: PrincipalDep,
    session: DbSession,
    pagination: PaginationDep,
    filters: Annotated[AssessmentFilter, Query()],
) -> Page[AssessmentOut]:
    """A page of the organization's assessments, newest first (FR-037)."""
    rows, total = await assessment_service.list_assessments(
        session, principal, filters=filters, pagination=pagination
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
    run_id = _seed_agent_run(session, principal, assessment)
    await session.commit()

    detail = await assessment_service.get_assessment(session, principal, assessment.id, detail=True)
    await publish_run_request(
        redis,
        settings,
        RunRequest.new(run_id, RunAction.START, principal=principal.to_dict()),
    )
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
