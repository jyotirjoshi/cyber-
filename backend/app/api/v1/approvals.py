"""The FR-011 human-in-the-loop gate, over REST (FR-011, FR-033).

WHY this router is a producer like :mod:`app.api.v1.assessments`: resolving an approval is
the second half of the one interrupt in the pipeline.  The agent paused the run *before*
``execute_scanners`` and is waiting; :func:`app.services.approval.resolve_approval` records
the operator's decision as durable authority -- but a service has no Redis, so it cannot wake
the paused worker.  This module does: it commits the decision and then publishes a
``RESUME`` request so the run re-enters the graph.

The decision is resumed *whatever it was*, and that is deliberate.  The scan node
(:mod:`app.agent.nodes.scan`) re-reads authority from the database rather than trusting the
queue message, so:

*   A **grant** (approved / approved_all / customized) wakes the run, which re-reads the
    granted approval and scans exactly its ``approved_payload`` scope.
*   A **rejection** wakes the run too.  ``granted_approval`` then returns nothing, so the scan
    node takes its designed no-scan branch -- no active traffic is sent, and the assessment
    still completes with a passive-only report explaining the gap.  Rejection is *not*
    cancellation (that is a separate endpoint and a separate terminal state); it means "do not
    actively scan," not "abandon the assessment."

Not resuming would strand the run ``interrupted`` and the assessment ``waiting_for_approval``
forever.  So a resolution that :func:`resolve_approval` accepts -- it refuses an
already-resolved or expired one with a 409 -- always publishes a ``RESUME``.

The ordering mirrors the start producer: the decision is committed before the ``RESUME`` is
published, because under at-least-once delivery a worker can pick the message up the instant
it lands and the scan node reads the decision back from the ``approvals`` table.  ``RESUME``
carries no principal -- the initiating operator's authority is recovered from the LangGraph
checkpoint, not re-sent (:class:`~app.worker.protocol.RunRequest`).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter

from app.api.deps import DbSession, PrincipalDep, RedisDep, SettingsDep
from app.api.v1.projections import load_approval_out
from app.db.models.assessment import Approval
from app.schemas.assessment import ApprovalOut, ApproveIn
from app.services import approval as approval_service
from app.worker import RunAction, RunRequest, publish_run_request

router = APIRouter(prefix="/approvals", tags=["approvals"])


def _resolver_email(approval: Approval) -> str | None:
    """The resolving operator's email for the projection, or ``None`` while still pending.

    Read off the ``resolved_by`` relationship :func:`~app.services.approval.get_approval`
    eager-loads, so this never lazy-loads under ``raise_on_sql``.  The wire field is the
    email alone, never the ``User`` row (SEC-002).
    """
    return approval.resolved_by.email if approval.resolved_by is not None else None


@router.get("/{approval_id}", response_model=ApprovalOut)
async def get_approval(
    approval_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> ApprovalOut:
    """One approval with its proposed-scope card (FR-011).

    Tenant-scoped: an approval in another organization is a 404, never a 403 (SEC-003).
    """
    approval = await approval_service.get_approval(session, principal, approval_id)
    return await load_approval_out(session, approval, resolved_by=_resolver_email(approval))


@router.post("/{approval_id}/resolve", response_model=ApprovalOut)
async def resolve_approval(
    approval_id: uuid.UUID,
    payload: ApproveIn,
    principal: PrincipalDep,
    session: DbSession,
    settings: SettingsDep,
    redis: RedisDep,
) -> ApprovalOut:
    """Record the operator's decision on a pending approval and resume the run (FR-011).

    The write is a conditional update narrowed on ``decision = 'pending'``, so a second
    operator resolving the same gate gets a 409 rather than silently overwriting the first.
    A ``customized`` decision may only *narrow* the proposed scope; an approval that selects
    nothing in scope is refused.  Once the decision is committed, a ``RESUME`` is published so
    the paused worker re-enters the graph -- which scans on a grant and winds down to a
    passive-only report on a rejection.
    """
    resolved = await approval_service.resolve_approval(session, principal, approval_id, payload)
    run_id = resolved.agent_run_id
    await session.commit()

    if run_id is not None:
        await publish_run_request(redis, settings, RunRequest.new(run_id, RunAction.RESUME))

    approval = await approval_service.get_approval(session, principal, approval_id)
    return await load_approval_out(session, approval, resolved_by=_resolver_email(approval))


__all__ = ["router"]
