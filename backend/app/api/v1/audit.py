"""Audit trail read endpoints (FR-032).

FR-032 makes the audit trail a first-class, queryable record -- authentication, approvals,
scanner lifecycle, integration changes, finding status changes, ticket creation, report
generation, permission denials and every agent tool invocation. These endpoints expose it for
review, gated on ``audit:read`` (enforced in :mod:`app.services.audit`).

Both endpoints are read-only, so neither commits. The list is filtered and paginated; the
resource history reads as a narrative (oldest first) for one resource -- "created, approved,
scanned, reported". Rows with a NULL ``organization_id`` (global security events such as a
failed login) are never returned to a tenant: attributing them to whichever organization
happens to be looking would be wrong in both directions (handled in the service).
"""

from __future__ import annotations

import csv
import io
import json
from typing import Annotated

from fastapi import APIRouter, Query, Response

from app.api.deps import DbSession, PrincipalDep
from app.schemas.audit import AuditEventOut, AuditFilter, AuditListQuery
from app.schemas.common import Page, PaginationParams
from app.services import audit as audit_service

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=Page[AuditEventOut])
async def list_audit_events(
    principal: PrincipalDep,
    session: DbSession,
    query: Annotated[AuditListQuery, Query()],
) -> Page[AuditEventOut]:
    """A page of audit events, newest first (FR-032).

    Filter by actor, action prefix (``assessment.`` selects the whole group), resource,
    outcome, a time window, or a free-text term matched against actor email, action and reason.
    """
    pagination = PaginationParams(limit=query.limit, offset=query.offset)
    filters = AuditFilter.model_validate(
        query.model_dump(include=set(AuditFilter.model_fields))
    )
    rows, total = await audit_service.list_audit_events(
        session, principal, filters=filters, pagination=pagination
    )
    items = [AuditEventOut.model_validate(row) for row in rows]
    return Page.build(items, total=total, limit=pagination.limit, offset=pagination.offset)


@router.get("/export")
async def export_audit_events(
    principal: PrincipalDep,
    session: DbSession,
    filters: Annotated[AuditFilter, Query()],
) -> Response:
    """Download up to 10,000 filtered audit events as a CSV evidence file."""
    rows = await audit_service.export_audit_events(session, principal, filters=filters)
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        [
            "timestamp", "actor_email", "actor_type", "action", "resource_type",
            "resource_id", "outcome", "reason", "source_ip", "user_agent",
            "request_id", "trace_id", "detail",
        ]
    )
    for row in rows:
        writer.writerow(
            [
                row.created_at.isoformat(), row.actor_email or "", row.actor_type, row.action,
                row.resource_type or "", row.resource_id or "", row.outcome, row.reason or "",
                row.source_ip or "", row.user_agent or "", row.request_id or "",
                row.trace_id or "", json.dumps(row.detail or {}, sort_keys=True, default=str),
            ]
        )
    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="cynux-audit-events.csv"'},
    )


@router.get(
    "/resource/{resource_type}/{resource_id}",
    response_model=list[AuditEventOut],
)
async def resource_history(
    resource_type: str,
    resource_id: str,
    principal: PrincipalDep,
    session: DbSession,
) -> list[AuditEventOut]:
    """The full history of one resource, oldest first (FR-032).

    Read as a narrative rather than a feed -- the ordering is deliberate. Tenant-scoped in the
    service, so a resource id from another organization yields an empty list, not a disclosure.
    """
    rows = await audit_service.resource_history(
        session, principal, resource_type=resource_type, resource_id=resource_id
    )
    return [AuditEventOut.model_validate(row) for row in rows]


__all__ = ["router"]
