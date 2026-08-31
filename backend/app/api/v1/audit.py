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

from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import DbSession, PaginationDep, PrincipalDep
from app.schemas.audit import AuditEventOut, AuditFilter
from app.schemas.common import Page
from app.services import audit as audit_service

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=Page[AuditEventOut])
async def list_audit_events(
    principal: PrincipalDep,
    session: DbSession,
    pagination: PaginationDep,
    filters: Annotated[AuditFilter, Query()],
) -> Page[AuditEventOut]:
    """A page of audit events, newest first (FR-032).

    Filter by actor, action prefix (``assessment.`` selects the whole group), resource,
    outcome, a time window, or a free-text term matched against actor email, action and reason.
    """
    rows, total = await audit_service.list_audit_events(
        session, principal, filters=filters, pagination=pagination
    )
    items = [AuditEventOut.model_validate(row) for row in rows]
    return Page.build(items, total=total, limit=pagination.limit, offset=pagination.offset)


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
