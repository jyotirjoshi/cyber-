"""Tenant-scoped saved finding and asset query presets."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, status

from app.api.deps import DbSession, PrincipalDep
from app.core.errors import ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.platform import SavedView
from app.db.repository import tenant_select
from app.schemas.saved_view import SavedViewCreateIn, SavedViewOut, SavedViewUpdateIn
from app.services.audit import AuditAction, record
from app.services.query_language import validate_saved_query

router = APIRouter(prefix="/saved-views", tags=["saved-views"])


@router.get("", response_model=list[SavedViewOut])
async def list_saved_views(principal: PrincipalDep, session: DbSession) -> list[SavedView]:
    principal.require(Permission.FINDING_READ)
    return list(
        (
            await session.scalars(
                tenant_select(SavedView, principal.organization_id)
                .order_by(SavedView.resource, SavedView.name)
                .limit(200)
            )
        ).all()
    )


@router.post("", response_model=SavedViewOut, status_code=status.HTTP_201_CREATED)
async def create_saved_view(
    payload: SavedViewCreateIn, principal: PrincipalDep, session: DbSession
) -> SavedView:
    principal.require(Permission.FINDING_READ)
    view = SavedView(
        organization_id=principal.organization_id,
        created_by_id=principal.user_id,
        name=payload.name,
        resource=payload.resource,
        filters=payload.filters,
    )
    session.add(view)
    await session.flush()
    await record(
        session,
        action=AuditAction.SAVED_VIEW_CREATE,
        principal=principal,
        resource_type="saved_view",
        resource_id=view.id,
        detail={"resource": view.resource, "name": view.name},
    )
    await session.commit()
    return view


@router.put("/{view_id}", response_model=SavedViewOut, status_code=status.HTTP_200_OK)
async def update_saved_view(
    view_id: uuid.UUID,
    payload: SavedViewUpdateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> SavedView:
    """Update a preset without allowing a cross-resource filter change."""
    principal.require(Permission.FINDING_READ)
    view = (
        await session.execute(
            tenant_select(SavedView, principal.organization_id)
            .where(SavedView.id == view_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if view is None:
        raise ResourceNotFoundError("Saved view not found")

    if payload.filters is not None:
        allowed = {
            "findings": {"status", "severity", "q", "query", "source"},
            "assets": {
                "status",
                "environment",
                "criticality",
                "q",
                "internet_exposed",
                "query",
            },
        }
        if unsupported := set(payload.filters).difference(allowed[view.resource]):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"unsupported {view.resource} saved-view filters: {', '.join(sorted(unsupported))}",
            )
        if "query" in payload.filters:
            validate_saved_query(view.resource, payload.filters["query"])
        if view.resource == "findings" and payload.filters.get("source", "assessment") not in {
            "assessment",
            "canonical",
        }:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="finding saved view source must be assessment or canonical",
            )
        view.filters = payload.filters
    if payload.name is not None:
        view.name = payload.name

    await record(
        session,
        action=AuditAction.SAVED_VIEW_UPDATE,
        principal=principal,
        resource_type="saved_view",
        resource_id=view.id,
        detail={"resource": view.resource, "changed": sorted(payload.model_fields_set)},
    )
    await session.commit()
    return view


@router.delete("/{view_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_saved_view(
    view_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> None:
    """Delete one tenant-owned saved preset."""
    principal.require(Permission.FINDING_READ)
    view = (
        await session.execute(
            tenant_select(SavedView, principal.organization_id)
            .where(SavedView.id == view_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if view is None:
        raise ResourceNotFoundError("Saved view not found")
    await record(
        session,
        action=AuditAction.SAVED_VIEW_DELETE,
        principal=principal,
        resource_type="saved_view",
        resource_id=view.id,
        detail={"resource": view.resource, "name": view.name},
    )
    await session.delete(view)
    await session.commit()


__all__ = ["router"]
