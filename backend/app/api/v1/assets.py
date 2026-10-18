"""Asset inventory and the operator scoping controls (FR-009, FR-010, FR-022, SEC-003).

Thin over :mod:`app.services.asset`, which owns the rules: the per-organization inventory,
the deterministic risk score behind FR-010 selection, and criticality precedence (an operator
tag always outranks a keyword guess, FR-022).  The two read endpoints are tenant-scoped -- an
asset in another organization is a 404, never a 403 (SEC-003) -- and commit nothing.

Three endpoints mutate, and all three share one shape that is worth stating once.  Each
operator action -- tagging, overriding criticality, excluding an asset -- returns the asset's
*new state* as :class:`AssetOut`, re-read through :func:`~app.services.asset.get_asset` after
the commit rather than projected from the row the mutating service handed back.  There are two
reasons the re-read is not optional:

*   :class:`AssetOut` carries the asset's ``tags`` list, but the mutation services load the
    asset without that relationship, which is ``lazy="raise_on_sql"``.  Projecting the
    un-reloaded row would raise on the tag list rather than emit a silent per-row query.
*   A freshly-inserted ``AssetTag``'s ``created_at`` is a ``server_default`` that is not
    fetched back on ``flush`` for a single-row insert with a client-side primary key, so even
    a bare tag could not be projected without an explicit reload.

:func:`~app.services.asset.get_asset` dissolves both: its ``selectinload(tags)`` is the SELECT
that populates every column and the relationship.  It requires ``ASSET_READ``, which every
role holding ``ASSET_TAG`` also holds (``_READ_ONLY`` is a subset of each writing role), so the
reload can never fail after a mutation the caller was allowed to make.

The exclusion endpoint takes no body.  ``mark_out_of_scope`` accepts an optional free-text
reason, but there is no wire schema for it and the asset schema module is frozen; the
exclusion stays attributable through its audit row (actor, asset, status change, FR-032)
rather than inventing an off-package request type for one optional string.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, File, Form, Query, Response, UploadFile, status

from app.api.deps import DbSession, PaginationDep, PrincipalDep
from app.core.errors import InvalidConfigurationError
from app.schemas.asset import (
    AssetBulkUpdateIn,
    AssetContextIn,
    AssetCreateIn,
    AssetCriticalityIn,
    AssetCsvImportOut,
    AssetFilter,
    AssetMergeIn,
    AssetMergeOut,
    AssetOut,
    AssetRelationshipIn,
    AssetRelationshipOut,
    AssetTagIn,
    CmdbImportOut,
)
from app.schemas.asset_change import AssetChangePageOut
from app.schemas.common import Page
from app.schemas.policy_gate import PolicyGateOut
from app.services import asset as asset_service
from app.services import asset_change as asset_change_service
from app.services import asset_cmdb as asset_cmdb_service
from app.services import asset_merge as asset_merge_service
from app.services import attack_path as attack_path_service
from app.services import policy_gate as policy_gate_service
from app.services.attack_path import AttackPath

router = APIRouter(prefix="/assets", tags=["assets"])


@router.post("", response_model=AssetOut, status_code=status.HTTP_201_CREATED)
async def create_asset(
    payload: AssetCreateIn, principal: PrincipalDep, session: DbSession
) -> AssetOut:
    row = await asset_merge_service.create_asset(session, principal, payload)
    await session.commit()
    row = await asset_service.get_asset(session, principal, row.id)
    return AssetOut.model_validate(row)


@router.patch("/bulk", response_model=list[AssetOut])
async def bulk_update_assets(
    payload: AssetBulkUpdateIn, principal: PrincipalDep, session: DbSession
) -> list[AssetOut]:
    rows = await asset_merge_service.bulk_update_assets(session, principal, payload)
    await session.commit()
    return [
        AssetOut.model_validate(await asset_service.get_asset(session, principal, row.id))
        for row in rows
    ]


@router.post("/merge", response_model=AssetMergeOut, status_code=status.HTTP_201_CREATED)
async def merge_assets(
    payload: AssetMergeIn, principal: PrincipalDep, session: DbSession
) -> AssetMergeOut:
    event = await asset_merge_service.merge_assets(session, principal, payload)
    await session.commit()
    return AssetMergeOut(
        event_id=event.id,
        source_asset_id=event.source_asset_id,
        target_asset_id=event.target_asset_id,
        moved_counts={key: int(value) for key, value in event.moved_counts.items()},
    )


@router.post(
    "/relationships",
    response_model=AssetRelationshipOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_asset_relationship(
    payload: AssetRelationshipIn, principal: PrincipalDep, session: DbSession
) -> AssetRelationshipOut:
    row = await asset_merge_service.create_relationship(session, principal, payload)
    await session.commit()
    await session.refresh(row)
    return AssetRelationshipOut.model_validate(row)


@router.get("/{asset_id}/relationships", response_model=list[AssetRelationshipOut])
async def list_asset_relationships(
    asset_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> list[AssetRelationshipOut]:
    rows = await asset_merge_service.list_relationships(session, principal, asset_id)
    return [AssetRelationshipOut.model_validate(row) for row in rows]


@router.post("/csv-import", response_model=AssetCsvImportOut)
async def import_asset_inventory(
    file: Annotated[UploadFile, File()],
    principal: PrincipalDep,
    session: DbSession,
    dry_run: Annotated[bool, Form()] = True,
) -> AssetCsvImportOut:
    data = await file.read(asset_merge_service.MAX_ASSET_CSV_BYTES + 1)
    try:
        rows = asset_merge_service.parse_asset_csv(data)
    except ValueError as exc:
        raise InvalidConfigurationError("invalid asset CSV", user_message=str(exc)) from exc
    result = await asset_merge_service.import_asset_rows(
        session, principal, rows, dry_run=dry_run
    )
    if not dry_run:
        await session.commit()
    return AssetCsvImportOut(dry_run=dry_run, **result)


@router.get("/export.csv", response_class=Response)
async def export_asset_inventory(principal: PrincipalDep, session: DbSession) -> Response:
    data = await asset_merge_service.export_inventory(session, principal)
    return Response(
        content=data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="cynux-assets.csv"'},
    )


@router.get("/changes", response_model=AssetChangePageOut)
async def list_asset_changes(
    principal: PrincipalDep,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AssetChangePageOut:
    return await asset_change_service.list_asset_changes(
        session,
        principal,
        limit=limit,
        offset=offset,
    )


@router.post("/cmdb-import", response_model=CmdbImportOut)
async def import_cmdb_assets(
    file: Annotated[UploadFile, File()],
    principal: PrincipalDep,
    session: DbSession,
    dry_run: Annotated[bool, Form()] = True,
) -> CmdbImportOut:
    """Attach CMDB tier and ownership to existing tenant inventory; no asset discovery."""
    data = await file.read(asset_cmdb_service.MAX_CMDB_BYTES + 1)
    try:
        rows = asset_cmdb_service.parse_cmdb_csv(data)
    except ValueError as exc:
        raise InvalidConfigurationError("invalid CMDB CSV", user_message=str(exc)) from exc
    result = await asset_cmdb_service.apply_cmdb_csv(
        session,
        principal,
        rows,
        dry_run=dry_run,
    )
    if not dry_run:
        await session.commit()
    return CmdbImportOut(dry_run=dry_run, **result)


@router.get("", response_model=Page[AssetOut])
async def list_assets(
    principal: PrincipalDep,
    session: DbSession,
    pagination: PaginationDep,
    filters: Annotated[AssetFilter, Query()],
) -> Page[AssetOut]:
    """A page of the organization's inventory, highest risk first (FR-010, ASSET_READ).

    The filter set is ``extra="forbid"``, so an unrecognized query parameter is a 422 rather
    than a silently-ignored filter that returns the wrong assets.
    """
    rows, total = await asset_service.list_assets(
        session, principal, filters=filters, pagination=pagination
    )
    return Page.build(
        [AssetOut.model_validate(row) for row in rows],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.get("/exposure-graph/paths", response_model=list[AttackPath])
async def list_exposure_graph_paths(
    principal: PrincipalDep,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[AttackPath]:
    """Evidence-backed paths; the graph topology is never generated by an LLM."""
    return await attack_path_service.current_exposure_paths(
        session,
        principal,
        max_paths=limit,
    )


@router.get("/{asset_id}", response_model=AssetOut)
async def get_asset(
    asset_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> AssetOut:
    """One asset with its tags and per-attribute evidence (FR-024, ASSET_READ).

    Tenant-scoped: an asset in another organization is a 404, never a 403 (SEC-003).
    """
    asset = await asset_service.get_asset(session, principal, asset_id)
    return AssetOut.model_validate(asset)


@router.get("/{asset_id}/policy-gate", response_model=PolicyGateOut)
async def evaluate_asset_policy_gate(
    asset_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> PolicyGateOut:
    return await policy_gate_service.evaluate_asset_gate(session, principal, asset_id)


@router.post("/{asset_id}/tags", response_model=AssetOut)
async def tag_asset(
    asset_id: uuid.UUID,
    payload: AssetTagIn,
    principal: PrincipalDep,
    session: DbSession,
) -> AssetOut:
    """Apply or replace an operator tag, returning the asset's new state (FR-022, ASSET_TAG).

    Upserts on ``(asset, key)``: re-tagging with a new value updates in place rather than
    failing on the unique constraint.  The tag is attributed to the caller and audited.
    """
    await asset_service.tag_asset(session, principal, asset_id, payload)
    await session.commit()
    asset = await asset_service.get_asset(session, principal, asset_id)
    return AssetOut.model_validate(asset)


@router.post("/{asset_id}/criticality", response_model=AssetOut)
async def set_asset_criticality(
    asset_id: uuid.UUID,
    payload: AssetCriticalityIn,
    principal: PrincipalDep,
    session: DbSession,
) -> AssetOut:
    """Override inferred criticality with a curated value (FR-009, ASSET_TAG).

    Writes ``operator_tag`` as the source, which is what makes the value survive the next
    inference pass, and stores the rationale verbatim in the audit trail -- an override
    changes which assets get scanned, so it must be attributable.
    """
    await asset_service.set_criticality(session, principal, asset_id, payload)
    await session.commit()
    asset = await asset_service.get_asset(session, principal, asset_id)
    return AssetOut.model_validate(asset)


@router.patch("/{asset_id}/context", response_model=AssetOut)
async def set_asset_context(
    asset_id: uuid.UUID,
    payload: AssetContextIn,
    principal: PrincipalDep,
    session: DbSession,
) -> AssetOut:
    """Set tenant-owned business context, with an audit trail (ASSET_TAG)."""
    await asset_service.set_asset_context(session, principal, asset_id, payload)
    await session.commit()
    asset = await asset_service.get_asset(session, principal, asset_id)
    return AssetOut.model_validate(asset)


@router.post("/{asset_id}/out-of-scope", response_model=AssetOut)
async def mark_asset_out_of_scope(
    asset_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> AssetOut:
    """Exclude an asset from future scope selection (ASSET_TAG).

    A status change, not a delete: the asset was observed, and an inventory that forgets what
    it was told to ignore rediscovers and re-proposes it every assessment.  Excluding one that
    is already out of scope is a 409.
    """
    await asset_service.mark_out_of_scope(session, principal, asset_id)
    await session.commit()
    asset = await asset_service.get_asset(session, principal, asset_id)
    return AssetOut.model_validate(asset)


__all__ = ["router"]
