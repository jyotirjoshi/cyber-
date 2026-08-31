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

from fastapi import APIRouter, Query

from app.api.deps import DbSession, PaginationDep, PrincipalDep
from app.schemas.asset import AssetCriticalityIn, AssetFilter, AssetOut, AssetTagIn
from app.schemas.common import Page
from app.services import asset as asset_service

router = APIRouter(prefix="/assets", tags=["assets"])


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
