"""Authenticated access to the locally synchronized CVE intelligence catalog."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query, Response, status
from sqlalchemy import func, select

from app.api.deps import DbSession, PaginationDep, PrincipalDep
from app.core.errors import ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.threat_intelligence import ThreatWatchlist, ThreatWatchlistMatch, VulnerabilityIntelligence
from app.db.repository import tenant_select
from app.schemas.common import Page
from app.schemas.threat_intelligence import (
    ThreatWatchlistCreateIn,
    ThreatWatchlistMatchOut,
    ThreatWatchlistOut,
    VulnerabilityIntelligenceOut,
)
from app.services.threat_feed import create_watchlist, delete_watchlist

router = APIRouter(prefix="/threat-intelligence", tags=["threat-intelligence"])


@router.get("", response_model=Page[VulnerabilityIntelligenceOut])
async def list_vulnerability_intelligence(
    principal: PrincipalDep,
    session: DbSession,
    pagination: PaginationDep,
    q: str | None = Query(default=None, min_length=3, max_length=32),
) -> Page[VulnerabilityIntelligenceOut]:
    """Search durable CVE snapshots populated by the intelligence worker."""
    principal.require(Permission.FINDING_READ)
    predicate = (
        VulnerabilityIntelligence.cve_id.ilike(f"%{q.strip()}%") if q is not None else None
    )
    query = select(VulnerabilityIntelligence)
    count_query = select(func.count()).select_from(VulnerabilityIntelligence)
    if predicate is not None:
        query = query.where(predicate)
        count_query = count_query.where(predicate)
    total = int((await session.scalar(count_query)) or 0)
    rows = (
        await session.scalars(
            query.order_by(VulnerabilityIntelligence.cve_id.desc())
            .limit(pagination.limit)
            .offset(pagination.offset)
        )
    ).all()
    return Page.build(
        [VulnerabilityIntelligenceOut.model_validate(row) for row in rows],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.get("/watchlists", response_model=list[ThreatWatchlistOut])
async def list_threat_watchlists(
    principal: PrincipalDep, session: DbSession
) -> list[ThreatWatchlistOut]:
    principal.require(Permission.FINDING_READ)
    rows = await session.scalars(
        tenant_select(ThreatWatchlist, principal.organization_id).order_by(
            ThreatWatchlist.created_at.desc()
        )
    )
    return [ThreatWatchlistOut.model_validate(row) for row in rows.all()]


@router.post("/watchlists", response_model=ThreatWatchlistOut, status_code=status.HTTP_201_CREATED)
async def create_threat_watchlist(
    payload: ThreatWatchlistCreateIn, principal: PrincipalDep, session: DbSession
) -> ThreatWatchlistOut:
    row = await create_watchlist(session, principal, payload)
    await session.commit()
    return ThreatWatchlistOut.model_validate(row)


@router.delete("/watchlists/{watchlist_id}", status_code=204, response_class=Response)
async def remove_threat_watchlist(
    watchlist_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> Response:
    await delete_watchlist(session, principal, watchlist_id)
    await session.commit()
    return Response(status_code=204)


@router.get("/watchlists/{watchlist_id}/matches", response_model=list[ThreatWatchlistMatchOut])
async def list_watchlist_matches(
    watchlist_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> list[ThreatWatchlistMatchOut]:
    principal.require(Permission.FINDING_READ)
    watch = await session.scalar(
        tenant_select(ThreatWatchlist, principal.organization_id).where(
            ThreatWatchlist.id == watchlist_id
        )
    )
    if watch is None:
        raise ResourceNotFoundError("Threat watchlist not found")
    rows = await session.scalars(
        tenant_select(ThreatWatchlistMatch, principal.organization_id)
        .where(ThreatWatchlistMatch.watchlist_id == watchlist_id)
        .order_by(ThreatWatchlistMatch.matched_at.desc())
        .limit(500)
    )
    return [ThreatWatchlistMatchOut.model_validate(row) for row in rows.all()]


@router.get("/{cve_id}", response_model=VulnerabilityIntelligenceOut)
async def get_vulnerability_intelligence(
    cve_id: str,
    principal: PrincipalDep,
    session: DbSession,
) -> VulnerabilityIntelligenceOut:
    """Read one CVE from the local catalog without a provider round trip."""
    principal.require(Permission.FINDING_READ)
    row = await session.get(VulnerabilityIntelligence, cve_id.strip().upper())
    if row is None:
        raise ResourceNotFoundError("Vulnerability intelligence not found")
    return VulnerabilityIntelligenceOut.model_validate(row)


__all__ = ["router"]
