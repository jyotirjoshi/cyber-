"""Unified exposure read feed, retaining original source identity."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Query

from app.api.deps import DbSession, PaginationDep, PrincipalDep
from app.schemas.common import Page
from app.schemas.exposure_feed import ExposureOut
from app.services.exposure_feed import list_exposures

router = APIRouter(prefix="/exposures", tags=["findings"])


@router.get("", response_model=Page[ExposureOut])
async def exposure_feed(
    principal: PrincipalDep,
    session: DbSession,
    pagination: PaginationDep,
    source: Annotated[
        str | None,
        Query(
            pattern=r"^[a-z][a-z0-9_-]{1,39}$",
            max_length=40,
            description="Normalized intake provider identifier.",
        ),
    ] = None,
    severity: Annotated[
        Literal["critical", "high", "medium", "low", "info"] | None, Query()
    ] = None,
) -> Page[ExposureOut]:
    rows, total = await list_exposures(
        session, principal, pagination=pagination, source=source, severity=severity
    )
    return Page.build(
        [ExposureOut.model_validate(row) for row in rows],
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
    )
