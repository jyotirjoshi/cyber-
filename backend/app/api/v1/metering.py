"""Usage metering — read-only tenant consumption endpoint."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query

from app.api.deps import DbSession, PrincipalDep
from app.services.usage_metering import get_usage

router = APIRouter(prefix="/metering", tags=["platform"])


@router.get("/usage")
async def get_tenant_usage(
    principal: PrincipalDep,
    session: DbSession,
    months: Annotated[int, Query(ge=1, le=12)] = 3,
) -> list[dict[str, Any]]:
    """Return the caller's organization's usage counters for the last N months."""
    return await get_usage(session, principal, months=months)
