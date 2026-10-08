"""Resumable, bounded projection of historical source records into canonical findings."""

from __future__ import annotations

import uuid
from typing import Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.external_alert import ExternalSecurityAlert
from app.db.models.finding import Finding
from app.services.canonical_ingest import ingest_external_alerts, ingest_native_findings

Source = Literal["external", "native"]


async def backfill_organization_page(
    session: AsyncSession,
    organization_id: uuid.UUID,
    *,
    source: Source,
    after_id: uuid.UUID | None,
    limit: int = 100,
) -> tuple[uuid.UUID | None, int, int]:
    """Project one keyset page; caller commits the transaction before advancing.

    Re-running a page is safe because canonical fingerprints and observation source
    keys are unique per tenant. A page is intentionally one transaction so a failed
    projection cannot advance the cursor without its findings.
    """
    if source not in {"external", "native"}:
        raise ValueError("unknown backfill source")
    if not 1 <= limit <= 500:
        raise ValueError("backfill page size must be between 1 and 500")
    if source == "external":
        statement = select(ExternalSecurityAlert).where(
            ExternalSecurityAlert.organization_id == organization_id
        )
        if after_id is not None:
            statement = statement.where(ExternalSecurityAlert.id > after_id)
        external_rows = (
            (await session.execute(statement.order_by(ExternalSecurityAlert.id).limit(limit)))
            .scalars()
            .all()
        )
        if not external_rows:
            return None, 0, 0
        projected = await ingest_external_alerts(session, organization_id, list(external_rows))
        return external_rows[-1].id, len(external_rows), projected

    native_statement = select(Finding).where(Finding.organization_id == organization_id)
    if after_id is not None:
        native_statement = native_statement.where(Finding.id > after_id)
    native_rows = (
        (await session.execute(native_statement.order_by(Finding.id).limit(limit))).scalars().all()
    )
    if not native_rows:
        return None, 0, 0
    projected = await ingest_native_findings(session, organization_id, list(native_rows))
    return native_rows[-1].id, len(native_rows), projected
