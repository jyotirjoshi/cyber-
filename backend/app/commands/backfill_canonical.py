"""Project existing alerts and DefectDojo findings after schema migration.

Run with ``python -m app.commands.backfill_canonical``. Every page commits
independently and the operation is idempotent, so interruption is recoverable by
running it again. No provider credentials or network calls are needed.
"""

from __future__ import annotations

import argparse
import asyncio
import uuid

import structlog
from sqlalchemy import select

from app.db.models.identity import Organization
from app.db.session import dispose_engine, session_scope
from app.services.canonical_backfill import Source, backfill_organization_page

log = structlog.get_logger(__name__)
_SOURCES: tuple[Source, ...] = ("external", "native")


async def backfill_all(*, batch_size: int = 100) -> None:
    if not 1 <= batch_size <= 500:
        raise ValueError("batch size must be between 1 and 500")
    after_organization: uuid.UUID | None = None
    while True:
        async with session_scope() as session:
            query = select(Organization.id)
            if after_organization is not None:
                query = query.where(Organization.id > after_organization)
            organization_id = (
                await session.execute(query.order_by(Organization.id).limit(1))
            ).scalar_one_or_none()
        if organization_id is None:
            return
        for source in _SOURCES:
            await _backfill_source(organization_id, source=source, batch_size=batch_size)
        after_organization = organization_id


async def _backfill_source(organization_id: uuid.UUID, *, source: Source, batch_size: int) -> None:
    after_id: uuid.UUID | None = None
    while True:
        async with session_scope() as session:
            cursor, processed, projected = await backfill_organization_page(
                session, organization_id, source=source, after_id=after_id, limit=batch_size
            )
        if processed == 0:
            return
        log.info(
            "canonical.backfill.page",
            organization_id=str(organization_id),
            source=source,
            processed=processed,
            projected=projected,
        )
        after_id = cursor
        if processed < batch_size:
            return


def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill tenant canonical findings")
    parser.add_argument("--batch-size", type=int, default=100)
    args = parser.parse_args()

    async def run() -> None:
        try:
            await backfill_all(batch_size=args.batch_size)
        finally:
            await dispose_engine()

    asyncio.run(run())


if __name__ == "__main__":
    main()
