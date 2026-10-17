"""PTaaS service operations enforce tenant and concurrency boundaries."""

import uuid

import pytest
from sqlalchemy import JSON, Column, MetaData, Table, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.errors import ConflictError, ResourceNotFoundError
from app.db.enums import Role
from app.db.models.audit import AuditEvent
from app.db.models.engagement import Engagement
from app.schemas.engagement import EngagementCreateIn
from app.services.context import Principal
from app.services.engagement import create_engagement, get_engagement, update_status


@pytest.fixture
async def engagement_store():
    engine = create_async_engine("sqlite+aiosqlite://")
    metadata = MetaData()
    for model in (Engagement, AuditEvent):
        Table(
            model.__tablename__,
            metadata,
            *[
                Column(
                    column.name,
                    JSON()
                    if isinstance(column.type, JSONB)
                    else Uuid()
                    if isinstance(column.type, Uuid)
                    else column.type,
                    primary_key=column.primary_key,
                    nullable=column.nullable,
                    server_default=column.server_default,
                )
                for column in model.__table__.columns
            ],
        )
    async with engine.begin() as connection:
        await connection.run_sync(metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield factory
    finally:
        await engine.dispose()


def _principal(organization_id: uuid.UUID) -> Principal:
    return Principal(
        user_id=None,
        organization_id=organization_id,
        role=Role.OWNER,
        request_id="engagement-test",
    )


@pytest.mark.asyncio
async def test_create_and_status_change_are_audited_and_versioned(engagement_store) -> None:
    principal = _principal(uuid.uuid4())
    async with engagement_store() as session:
        row = await create_engagement(
            session,
            principal,
            EngagementCreateIn(title="External API pentest"),
        )
        await session.commit()
        assert row.status == "draft"
        assert row.version == 1

        row = await update_status(
            session,
            principal,
            row.id,
            status="scoping",
            expected_version=1,
        )
        await session.commit()
        assert row.status == "scoping"
        assert row.version == 2

        events = list((await session.scalars(AuditEvent.__table__.select())).all())
        assert len(events) == 2


@pytest.mark.asyncio
async def test_cross_tenant_lookup_is_not_found_and_stale_update_conflicts(
    engagement_store,
) -> None:
    owner = _principal(uuid.uuid4())
    outsider = _principal(uuid.uuid4())
    async with engagement_store() as session:
        row = await create_engagement(
            session,
            owner,
            EngagementCreateIn(title="Internal network pentest"),
        )
        await session.commit()

        with pytest.raises(ResourceNotFoundError):
            await get_engagement(session, outsider, row.id)
        with pytest.raises(ConflictError):
            await update_status(
                session,
                owner,
                row.id,
                status="scoping",
                expected_version=99,
            )
