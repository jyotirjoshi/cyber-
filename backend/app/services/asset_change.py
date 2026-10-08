"""Inventory drift feed and batched notifications for passively discovered assets."""

from __future__ import annotations

import uuid

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.enums import NotificationEvent, Permission
from app.db.models.asset import Asset, AssetChange
from app.schemas.asset_change import AssetChangeOut, AssetChangePageOut
from app.services import notification as notification_service
from app.services.context import Principal
from app.services.notification import NotificationContent

_MAX_ALERT_ROWS = 1000


async def list_asset_changes(
    session: AsyncSession,
    principal: Principal,
    *,
    limit: int = 50,
    offset: int = 0,
) -> AssetChangePageOut:
    principal.require(Permission.ASSET_READ)
    if limit < 1 or limit > 100 or offset < 0:
        raise ValueError("invalid asset change page")
    org = principal.organization_id
    total = int(
        (
            await session.execute(
                select(func.count())
                .select_from(AssetChange)
                .where(AssetChange.organization_id == org)
            )
        ).scalar_one()
    )
    rows = (
        await session.execute(
            select(AssetChange, Asset.name)
            .join(
                Asset,
                and_(
                    Asset.id == AssetChange.asset_id,
                    Asset.organization_id == AssetChange.organization_id,
                ),
            )
            .where(AssetChange.organization_id == org, Asset.organization_id == org)
            .order_by(AssetChange.created_at.desc(), AssetChange.id.desc())
            .limit(limit)
            .offset(offset)
        )
    ).all()
    return AssetChangePageOut(
        items=[
            AssetChangeOut(
                id=change.id,
                asset_id=change.asset_id,
                assessment_id=change.assessment_id,
                asset_name=name,
                change_type=change.change_type,
                changes=change.changes,
                created_at=change.created_at,
            )
            for change, name in rows
            if change.organization_id == org
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


async def stage_new_asset_alert(
    session: AsyncSession,
    principal: Principal,
    *,
    assessment_id: uuid.UUID,
    seed_names: set[str],
    settings: Settings,
) -> int:
    """One outbox notification per assessment, never per certificate log entry."""
    org = principal.organization_id
    rows = (
        await session.execute(
            select(AssetChange, Asset)
            .join(
                Asset,
                and_(
                    Asset.id == AssetChange.asset_id,
                    Asset.organization_id == AssetChange.organization_id,
                ),
            )
            .where(
                AssetChange.organization_id == org,
                Asset.organization_id == org,
                AssetChange.assessment_id == assessment_id,
                AssetChange.change_type == "discovered",
            )
            .order_by(Asset.name, Asset.id)
            .limit(_MAX_ALERT_ROWS + 1)
        )
    ).all()
    names = sorted(
        {
            asset.name
            for change, asset in rows
            if (
                change.organization_id == org
                and asset.organization_id == org
                and change.assessment_id == assessment_id
                and change.asset_id == asset.id
                and change.change_type == "discovered"
                and asset.name not in seed_names
            )
        }
    )
    if not names:
        return 0
    count = len(names)
    truncated = len(rows) > _MAX_ALERT_ROWS
    preview = ", ".join(names[:5])
    suffix = ", and more" if count > 5 else ""
    await notification_service.dispatch(
        session,
        principal,
        event=NotificationEvent.NEW_ASSET,
        content=NotificationContent(
            subject=f"{count}{'+' if truncated else ''} new assets discovered",
            body=f"Passive discovery found {count}{' or more' if truncated else ''} assets not in the assessment seed: {preview}{suffix}.",
            link=f"{settings.public_base_url.rstrip('/')}/assets",
        ),
        settings=settings,
        resource_type="assessment",
        resource_id=str(assessment_id),
    )
    return count
