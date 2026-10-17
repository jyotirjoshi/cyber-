"""Operator-owned asset creation, bulk mutation, topology and immutable merge history."""

from __future__ import annotations

import csv
import datetime as dt
import io
import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, ResourceNotFoundError, UserError
from app.db.enums import AssetStatus, Criticality, CriticalitySource, Permission
from app.db.models.asset import Asset, AssetAlias, AssetMergeEvent, AssetRelationship
from app.db.models.identity import Membership
from app.db.repository import tenant_select
from app.schemas.asset import (
    AssetBulkUpdateIn,
    AssetCreateIn,
    AssetMergeIn,
    AssetRelationshipIn,
)
from app.services import audit as audit_service
from app.services.canonical_identity import asset_storage_name, normalized_asset_identity
from app.services.context import Principal

MAX_ASSET_CSV_BYTES = 2 * 1024 * 1024
MAX_ASSET_CSV_ROWS = 5_000


def _canonical_name(asset_type: str, name: str) -> tuple[str, str]:
    kind, value = normalized_asset_identity(asset_type, name)
    return kind, asset_storage_name(kind, value)


def _identity_from_asset(asset: Asset) -> tuple[str, str]:
    prefix = f"{asset.asset_type}:"
    value = asset.name[len(prefix) :] if asset.name.startswith(prefix) else asset.name
    return normalized_asset_identity(asset.asset_type, value)


async def _validate_owner(
    session: AsyncSession, organization_id: uuid.UUID, owner_user_id: uuid.UUID | None
) -> None:
    if owner_user_id is None:
        return
    member_id = (
        await session.execute(
            select(Membership.id).where(
                Membership.organization_id == organization_id,
                Membership.user_id == owner_user_id,
                Membership.accepted_at.is_not(None),
            )
        )
    ).scalar_one_or_none()
    if member_id is None:
        raise UserError(
            "asset owner is not an active member of this organization",
            user_message="Choose an active member of this organization as the asset owner.",
        )


async def create_asset(
    session: AsyncSession, principal: Principal, payload: AssetCreateIn
) -> Asset:
    principal.require(Permission.ASSET_TAG)
    kind, name = _canonical_name(payload.asset_type, payload.name)
    existing = (
        await session.execute(
            tenant_select(Asset, principal.organization_id).where(
                Asset.name == name,
                Asset.port.is_(None) if payload.port is None else Asset.port == payload.port,
                Asset.protocol.is_(None)
                if payload.protocol is None
                else Asset.protocol == payload.protocol,
                Asset.merged_into_id.is_(None),
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError("An active asset with this canonical identity already exists")
    now = dt.datetime.now(dt.UTC)
    row = Asset(
        id=uuid.uuid4(),
        organization_id=principal.organization_id,
        name=name,
        asset_type=kind,
        port=payload.port,
        protocol=payload.protocol,
        service=payload.service,
        internet_exposed=payload.internet_exposed,
        status=AssetStatus.ACTIVE.value,
        criticality=Criticality.UNKNOWN.value,
        criticality_source=CriticalitySource.DEFAULT.value,
        first_seen_at=now,
        last_seen_at=now,
        evidence={"manual": {"source": "operator", "observed_at": now.isoformat()}},
    )
    if payload.context is not None:
        if "owner_user_id" in payload.context.model_fields_set:
            await _validate_owner(
                session, principal.organization_id, payload.context.owner_user_id
            )
        for field, value in payload.context.model_dump(exclude_unset=True).items():
            setattr(row, field, value.value if hasattr(value, "value") else value)
    session.add(row)
    await session.flush()
    await audit_service.record(
        session,
        action="asset.create",
        principal=principal,
        resource_type="asset",
        resource_id=row.id,
        detail={"asset_type": kind, "manual": True},
    )
    return row


async def bulk_update_assets(
    session: AsyncSession, principal: Principal, payload: AssetBulkUpdateIn
) -> list[Asset]:
    principal.require(Permission.ASSET_TAG)
    ids = sorted((item.asset_id for item in payload.items), key=str)
    rows = list(
        (
            await session.execute(
                tenant_select(Asset, principal.organization_id)
                .where(Asset.id.in_(ids), Asset.merged_into_id.is_(None))
                .order_by(Asset.id)
                .with_for_update()
            )
        ).scalars().all()
    )
    by_id = {row.id: row for row in rows}
    if len(by_id) != len(ids):
        raise ResourceNotFoundError("One or more assets were not found")
    for item in payload.items:
        row = by_id[item.asset_id]
        if row.version != item.expected_version:
            raise ConflictError("Asset changed; reload before retrying")
        if item.context is not None:
            if "owner_user_id" in item.context.model_fields_set:
                await _validate_owner(
                    session, principal.organization_id, item.context.owner_user_id
                )
            for field, value in item.context.model_dump(exclude_unset=True).items():
                setattr(row, field, value.value if hasattr(value, "value") else value)
        if item.status is not None:
            row.status = item.status.value
        row.version += 1
    await audit_service.record(
        session,
        action="asset.bulk_update",
        principal=principal,
        resource_type="asset_batch",
        resource_id=None,
        detail={"asset_ids": [str(value) for value in ids], "count": len(ids)},
    )
    return [by_id[item.asset_id] for item in payload.items]


async def merge_assets(
    session: AsyncSession, principal: Principal, payload: AssetMergeIn
) -> AssetMergeEvent:
    principal.require(Permission.ASSET_TAG)
    ids = sorted((payload.source_asset_id, payload.target_asset_id), key=str)
    rows = list(
        (
            await session.execute(
                tenant_select(Asset, principal.organization_id)
                .where(Asset.id.in_(ids))
                .order_by(Asset.id)
                .with_for_update()
            )
        ).scalars().all()
    )
    by_id = {row.id: row for row in rows}
    source = by_id.get(payload.source_asset_id)
    target = by_id.get(payload.target_asset_id)
    if source is None or target is None:
        raise ResourceNotFoundError("Source or target asset was not found")
    if source.merged_into_id is not None or target.merged_into_id is not None:
        raise ConflictError("Merged assets cannot be merged again")
    if source.version != payload.source_expected_version or target.version != payload.target_expected_version:
        raise ConflictError("Asset changed; reload before retrying")
    source_snapshot = {
        "name": source.name,
        "asset_type": source.asset_type,
        "port": source.port,
        "protocol": source.protocol,
        "status": source.status,
        "version": source.version,
    }
    alias_kind, alias_value = _identity_from_asset(source)
    existing_alias = (
        await session.execute(
            tenant_select(AssetAlias, principal.organization_id).where(
                AssetAlias.alias_type == alias_kind,
                AssetAlias.alias_value == alias_value,
            )
        )
    ).scalar_one_or_none()
    if existing_alias is not None and existing_alias.asset_id != target.id:
        raise ConflictError("Asset alias already belongs to another canonical asset")
    aliases = list(
        (
            await session.execute(
                tenant_select(AssetAlias, principal.organization_id)
                .where(AssetAlias.asset_id == source.id)
                .with_for_update()
            )
        ).scalars().all()
    )
    for alias in aliases:
        alias.asset_id = target.id
    created_alias = existing_alias is None
    if created_alias:
        session.add(
            AssetAlias(
                organization_id=principal.organization_id,
                asset_id=target.id,
                alias_type=alias_kind,
                alias_value=alias_value,
                source_asset_id=source.id,
                created_by_id=principal.user_id,
            )
        )
    source.merged_into_id = target.id
    source.status = AssetStatus.OUT_OF_SCOPE.value
    source.selected_for_scanning = False
    source.version += 1
    target.version += 1
    event = AssetMergeEvent(
        organization_id=principal.organization_id,
        source_asset_id=source.id,
        target_asset_id=target.id,
        merged_by_id=principal.user_id,
        reason=payload.reason,
        source_snapshot=source_snapshot,
        moved_counts={
            "aliases": len(aliases) + int(created_alias),
            # Findings and topology retain the source id for immutable provenance.
            # The tombstone's merged_into_id resolves them to the canonical target.
            "provenance_rewritten": 0,
        },
    )
    session.add(event)
    await session.flush()
    await audit_service.record(
        session,
        action="asset.merge",
        principal=principal,
        resource_type="asset",
        resource_id=target.id,
        reason=payload.reason,
        detail={"source_asset_id": str(source.id), "merge_event_id": str(event.id)},
    )
    return event


async def _depends_on_reaches(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    start: uuid.UUID,
    target: uuid.UUID,
) -> bool:
    frontier = {start}
    visited: set[uuid.UUID] = set()
    relationships = AssetRelationship.__table__.c
    for _ in range(100):
        if target in frontier:
            return True
        current = frontier - visited
        if not current:
            return False
        visited.update(current)
        frontier = set(
            (
                await session.execute(
                    select(relationships.target_asset_id).where(
                        relationships.organization_id == organization_id,
                        relationships.relationship_type == "depends_on",
                        relationships.source_asset_id.in_(current),
                    )
                )
            ).scalars().all()
        )
    raise ConflictError("Asset dependency graph is too deep")


async def create_relationship(
    session: AsyncSession, principal: Principal, payload: AssetRelationshipIn
) -> AssetRelationship:
    principal.require(Permission.ASSET_TAG)
    assets = list(
        (
            await session.execute(
                tenant_select(Asset, principal.organization_id).where(
                    Asset.id.in_([payload.source_asset_id, payload.target_asset_id]),
                    Asset.merged_into_id.is_(None),
                )
            )
        ).scalars().all()
    )
    if len({asset.id for asset in assets}) != 2:
        raise ResourceNotFoundError("Relationship assets were not found")
    if payload.relationship_type == "depends_on" and await _depends_on_reaches(
        session,
        organization_id=principal.organization_id,
        start=payload.target_asset_id,
        target=payload.source_asset_id,
    ):
        raise ConflictError("Asset dependency would create a cycle")
    existing = (
        await session.execute(
            tenant_select(AssetRelationship, principal.organization_id).where(
                AssetRelationship.source_asset_id == payload.source_asset_id,
                AssetRelationship.target_asset_id == payload.target_asset_id,
                AssetRelationship.relationship_type == payload.relationship_type,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.evidence = dict(payload.evidence)
        return existing
    row = AssetRelationship(
        organization_id=principal.organization_id,
        source_asset_id=payload.source_asset_id,
        target_asset_id=payload.target_asset_id,
        relationship_type=payload.relationship_type,
        evidence=dict(payload.evidence),
        created_by_id=principal.user_id,
    )
    session.add(row)
    await session.flush()
    return row


async def list_relationships(
    session: AsyncSession, principal: Principal, asset_id: uuid.UUID
) -> Sequence[AssetRelationship]:
    principal.require(Permission.ASSET_READ)
    return list(
        (
            await session.execute(
                tenant_select(AssetRelationship, principal.organization_id)
                .where(
                    or_(
                        AssetRelationship.source_asset_id == asset_id,
                        AssetRelationship.target_asset_id == asset_id,
                    )
                )
                .order_by(AssetRelationship.created_at, AssetRelationship.id)
            )
        ).scalars().all()
    )


async def import_asset_rows(
    session: AsyncSession,
    principal: Principal,
    rows: Sequence[AssetCreateIn],
    *,
    dry_run: bool,
) -> dict[str, Any]:
    principal.require(Permission.ASSET_TAG)
    accepted = created = existing = 0
    errors: list[str] = []
    seen: set[tuple[str, str, int | None, str | None]] = set()
    for number, payload in enumerate(rows, start=2):
        try:
            kind, name = _canonical_name(payload.asset_type, payload.name)
            key = (kind, name, payload.port, payload.protocol)
            if key in seen:
                existing += 1
                continue
            seen.add(key)
            match = (
                await session.execute(
                    tenant_select(Asset, principal.organization_id).where(
                        Asset.name == name,
                        Asset.port.is_(None) if payload.port is None else Asset.port == payload.port,
                        Asset.protocol.is_(None)
                        if payload.protocol is None
                        else Asset.protocol == payload.protocol,
                    )
                )
            ).scalar_one_or_none()
            accepted += 1
            if match is not None:
                existing += 1
            elif not dry_run:
                await create_asset(session, principal, payload)
                created += 1
        except (ConflictError, ValueError) as exc:
            errors.append(f"row {number}: {exc.user_message if isinstance(exc, ConflictError) else str(exc)}")
    return {
        "accepted": accepted,
        "created": created,
        "existing": existing,
        "errors": errors[:100],
    }


async def export_inventory(session: AsyncSession, principal: Principal) -> bytes:
    principal.require(Permission.ASSET_READ)
    rows = list(
        (
            await session.execute(
                tenant_select(Asset, principal.organization_id)
                .where(Asset.merged_into_id.is_(None))
                .order_by(Asset.name, Asset.port, Asset.id)
                .limit(20_000)
            )
        ).scalars().all()
    )
    return export_asset_csv(rows)


def parse_asset_csv(data: bytes) -> list[AssetCreateIn]:
    if len(data) > MAX_ASSET_CSV_BYTES:
        raise ValueError("asset CSV exceeds 2 MiB")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("asset CSV must be UTF-8") from exc
    reader = csv.DictReader(io.StringIO(text))
    required = {"name", "asset_type"}
    if not reader.fieldnames or not required.issubset(reader.fieldnames):
        raise ValueError("asset CSV requires name and asset_type columns")
    rows: list[AssetCreateIn] = []
    for number, raw in enumerate(reader, start=2):
        if len(rows) >= MAX_ASSET_CSV_ROWS:
            raise ValueError("asset CSV exceeds 5,000 rows")
        try:
            rows.append(
                AssetCreateIn(
                    name=raw.get("name", ""),
                    asset_type=raw.get("asset_type", ""),
                    port=int(raw["port"]) if raw.get("port") else None,
                    protocol=raw.get("protocol") or None,
                    service=raw.get("service") or None,
                    internet_exposed=str(raw.get("internet_exposed", "")).lower()
                    in {"1", "true", "yes"},
                )
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"asset CSV row {number} is invalid") from exc
    return rows


def export_asset_csv(rows: Sequence[Asset]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        ["id", "name", "asset_type", "port", "protocol", "service", "status", "environment"]
    )
    for row in rows:
        writer.writerow(
            [row.id, row.name, row.asset_type, row.port or "", row.protocol or "", row.service or "", row.status, row.environment]
        )
    return output.getvalue().encode("utf-8")


__all__ = [
    "MAX_ASSET_CSV_BYTES",
    "bulk_update_assets",
    "create_asset",
    "create_relationship",
    "export_asset_csv",
    "export_inventory",
    "import_asset_rows",
    "list_relationships",
    "merge_assets",
    "parse_asset_csv",
]
