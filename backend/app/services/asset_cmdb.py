"""Bounded CMDB CSV intake for existing tenant-owned asset business context."""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.enums import CriticalitySource, Permission
from app.db.models.asset import Asset
from app.db.models.identity import Organization
from app.services import audit as audit_service
from app.services.canonical_identity import asset_storage_name, normalized_asset_identity
from app.services.context import Principal

MAX_CMDB_BYTES = 1_000_000
MAX_CMDB_ROWS = 1_000
_COLUMNS = frozenset({"asset_type", "asset_value", "tier", "owner_team", "environment", "groups"})
_TIERS = {
    "tier0": "critical",
    "tier1": "high",
    "tier2": "normal",
    "tier3": "low",
    "critical": "critical",
    "high": "high",
    "normal": "normal",
    "low": "low",
}
_ENVIRONMENTS = frozenset({"production", "staging", "development", "test", "unknown"})


@dataclass(frozen=True)
class CmdbRow:
    asset_type: str
    asset_value: str
    criticality: str | None
    owner_team: str | None
    environment: str | None
    groups: list[str] | None


def parse_cmdb_csv(data: bytes) -> list[CmdbRow]:
    if not data or len(data) > MAX_CMDB_BYTES or b"\x00" in data:
        raise ValueError("CMDB CSV must be nonempty, valid, and at most 1 MB")
    try:
        decoded = data.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(decoded, newline=""), strict=True)
        columns = reader.fieldnames or []
        if len(columns) != len(set(columns)):
            raise ValueError("duplicate CMDB column")
        unknown = set(columns) - _COLUMNS
        if unknown:
            raise ValueError(f"unknown column: {', '.join(sorted(unknown))}")
        if not {"asset_type", "asset_value"}.issubset(columns):
            raise ValueError("asset_type and asset_value columns are required")
        if not ({"tier", "owner_team", "environment", "groups"} & set(columns)):
            raise ValueError("at least one business context column is required")
        rows: list[CmdbRow] = []
        seen: set[tuple[str, str]] = set()
        for raw in reader:
            if len(rows) >= MAX_CMDB_ROWS:
                raise ValueError("CMDB CSV exceeds the 1000-row limit")
            if None in raw:
                raise ValueError("CMDB row has more values than columns")
            raw_type = (raw.get("asset_type") or "").strip().lower()
            raw_value = (raw.get("asset_value") or "").strip()
            if (
                not re.fullmatch(r"[a-z][a-z0-9_]{0,39}", raw_type)
                or not raw_value
                or len(raw_value) > 2048
                or any(ord(char) < 32 for char in raw_value)
            ):
                raise ValueError("invalid CMDB asset identity")
            if raw_type in {"url", "website"}:
                parsed_url = urlsplit(raw_value)
                if (
                    parsed_url.username
                    or parsed_url.password
                    or parsed_url.query
                    or parsed_url.fragment
                ):
                    raise ValueError("invalid CMDB asset identity: URL credentials or parameters")
            kind, value = normalized_asset_identity(
                raw_type,
                raw_value,
            )
            if (kind, value) in seen:
                raise ValueError("duplicate asset identity in CMDB CSV")
            seen.add((kind, value))
            tier = (raw.get("tier") or "").strip().lower()
            if tier and tier not in _TIERS:
                raise ValueError("invalid CMDB tier")
            team = (raw.get("owner_team") or "").strip()
            if len(team) > 120:
                raise ValueError("owner_team exceeds 120 characters")
            environment = (raw.get("environment") or "").strip().lower()
            if environment and environment not in _ENVIRONMENTS:
                raise ValueError("invalid CMDB environment")
            raw_groups = (raw.get("groups") or "").strip()
            groups = [value.strip() for value in raw_groups.split(";") if value.strip()]
            if len(groups) > 30 or any(len(value) > 60 for value in groups):
                raise ValueError("CMDB groups must contain at most 30 names of 1 to 60 characters")
            if len({value.casefold() for value in groups}) != len(groups):
                raise ValueError("CMDB groups must be unique")
            if not (tier or team or environment or groups):
                raise ValueError("CMDB row has no business context")
            rows.append(CmdbRow(kind, value, _TIERS.get(tier), team or None, environment or None, groups or None))
        if not rows:
            raise ValueError("CMDB CSV has no rows")
        return rows
    except UnicodeDecodeError as exc:
        raise ValueError("CMDB CSV must be UTF-8") from exc
    except csv.Error as exc:
        raise ValueError("CMDB CSV is malformed") from exc


async def apply_cmdb_csv(
    session: AsyncSession,
    principal: Principal,
    rows: list[CmdbRow],
    *,
    dry_run: bool,
) -> dict[str, object]:
    principal.require(Permission.ASSET_TAG)
    if not rows or len(rows) > MAX_CMDB_ROWS:
        raise ValueError("CMDB import must contain 1 to 1000 rows")
    names = {
        name
        for row in rows
        for name in (row.asset_value, asset_storage_name(row.asset_type, row.asset_value))
    }
    stmt = select(Asset).where(
        Asset.organization_id == principal.organization_id,
        Asset.name.in_(names),
    )
    if not dry_run:
        stmt = stmt.with_for_update()
    assets = (await session.execute(stmt)).scalars().all()
    matched = updated = 0
    unmatched: list[str] = []
    scoring_context_changed = False
    for row in rows:
        storage_name = asset_storage_name(row.asset_type, row.asset_value)
        candidates = [
            asset
            for asset in assets
            if asset.organization_id == principal.organization_id
            and asset.name in {row.asset_value, storage_name}
            and _same_identity(asset, row)
        ]
        if len(candidates) != 1:
            unmatched.append(f"{row.asset_type}:{row.asset_value}")
            continue
        asset = candidates[0]
        matched += 1
        changes: dict[str, str] = {}
        if (
            row.criticality is not None
            and asset.criticality_source != CriticalitySource.OPERATOR_TAG.value
            and (asset.criticality != row.criticality or asset.criticality_source != "cmdb")
        ):
            changes["criticality"] = row.criticality
            scoring_context_changed |= asset.criticality != row.criticality
        if row.owner_team is not None and asset.owner_team != row.owner_team:
            changes["owner_team"] = row.owner_team
        if row.environment is not None and asset.environment != row.environment:
            changes["environment"] = row.environment
            scoring_context_changed = True
        if row.groups is not None and asset.groups != row.groups:
            changes["groups"] = row.groups
        if not changes:
            continue
        updated += 1
        if dry_run:
            continue
        for key, value in changes.items():
            setattr(asset, key, value)
        if "criticality" in changes:
            asset.criticality_source = "cmdb"
            asset.criticality_rationale = "Imported from CMDB business tier."
        await audit_service.record(
            session,
            action=audit_service.AuditAction.ASSET_CONTEXT_SET,
            principal=principal,
            resource_type="asset",
            resource_id=asset.id,
            detail={"source": "cmdb", "fields": sorted(changes)},
        )
    if scoring_context_changed and not dry_run:
        await session.execute(
            update(Organization)
            .where(Organization.id == principal.organization_id)
            .values(risk_policy_version=Organization.risk_policy_version + 1)
        )
    return {"matched": matched, "updated": updated, "unmatched": unmatched}


def _same_identity(asset: Asset, row: CmdbRow) -> bool:
    if asset.name == asset_storage_name(row.asset_type, row.asset_value):
        return asset.asset_type == row.asset_type
    try:
        return normalized_asset_identity(asset.asset_type, asset.name) == (
            row.asset_type,
            row.asset_value,
        )
    except ValueError:
        return False
