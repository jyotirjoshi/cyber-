"""Fail-closed CI decision from tenant findings and completed scan imports."""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.db.enums import Permission
from app.db.models.asset import Asset
from app.db.models.canonical import CanonicalFinding
from app.db.models.scanner import ScannerJob
from app.db.repository import TenantRepository
from app.schemas.policy_gate import PolicyGateOut
from app.services.canonical_identity import asset_storage_name, normalized_asset_identity
from app.services.context import Principal

_ACTIVE_STATUSES = ("new", "open", "reopened")
_MAX_SCAN_AGE = dt.timedelta(days=7)
_SEVERITIES = ("critical", "high", "medium", "low", "info")
_COVERAGE_SCANNERS = {
    "repository": ("trivy_repo", "semgrep_repo", "gitleaks_repo"),
    "repo": ("trivy_repo", "semgrep_repo", "gitleaks_repo"),
    "container": ("trivy_image",),
    "container_image": ("trivy_image",),
    "image": ("trivy_image",),
}


async def evaluate_asset_gate(
    session: AsyncSession,
    principal: Principal,
    asset_id: uuid.UUID,
    *,
    now: dt.datetime | None = None,
) -> PolicyGateOut:
    principal.require(Permission.ASSET_READ, Permission.FINDING_READ)
    asset = await TenantRepository(
        session,
        Asset,
        principal.organization_id,
    ).get_or_404(asset_id)
    evaluated_at = now or utcnow()
    asset_ids = [asset.id]
    # Older provider imports used a synthetic asset name. Until those rows are
    # migrated, a gate must count their findings too or it can approve a deploy
    # despite a critical issue on the same repository/image.
    if asset.asset_type in {"repository", "repo", "container", "container_image", "image"}:
        try:
            kind, identity = normalized_asset_identity(asset.asset_type, asset.name)
        except ValueError:
            pass
        else:
            alias_name = asset_storage_name(kind, identity)
            aliases = (
                (
                    await session.execute(
                        select(Asset).where(
                            Asset.organization_id == principal.organization_id,
                            Asset.name == alias_name,
                            Asset.asset_type == kind,
                            Asset.port.is_(None),
                            Asset.protocol.is_(None),
                        )
                    )
                )
                .scalars()
                .all()
            )
            asset_ids.extend(
                alias.id
                for alias in aliases
                if alias.organization_id == principal.organization_id
                and alias.name == alias_name
                and alias.asset_type == kind
            )

    rows = (
        await session.execute(
            select(CanonicalFinding.severity, func.count(CanonicalFinding.id))
            .where(
                CanonicalFinding.organization_id == principal.organization_id,
                CanonicalFinding.asset_id.in_(asset_ids),
                CanonicalFinding.status.in_(_ACTIVE_STATUSES),
            )
            .group_by(CanonicalFinding.severity)
        )
    ).all()
    counts = {severity: 0 for severity in _SEVERITIES}
    for severity, count in rows:
        if severity in counts:
            counts[severity] = int(count)

    imported_at = (
        await session.execute(
            select(func.max(ScannerJob.imported_at)).where(
                ScannerJob.organization_id == principal.organization_id,
                ScannerJob.status == "COMPLETED",
                ScannerJob.imported_at.is_not(None),
                ScannerJob.scanner.in_(_COVERAGE_SCANNERS.get(asset.asset_type, ("nuclei", "zap"))),
                ScannerJob.targets.contains([asset.endpoint]),
            )
        )
    ).scalar_one()
    if counts["critical"]:
        decision, reason = "block", "critical_findings"
    elif (
        asset.status != "active"
        or imported_at is None
        or imported_at < evaluated_at - _MAX_SCAN_AGE
    ):
        decision, reason = "unknown", "missing_or_stale_scan"
    elif counts["high"]:
        decision, reason = "warn", "high_findings"
    else:
        decision, reason = "pass", "no_blocking_findings"
    return PolicyGateOut(
        asset_id=asset.id,
        decision=decision,
        allow_deploy=decision in {"pass", "warn"},
        reason_code=reason,
        counts=counts,
        scan_imported_at=imported_at,
        evaluated_at=evaluated_at,
    )
