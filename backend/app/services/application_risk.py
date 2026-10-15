"""Tenant-scoped ASPM rollups over the canonical finding and asset tables."""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from typing import Any

from sqlalchemy import and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.enums import Permission
from app.db.models.asset import Asset
from app.db.models.canonical import CanonicalFinding, FindingObservation
from app.schemas.application_risk import (
    ApplicationPatternOut,
    ApplicationPatternsOut,
    ApplicationRiskOut,
    ApplicationRiskPageOut,
)
from app.services.canonical_identity import normalized_asset_identity
from app.services.context import Principal

_ACTIVE = ("new", "open", "reopened")
_REPOSITORY_TYPES = ("repo", "repository")
_RULE = re.compile(r"[A-Za-z0-9_.:/-]{1,120}\Z")
_MAX_PATTERN_ROWS = 5_000
_MAX_PATTERNS = 20


def _repository_identity(name: str) -> str:
    raw = name[5:] if name.lower().startswith("repo:") else name
    try:
        return normalized_asset_identity("repo", raw)[1]
    except ValueError:
        return raw.strip().lower()


async def list_application_risks(
    session: AsyncSession,
    principal: Principal,
    *,
    limit: int = 50,
    offset: int = 0,
) -> ApplicationRiskPageOut:
    principal.require(Permission.ASSET_READ, Permission.FINDING_READ)
    if limit < 1 or limit > 100 or offset < 0:
        raise ValueError("invalid application risk page")
    app = Asset.custom_fields["application"].astext
    conditions = (
        Asset.organization_id == principal.organization_id,
        app.is_not(None),
        app != "",
    )
    total = int(
        (
            await session.execute(select(func.count(func.distinct(app))).where(*conditions))
        ).scalar_one()
    )
    active_join = and_(
        CanonicalFinding.asset_id == Asset.id,
        CanonicalFinding.organization_id == principal.organization_id,
        CanonicalFinding.status.in_(_ACTIVE),
    )
    finding_count = func.count(CanonicalFinding.id)
    critical_count = func.sum(
        case((CanonicalFinding.severity == "critical", 1), else_=0)
    )
    high_count = func.sum(case((CanonicalFinding.severity == "high", 1), else_=0))
    max_risk = func.coalesce(func.max(CanonicalFinding.risk_score), 0.0)
    # Application exposure should not collapse to its single worst finding.  This
    # bounded rollup keeps one critical issue prominent while surfacing a product that
    # has a concentrated backlog of critical/high issues across repositories and assets.
    aggregate_risk = func.least(
        100.0,
        max_risk
        + func.coalesce(critical_count, 0) * 5.0
        + func.coalesce(high_count, 0) * 2.0
        + func.least(15.0, finding_count * 0.5),
    ).label("aggregate_risk")
    rows = (
        await session.execute(
            select(
                app,
                func.count(func.distinct(Asset.id)),
                finding_count,
                critical_count,
                high_count,
                max_risk,
                aggregate_risk,
            )
            .select_from(Asset)
            .outerjoin(CanonicalFinding, active_join)
            .where(*conditions)
            .group_by(app)
            .order_by(aggregate_risk.desc(), max_risk.desc(), app)
            .limit(limit)
            .offset(offset)
        )
    ).all()
    return ApplicationRiskPageOut(
        items=[
            ApplicationRiskOut(
                application=name,
                asset_count=int(assets),
                active_findings=int(findings),
                critical=int(critical or 0),
                high=int(high or 0),
                max_risk_score=float(max_risk or 0),
                aggregate_risk_score=float(aggregate_risk or 0),
            )
            for name, assets, findings, critical, high, max_risk, aggregate_risk in rows
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


async def get_application_patterns(
    session: AsyncSession,
    principal: Principal,
    application: str,
) -> ApplicationPatternsOut:
    principal.require(Permission.ASSET_READ, Permission.FINDING_READ)
    if not application or len(application) > 120 or any(ord(ch) < 32 for ch in application):
        raise ValueError("invalid application name")
    app = Asset.custom_fields["application"].astext
    rows = (
        await session.execute(
            select(CanonicalFinding, Asset, FindingObservation)
            .join(
                Asset,
                and_(
                    Asset.id == CanonicalFinding.asset_id,
                    Asset.organization_id == CanonicalFinding.organization_id,
                ),
            )
            .outerjoin(
                FindingObservation,
                and_(
                    FindingObservation.canonical_finding_id == CanonicalFinding.id,
                    FindingObservation.organization_id == CanonicalFinding.organization_id,
                ),
            )
            .where(
                CanonicalFinding.organization_id == principal.organization_id,
                Asset.organization_id == principal.organization_id,
                app == application,
                Asset.asset_type.in_(_REPOSITORY_TYPES),
                CanonicalFinding.status.in_(_ACTIVE),
            )
            .order_by(CanonicalFinding.risk_score.desc(), CanonicalFinding.id)
            .limit(_MAX_PATTERN_ROWS + 1)
        )
    ).all()
    truncated = len(rows) > _MAX_PATTERN_ROWS
    groups: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"repos": {}, "findings": set(), "risk": 0.0, "confidence": "rule"}
    )
    seen_findings: set[uuid.UUID] = set()
    for finding, asset, observation in rows[:_MAX_PATTERN_ROWS]:
        if (
            finding.organization_id != principal.organization_id
            or asset.organization_id != principal.organization_id
            or asset.id != finding.asset_id
            or (asset.custom_fields or {}).get("application") != application
            or asset.asset_type not in _REPOSITORY_TYPES
            or finding.status not in _ACTIVE
        ):
            continue
        seen_findings.add(finding.id)
        cves = [
            cve
            for cve in (finding.cve_ids or [])
            if isinstance(cve, str)
            and re.fullmatch(
                r"CVE-\d{4}-\d{4,}",
                cve,
                re.I,
            )
        ][:5]
        if cves:
            keys = [(cve.upper(), "cve") for cve in cves]
        else:
            evidence = (
                observation.evidence
                if observation and isinstance(observation.evidence, dict)
                else {}
            )
            rule = evidence.get("rule_id")
            provider = observation.provider if observation else ""
            keys = (
                [(f"{provider}:{rule}", "rule")]
                if (
                    isinstance(rule, str)
                    and isinstance(provider, str)
                    and _RULE.fullmatch(rule)
                    and _RULE.fullmatch(provider)
                )
                else []
            )
        for key, confidence in keys:
            group = groups[key]
            group["repos"][_repository_identity(asset.name)] = asset.name[:512]
            group["findings"].add(finding.id)
            group["risk"] = max(group["risk"], float(finding.risk_score or 0))
            group["confidence"] = confidence
    patterns = [
        ApplicationPatternOut(
            key=key,
            confidence=group["confidence"],
            repository_count=len(group["repos"]),
            repositories=sorted(group["repos"].values()),
            finding_ids=sorted(group["findings"], key=str),
            max_risk_score=group["risk"],
        )
        for key, group in groups.items()
        if len(group["repos"]) >= 2
    ]
    patterns.sort(key=lambda item: (-item.max_risk_score, -item.repository_count, item.key))
    if len(patterns) > _MAX_PATTERNS:
        truncated = True
    return ApplicationPatternsOut(
        application=application,
        patterns=patterns[:_MAX_PATTERNS],
        findings_sampled=len(seen_findings),
        truncated=truncated,
    )
