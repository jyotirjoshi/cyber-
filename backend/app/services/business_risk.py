"""Business-service ownership, dependency mapping, and quantitative exposure."""

from __future__ import annotations

import re
import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.asset import Asset
from app.db.models.business_risk import (
    AssetBusinessService,
    BusinessRiskScenario,
    BusinessService,
)
from app.db.models.canonical import CanonicalFinding
from app.db.repository import tenant_select
from app.schemas.business_risk import (
    AssetServiceLinkIn,
    BusinessRiskScenarioIn,
    BusinessServiceCreateIn,
)
from app.services.audit import record
from app.services.context import Principal


def service_slug(name: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", name.strip().casefold()).strip("-")
    if not value:
        raise ValueError("business service name must contain letters or numbers")
    return value[:120]


async def create_service(
    session: AsyncSession, principal: Principal, payload: BusinessServiceCreateIn
) -> BusinessService:
    principal.require(Permission.ASSET_TAG)
    slug = service_slug(payload.name)
    exists = await session.scalar(
        select(BusinessService.id).where(
            BusinessService.organization_id == principal.organization_id,
            BusinessService.slug == slug,
        )
    )
    if exists is not None:
        raise ConflictError("A business service with this name already exists")
    row = BusinessService(
        organization_id=principal.organization_id,
        slug=slug,
        name=payload.name.strip(),
        description=payload.description,
        owner_team=payload.owner_team,
        owner_user_id=payload.owner_user_id,
        criticality=payload.criticality,
        environment=payload.environment,
        revenue_per_hour_usd=payload.revenue_per_hour_usd,
        maximum_loss_usd=payload.maximum_loss_usd,
        data_records_at_risk=payload.data_records_at_risk,
        regulatory_scopes=sorted(set(payload.regulatory_scopes)),
        metadata_=payload.metadata,
        status="active",
        version=1,
    )
    session.add(row)
    await session.flush()
    await record(
        session,
        action="business_service.create",
        principal=principal,
        resource_type="business_service",
        resource_id=row.id,
        detail={"slug": row.slug, "criticality": row.criticality},
    )
    return row


async def list_services(
    session: AsyncSession, principal: Principal
) -> list[BusinessService]:
    principal.require(Permission.ORG_READ)
    rows = await session.scalars(
        tenant_select(BusinessService, principal.organization_id).order_by(
            BusinessService.status, BusinessService.name
        )
    )
    return list(rows.all())


async def get_service(
    session: AsyncSession,
    principal: Principal,
    service_id: uuid.UUID,
    *,
    for_update: bool = False,
) -> BusinessService:
    principal.require(Permission.ORG_READ)
    query = tenant_select(BusinessService, principal.organization_id).where(
        BusinessService.id == service_id
    )
    if for_update:
        query = query.with_for_update()
    row = await session.scalar(query)
    if row is None:
        raise ResourceNotFoundError("Business service not found")
    return row


async def link_asset(
    session: AsyncSession,
    principal: Principal,
    service_id: uuid.UUID,
    payload: AssetServiceLinkIn,
) -> AssetBusinessService:
    principal.require(Permission.ASSET_TAG)
    await get_service(session, principal, service_id, for_update=True)
    asset = await session.scalar(
        tenant_select(Asset, principal.organization_id).where(Asset.id == payload.asset_id)
    )
    if asset is None:
        raise ResourceNotFoundError("Asset not found")
    row = await session.scalar(
        tenant_select(AssetBusinessService, principal.organization_id).where(
            AssetBusinessService.asset_id == asset.id,
            AssetBusinessService.business_service_id == service_id,
        )
    )
    if row is None:
        row = AssetBusinessService(
            organization_id=principal.organization_id,
            asset_id=asset.id,
            business_service_id=service_id,
        )
        session.add(row)
    row.dependency_type = payload.dependency_type
    row.importance_weight = payload.importance_weight
    row.recovery_time_minutes = payload.recovery_time_minutes
    row.recovery_point_minutes = payload.recovery_point_minutes
    row.provenance = payload.provenance
    await session.flush()
    await record(
        session,
        action="business_service.asset.link",
        principal=principal,
        resource_type="asset_business_service",
        resource_id=row.id,
        detail={"service_id": str(service_id), "asset_id": str(asset.id)},
    )
    return row


async def list_links(
    session: AsyncSession, principal: Principal, service_id: uuid.UUID
) -> list[AssetBusinessService]:
    await get_service(session, principal, service_id)
    rows = await session.scalars(
        tenant_select(AssetBusinessService, principal.organization_id)
        .where(AssetBusinessService.business_service_id == service_id)
        .order_by(AssetBusinessService.importance_weight.desc(), AssetBusinessService.asset_id)
    )
    return list(rows.all())


async def create_scenario(
    session: AsyncSession,
    principal: Principal,
    service_id: uuid.UUID,
    payload: BusinessRiskScenarioIn,
) -> BusinessRiskScenario:
    principal.require(Permission.ASSET_TAG)
    await get_service(session, principal, service_id, for_update=True)
    exists = await session.scalar(
        select(BusinessRiskScenario.id).where(
            BusinessRiskScenario.organization_id == principal.organization_id,
            BusinessRiskScenario.business_service_id == service_id,
            BusinessRiskScenario.name == payload.name.strip(),
        )
    )
    if exists is not None:
        raise ConflictError("This business service already has a scenario with that name")
    row = BusinessRiskScenario(
        organization_id=principal.organization_id,
        business_service_id=service_id,
        status="active",
        **payload.model_dump(),
    )
    row.name = row.name.strip()
    session.add(row)
    await session.flush()
    await record(
        session,
        action="business_risk_scenario.create",
        principal=principal,
        resource_type="business_risk_scenario",
        resource_id=row.id,
        detail={"service_id": str(service_id), "annual_probability": row.annual_probability},
    )
    return row


async def list_scenarios(
    session: AsyncSession, principal: Principal, service_id: uuid.UUID
) -> list[BusinessRiskScenario]:
    await get_service(session, principal, service_id)
    rows = await session.scalars(
        tenant_select(BusinessRiskScenario, principal.organization_id)
        .where(BusinessRiskScenario.business_service_id == service_id)
        .order_by(BusinessRiskScenario.status, BusinessRiskScenario.name)
    )
    return list(rows.all())


async def exposure_summary(
    session: AsyncSession, principal: Principal, service_id: uuid.UUID
) -> dict[str, object]:
    service = await get_service(session, principal, service_id)
    links = await list_links(session, principal, service_id)
    asset_ids = [item.asset_id for item in links]
    asset_count = len(asset_ids)
    internet_assets = 0
    open_findings = 0
    critical_findings = 0
    maximum_risk = 0.0
    if asset_ids:
        internet_assets = int(
            await session.scalar(
                select(func.count(Asset.id)).where(
                    Asset.organization_id == principal.organization_id,
                    Asset.id.in_(asset_ids),
                    Asset.internet_exposed.is_(True),
                )
            )
            or 0
        )
        finding_row = (
            await session.execute(
                select(
                    func.count(CanonicalFinding.id),
                    func.count(CanonicalFinding.id).filter(CanonicalFinding.severity == "critical"),
                    func.max(CanonicalFinding.risk_score),
                ).where(
                    CanonicalFinding.organization_id == principal.organization_id,
                    CanonicalFinding.asset_id.in_(asset_ids),
                    CanonicalFinding.status.in_(("new", "open", "reopened", "mitigated")),
                )
            )
        ).one()
        open_findings = int(finding_row[0] or 0)
        critical_findings = int(finding_row[1] or 0)
        maximum_risk = float(finding_row[2] or 0.0)
    scenarios = await list_scenarios(session, principal, service_id)
    annualized_loss = round(
        sum(item.annualized_loss_expectancy_usd for item in scenarios if item.status == "active"), 2
    )
    internet_ratio = internet_assets / max(1, asset_count)
    criticality_factor = {"critical": 1.0, "high": 0.75, "normal": 0.5, "low": 0.25}[
        service.criticality
    ]
    finding_pressure = min(1.0, open_findings / max(1, asset_count * 5))
    blast_radius_score = round(
        100
        * (
            0.35 * criticality_factor
            + 0.25 * internet_ratio
            + 0.20 * finding_pressure
            + 0.20 * min(1.0, maximum_risk / 100)
        ),
        2,
    )
    estimated_exposure = annualized_loss * (1 + blast_radius_score / 100)
    if service.maximum_loss_usd is not None:
        estimated_exposure = min(estimated_exposure, service.maximum_loss_usd)
    return {
        "service": service,
        "asset_count": asset_count,
        "internet_exposed_assets": internet_assets,
        "open_findings": open_findings,
        "critical_findings": critical_findings,
        "maximum_finding_risk": round(maximum_risk, 2),
        "blast_radius_score": blast_radius_score,
        "annualized_loss_expectancy_usd": annualized_loss,
        "estimated_exposure_usd": round(estimated_exposure, 2),
    }


__all__ = [
    "create_scenario",
    "create_service",
    "exposure_summary",
    "get_service",
    "link_asset",
    "list_links",
    "list_scenarios",
    "list_services",
    "service_slug",
]
