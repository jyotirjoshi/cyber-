"""Breach and attack simulation campaign management."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response, status

from app.api.deps import DbSession, PaginationDep, PrincipalDep
from app.core.errors import ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.canonical import (
    AttackSimulationCampaign,
    AttackSimulationRun,
    AttackSimulationTechniqueRun,
)
from app.db.repository import tenant_select
from app.schemas.attack_simulation import (
    AttackSimulationCampaignCreateIn,
    AttackSimulationCampaignOut,
    AttackSimulationCampaignUpdateIn,
    AttackSimulationRunDetailOut,
    AttackSimulationRunOut,
    AttackSimulationTechniqueCatalogOut,
    AttackSimulationTechniqueRunOut,
)
from app.schemas.common import Page
from app.services.attack_simulation import create_campaign, run_campaign_now
from app.services.bas_techniques import list_techniques
from app.services.audit import AuditAction, record

router = APIRouter(prefix="/attack-simulations", tags=["attack-simulations"])


@router.get("/catalog", response_model=list[AttackSimulationTechniqueCatalogOut])
async def get_technique_catalog(
    principal: PrincipalDep,
) -> list[AttackSimulationTechniqueCatalogOut]:
    principal.require(Permission.ASSESSMENT_READ)
    return [
        AttackSimulationTechniqueCatalogOut(
            key=item.key,
            scenario=item.scenario,
            title=item.title,
            mitre_technique=item.mitre_technique,
            target_types=sorted(target.value for target in item.target_types),
            adapter=item.adapter.value,
            risk_class=item.risk_class,
            approval_required=item.approval_required,
            timeout_seconds=item.timeout_seconds,
            expected_evidence=list(item.expected_evidence),
            cleanup=item.cleanup,
            catalog_version=item.catalog_version,
        )
        for item in list_techniques()
    ]


@router.get("", response_model=Page[AttackSimulationCampaignOut])
async def list_campaigns(
    principal: PrincipalDep,
    session: DbSession,
    pagination: PaginationDep,
) -> Page[AttackSimulationCampaignOut]:
    from sqlalchemy import func, select

    principal.require(Permission.ASSESSMENT_READ)
    total = (
        await session.execute(
            select(func.count()).select_from(AttackSimulationCampaign).where(
                AttackSimulationCampaign.organization_id == principal.organization_id
            )
        )
    ).scalar_one()
    rows = list(
        (
            await session.scalars(
                tenant_select(AttackSimulationCampaign, principal.organization_id)
                .order_by(AttackSimulationCampaign.created_at.desc())
                .limit(pagination.limit)
                .offset(pagination.offset)
            )
        ).all()
    )
    return Page.build(
        [AttackSimulationCampaignOut.model_validate(r) for r in rows],
        total=int(total),
        limit=pagination.limit,
        offset=pagination.offset,
    )


@router.post("", response_model=AttackSimulationCampaignOut, status_code=status.HTTP_201_CREATED)
async def create_attack_simulation_campaign(
    payload: AttackSimulationCampaignCreateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> AttackSimulationCampaignOut:
    campaign = await create_campaign(session, principal, payload)
    await session.commit()
    return AttackSimulationCampaignOut.model_validate(campaign)


@router.get("/{campaign_id}", response_model=AttackSimulationCampaignOut)
async def get_campaign(
    campaign_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> AttackSimulationCampaignOut:
    principal.require(Permission.ASSESSMENT_READ)
    campaign = (
        await session.execute(
            tenant_select(AttackSimulationCampaign, principal.organization_id).where(
                AttackSimulationCampaign.id == campaign_id
            )
        )
    ).scalar_one_or_none()
    if campaign is None or campaign.organization_id != principal.organization_id:
        raise ResourceNotFoundError("Attack simulation campaign not found")
    return AttackSimulationCampaignOut.model_validate(campaign)


@router.patch("/{campaign_id}", response_model=AttackSimulationCampaignOut)
async def update_campaign(
    campaign_id: uuid.UUID,
    payload: AttackSimulationCampaignUpdateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> AttackSimulationCampaignOut:
    principal.require(Permission.ASSESSMENT_CREATE)
    campaign = (
        await session.execute(
            tenant_select(AttackSimulationCampaign, principal.organization_id)
            .where(AttackSimulationCampaign.id == campaign_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if campaign is None or campaign.organization_id != principal.organization_id:
        raise ResourceNotFoundError("Attack simulation campaign not found")
    if payload.name is not None:
        campaign.name = payload.name
    if payload.scenarios is not None:
        campaign.scenarios = list(payload.scenarios)
    if payload.targets is not None:
        campaign.targets = list(payload.targets)
    if payload.cron_expression is not None:
        campaign.cron_expression = payload.cron_expression
    if payload.status is not None:
        campaign.status = payload.status
    await record(
        session,
        action=AuditAction.ATTACK_SIMULATION_UPDATE,
        principal=principal,
        resource_type="attack_simulation_campaign",
        resource_id=campaign.id,
        detail={"operation": "update"},
    )
    await session.commit()
    return AttackSimulationCampaignOut.model_validate(campaign)


@router.delete("/{campaign_id}", status_code=204, response_class=Response)
async def delete_campaign(
    campaign_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> Response:
    principal.require(Permission.ASSESSMENT_CREATE)
    campaign = (
        await session.execute(
            tenant_select(AttackSimulationCampaign, principal.organization_id).where(
                AttackSimulationCampaign.id == campaign_id
            )
        )
    ).scalar_one_or_none()
    if campaign is None or campaign.organization_id != principal.organization_id:
        raise ResourceNotFoundError("Attack simulation campaign not found")
    await session.delete(campaign)
    await record(
        session,
        action=AuditAction.ATTACK_SIMULATION_DELETE,
        principal=principal,
        resource_type="attack_simulation_campaign",
        resource_id=campaign_id,
        detail={"name": campaign.name},
    )
    await session.commit()
    return Response(status_code=204)


@router.post("/{campaign_id}/run", response_model=AttackSimulationCampaignOut)
async def trigger_campaign_run(
    campaign_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> AttackSimulationCampaignOut:
    """Trigger an immediate run for an active campaign, subject to authorization check."""
    campaign = await run_campaign_now(session, principal, campaign_id)
    await session.commit()
    return AttackSimulationCampaignOut.model_validate(campaign)


@router.get("/{campaign_id}/runs", response_model=list[AttackSimulationRunOut])
async def list_campaign_runs(
    campaign_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> list[AttackSimulationRunOut]:
    principal.require(Permission.ASSESSMENT_READ)
    rows = await session.scalars(
        tenant_select(AttackSimulationRun, principal.organization_id)
        .where(AttackSimulationRun.campaign_id == campaign_id)
        .order_by(AttackSimulationRun.created_at.desc())
        .limit(100)
    )
    return [AttackSimulationRunOut.model_validate(row) for row in rows.all()]


@router.get("/runs/{run_id}", response_model=AttackSimulationRunDetailOut)
async def get_simulation_run(
    run_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> AttackSimulationRunDetailOut:
    principal.require(Permission.ASSESSMENT_READ)
    run = await session.scalar(
        tenant_select(AttackSimulationRun, principal.organization_id).where(
            AttackSimulationRun.id == run_id
        )
    )
    if run is None:
        raise ResourceNotFoundError("Attack simulation run not found")
    technique_rows = await session.scalars(
        tenant_select(AttackSimulationTechniqueRun, principal.organization_id)
        .where(AttackSimulationTechniqueRun.run_id == run.id)
        .order_by(AttackSimulationTechniqueRun.created_at)
    )
    return AttackSimulationRunDetailOut(
        **AttackSimulationRunOut.model_validate(run).model_dump(),
        techniques=[
            AttackSimulationTechniqueRunOut.model_validate(row)
            for row in technique_rows.all()
        ],
    )


@router.post("/{campaign_id}/pause", response_model=AttackSimulationCampaignOut)
async def pause_attack_simulation_campaign(
    campaign_id: uuid.UUID,
    principal: PrincipalDep,
    session: DbSession,
) -> AttackSimulationCampaignOut:
    principal.require(Permission.ASSESSMENT_CREATE)
    campaign = (
        await session.execute(
            tenant_select(AttackSimulationCampaign, principal.organization_id)
            .where(AttackSimulationCampaign.id == campaign_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if campaign is None or campaign.organization_id != principal.organization_id:
        raise ResourceNotFoundError("Attack simulation campaign not found")
    campaign.status = "paused"
    await record(
        session,
        action=AuditAction.ATTACK_SIMULATION_PAUSE,
        principal=principal,
        resource_type="attack_simulation_campaign",
        resource_id=campaign.id,
        detail={"operation": "pause"},
    )
    await session.commit()
    return AttackSimulationCampaignOut.model_validate(campaign)


__all__ = ["router"]
