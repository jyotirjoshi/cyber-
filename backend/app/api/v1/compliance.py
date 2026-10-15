"""Compliance-control evidence API backed by canonical findings."""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Query, status

from app.api.deps import DbSession, PrincipalDep
from app.schemas.common import OkOut
from app.schemas.compliance import (
    ComplianceControlCreateIn,
    ComplianceControlOut,
    ComplianceControlUpdateIn,
    ComplianceFindingMappingOut,
    ComplianceMappingCreateIn,
    ComplianceOverviewOut,
)
from app.services import compliance as compliance_service
from app.services.audit import AuditAction, record

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/overview", response_model=ComplianceOverviewOut)
async def get_compliance_overview(
    principal: PrincipalDep, session: DbSession
) -> ComplianceOverviewOut:
    return ComplianceOverviewOut(
        frameworks=await compliance_service.overview(session, principal)
    )


@router.get("/controls", response_model=list[ComplianceControlOut])
async def list_compliance_controls(
    principal: PrincipalDep,
    session: DbSession,
    framework: str | None = Query(
        default=None,
        pattern="^(pci_dss|iso_27001|soc_2|hipaa|nist_csf|cis_controls)$",
    ),
) -> list[ComplianceControlOut]:
    return await compliance_service.list_controls(session, principal, framework=framework)


@router.post(
    "/frameworks/{framework}/seed",
    response_model=list[ComplianceControlOut],
    status_code=status.HTTP_201_CREATED,
)
async def seed_compliance_framework(
    framework: Literal[
        "pci_dss", "iso_27001", "soc_2", "hipaa", "nist_csf", "cis_controls"
    ],
    principal: PrincipalDep,
    session: DbSession,
) -> list[ComplianceControlOut]:
    created = await compliance_service.seed_starter_controls(session, principal, framework)
    await record(
        session,
        action=AuditAction.COMPLIANCE_FRAMEWORK_SEED,
        principal=principal,
        resource_type="compliance_framework",
        resource_id=framework,
        detail={"framework": framework, "controls_created": len(created)},
    )
    await session.commit()
    return await compliance_service.list_controls(session, principal, framework=framework)


@router.post("/controls", response_model=ComplianceControlOut, status_code=status.HTTP_201_CREATED)
async def create_compliance_control(
    payload: ComplianceControlCreateIn, principal: PrincipalDep, session: DbSession
) -> ComplianceControlOut:
    control = await compliance_service.create_control(session, principal, payload)
    await record(
        session,
        action=AuditAction.COMPLIANCE_CONTROL_CREATE,
        principal=principal,
        resource_type="compliance_control",
        resource_id=control.id,
        detail={"framework": control.framework, "control_id": control.control_id},
    )
    await session.commit()
    return next(
        item
        for item in await compliance_service.list_controls(session, principal, framework=control.framework)
        if item.id == control.id
    )


@router.patch("/controls/{control_id}", response_model=ComplianceControlOut)
async def update_compliance_control(
    control_id: uuid.UUID,
    payload: ComplianceControlUpdateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> ComplianceControlOut:
    control = await compliance_service.update_control(session, principal, control_id, payload)
    await record(
        session,
        action=AuditAction.COMPLIANCE_CONTROL_UPDATE,
        principal=principal,
        resource_type="compliance_control",
        resource_id=control.id,
        detail={"fields": sorted(payload.model_fields_set)},
    )
    await session.commit()
    return next(
        item
        for item in await compliance_service.list_controls(session, principal, framework=control.framework)
        if item.id == control.id
    )


@router.get("/controls/{control_id}/mappings", response_model=list[ComplianceFindingMappingOut])
async def list_control_mappings(
    control_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> list[ComplianceFindingMappingOut]:
    return [
        ComplianceFindingMappingOut.model_validate(item)
        for item in await compliance_service.list_mappings(session, principal, control_id)
    ]


@router.post(
    "/controls/{control_id}/mappings",
    response_model=ComplianceFindingMappingOut,
    status_code=status.HTTP_201_CREATED,
)
async def add_control_mapping(
    control_id: uuid.UUID,
    payload: ComplianceMappingCreateIn,
    principal: PrincipalDep,
    session: DbSession,
) -> ComplianceFindingMappingOut:
    mapping = await compliance_service.add_finding_mapping(
        session,
        principal,
        control_id=control_id,
        canonical_finding_id=payload.canonical_finding_id,
        mapping_type=payload.mapping_type,
        note=payload.note,
    )
    await record(
        session,
        action=AuditAction.COMPLIANCE_MAPPING_CREATE,
        principal=principal,
        resource_type="compliance_finding_mapping",
        resource_id=mapping.id,
        detail={"control_id": str(control_id), "canonical_finding_id": str(mapping.canonical_finding_id)},
    )
    await session.commit()
    return ComplianceFindingMappingOut.model_validate(mapping)


@router.delete("/mappings/{mapping_id}", response_model=OkOut)
async def remove_control_mapping(
    mapping_id: uuid.UUID, principal: PrincipalDep, session: DbSession
) -> OkOut:
    mapping = await compliance_service.remove_finding_mapping(session, principal, mapping_id)
    await record(
        session,
        action=AuditAction.COMPLIANCE_MAPPING_DELETE,
        principal=principal,
        resource_type="compliance_finding_mapping",
        resource_id=mapping.id,
        detail={"control_id": str(mapping.control_id), "canonical_finding_id": str(mapping.canonical_finding_id)},
    )
    await session.commit()
    return OkOut()


__all__ = ["router"]
