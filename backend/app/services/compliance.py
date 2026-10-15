"""Compliance control management and live finding-backed coverage calculations."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.canonical import CanonicalFinding
from app.db.models.compliance import ComplianceControl, ComplianceFindingMapping
from app.db.models.identity import User
from app.db.repository import TenantRepository, tenant_select
from app.schemas.compliance import (
    ComplianceControlCreateIn,
    ComplianceControlOut,
    ComplianceControlUpdateIn,
    ComplianceFrameworkSummaryOut,
)
from app.services.context import Principal

_RESOLVED_FINDING_STATUSES = ("closed", "mitigated", "false_positive")

# A focused starter catalogue, intentionally not a claim of certification.  These are
# the high-value controls needed to turn existing exposure data into an initial
# evidence register; tenants can add their exact control set through the same API.
_STARTER_CONTROLS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "pci_dss": (
        ("1.2", "Network security controls", "Network security"),
        ("5.2", "Malware protection", "Threat protection"),
        ("6.4", "Secure systems and software", "Secure development"),
        ("11.3", "External and internal penetration testing", "Security testing"),
    ),
    "iso_27001": (
        ("A.5.7", "Threat intelligence", "Organizational controls"),
        ("A.8.8", "Management of technical vulnerabilities", "Technological controls"),
        ("A.8.9", "Configuration management", "Technological controls"),
        ("A.8.29", "Security testing in development and acceptance", "Technological controls"),
    ),
    "soc_2": (
        ("CC6.1", "Logical and physical access controls", "Common Criteria"),
        ("CC7.1", "Detect and monitor system anomalies", "Common Criteria"),
        ("CC7.2", "Monitor security events", "Common Criteria"),
        ("CC8.1", "Manage change", "Common Criteria"),
    ),
    "hipaa": (
        ("164.308(a)(1)", "Security management process", "Administrative safeguards"),
        ("164.308(a)(5)", "Security awareness and training", "Administrative safeguards"),
        ("164.312(a)(1)", "Access control", "Technical safeguards"),
        ("164.312(e)(1)", "Transmission security", "Technical safeguards"),
    ),
    "nist_csf": (
        ("GV.OC", "Organizational context", "Govern"),
        ("ID.RA", "Risk assessment", "Identify"),
        ("PR.PS", "Platform security", "Protect"),
        ("DE.CM", "Continuous monitoring", "Detect"),
        ("RS.MA", "Incident management", "Respond"),
    ),
    "cis_controls": (
        ("1", "Inventory and control of enterprise assets", "Inventory"),
        ("2", "Inventory and control of software assets", "Inventory"),
        ("7", "Continuous vulnerability management", "Vulnerability management"),
        ("12", "Network infrastructure management", "Network defense"),
        ("18", "Penetration testing", "Security testing"),
    ),
}


async def _require_tenant_user(
    session: AsyncSession, organization_id: uuid.UUID, user_id: uuid.UUID | None
) -> None:
    if user_id is None:
        return
    user = await session.scalar(
        select(User).where(User.id == user_id, User.is_active.is_(True))
    )
    # A user record alone is not sufficient: owners must belong to the control's tenant.
    if user is None:
        raise ResourceNotFoundError("control owner not found")
    from app.db.models.identity import Membership

    membership = await session.scalar(
        select(Membership.id).where(
            Membership.organization_id == organization_id,
            Membership.user_id == user_id,
        )
    )
    if membership is None:
        raise ResourceNotFoundError("control owner not found")


async def create_control(
    session: AsyncSession, principal: Principal, payload: ComplianceControlCreateIn
) -> ComplianceControl:
    principal.require(Permission.ORG_MANAGE)
    await _require_tenant_user(session, principal.organization_id, payload.owner_user_id)
    control = ComplianceControl(
        organization_id=principal.organization_id,
        framework=payload.framework,
        control_id=payload.control_id,
        title=payload.title,
        family=payload.family,
        description=payload.description,
        owner_user_id=payload.owner_user_id,
        assessment_status=payload.assessment_status,
        evidence=payload.evidence,
    )
    try:
        # A savepoint keeps a uniqueness race from poisoning the request transaction,
        # which lets the API return a clean 409 rather than failing during its audit write.
        async with session.begin_nested():
            session.add(control)
            await session.flush()
    except IntegrityError as exc:
        raise ConflictError(
            "control already exists for this framework",
            user_message="This compliance control already exists.",
        ) from exc
    return control


async def seed_starter_controls(
    session: AsyncSession, principal: Principal, framework: str
) -> list[ComplianceControl]:
    """Create only missing starter controls; never overwrite tenant evidence."""
    principal.require(Permission.ORG_MANAGE)
    existing = set(
        (
            await session.scalars(
                tenant_select(ComplianceControl, principal.organization_id)
                .where(ComplianceControl.framework == framework)
                .with_only_columns(ComplianceControl.control_id)
            )
        ).all()
    )
    added: list[ComplianceControl] = []
    for control_id, title, family in _STARTER_CONTROLS[framework]:
        if control_id in existing:
            continue
        control = ComplianceControl(
            organization_id=principal.organization_id,
            framework=framework,
            control_id=control_id,
            title=title,
            family=family,
            assessment_status="not_assessed",
            evidence={},
        )
        session.add(control)
        added.append(control)
    await session.flush()
    return added


async def update_control(
    session: AsyncSession,
    principal: Principal,
    control_id: uuid.UUID,
    payload: ComplianceControlUpdateIn,
) -> ComplianceControl:
    principal.require(Permission.ORG_MANAGE)
    control = await TenantRepository(
        session, ComplianceControl, principal.organization_id
    ).get_or_404(control_id)
    if "owner_user_id" in payload.model_fields_set:
        await _require_tenant_user(session, principal.organization_id, payload.owner_user_id)
    for field in payload.model_fields_set:
        setattr(control, field, getattr(payload, field))
    await session.flush()
    return control


async def add_finding_mapping(
    session: AsyncSession,
    principal: Principal,
    *,
    control_id: uuid.UUID,
    canonical_finding_id: uuid.UUID,
    mapping_type: str,
    note: str | None,
) -> ComplianceFindingMapping:
    principal.require(Permission.ORG_MANAGE)
    control = await TenantRepository(
        session, ComplianceControl, principal.organization_id
    ).get_or_404(control_id)
    finding = await TenantRepository(
        session, CanonicalFinding, principal.organization_id
    ).get(canonical_finding_id)
    if finding is None:
        raise ResourceNotFoundError("canonical finding not found")
    existing = await session.scalar(
        tenant_select(ComplianceFindingMapping, principal.organization_id).where(
            ComplianceFindingMapping.control_id == control.id,
            ComplianceFindingMapping.canonical_finding_id == finding.id,
        )
    )
    if existing is not None:
        raise ConflictError(
            "compliance mapping already exists",
            user_message="That finding is already mapped to this control.",
        )
    mapping = ComplianceFindingMapping(
        organization_id=principal.organization_id,
        control_id=control.id,
        canonical_finding_id=finding.id,
        mapping_type=mapping_type,
        note=note,
        created_by_id=principal.user_id,
    )
    session.add(mapping)
    await session.flush()
    return mapping


async def remove_finding_mapping(
    session: AsyncSession, principal: Principal, mapping_id: uuid.UUID
) -> ComplianceFindingMapping:
    principal.require(Permission.ORG_MANAGE)
    mapping = await TenantRepository(
        session, ComplianceFindingMapping, principal.organization_id
    ).get_or_404(mapping_id)
    await session.delete(mapping)
    await session.flush()
    return mapping


async def list_mappings(
    session: AsyncSession, principal: Principal, control_id: uuid.UUID
) -> Sequence[ComplianceFindingMapping]:
    principal.require(Permission.FINDING_READ)
    await TenantRepository(
        session, ComplianceControl, principal.organization_id
    ).get_or_404(control_id)
    return (
        await session.scalars(
            tenant_select(ComplianceFindingMapping, principal.organization_id)
            .where(ComplianceFindingMapping.control_id == control_id)
            .order_by(
                ComplianceFindingMapping.created_at.desc(), ComplianceFindingMapping.id.desc()
            )
        )
    ).all()


async def list_controls(
    session: AsyncSession, principal: Principal, *, framework: str | None = None
) -> list[ComplianceControlOut]:
    principal.require(Permission.FINDING_READ)
    statement = tenant_select(ComplianceControl, principal.organization_id)
    if framework:
        statement = statement.where(ComplianceControl.framework == framework)
    controls = list(
        (
            await session.scalars(
                statement.order_by(ComplianceControl.framework, ComplianceControl.control_id)
            )
        ).all()
    )
    return await _control_views(session, principal.organization_id, controls)


async def overview(
    session: AsyncSession, principal: Principal
) -> list[ComplianceFrameworkSummaryOut]:
    controls = await list_controls(session, principal)
    grouped: dict[str, list[ComplianceControlOut]] = {}
    for control in controls:
        grouped.setdefault(control.framework, []).append(control)
    summaries: list[ComplianceFrameworkSummaryOut] = []
    for framework in sorted(grouped):
        rows = grouped[framework]
        mapped = [item for item in rows if item.mapped_finding_count > 0]
        count = len(rows)
        summaries.append(
            ComplianceFrameworkSummaryOut(
                framework=framework,
                control_count=count,
                mapped_control_count=len(mapped),
                at_risk_control_count=sum(item.effective_status == "at_risk" for item in rows),
                partially_satisfied_control_count=sum(
                    item.effective_status == "partially_satisfied" for item in rows
                ),
                satisfied_control_count=sum(item.effective_status == "satisfied" for item in rows),
                active_finding_count=sum(item.active_finding_count for item in rows),
                coverage_percent=round((len(mapped) / count) * 100, 2) if count else 0.0,
            )
        )
    return summaries


async def _control_views(
    session: AsyncSession,
    organization_id: uuid.UUID,
    controls: list[ComplianceControl],
) -> list[ComplianceControlOut]:
    if not controls:
        return []
    control_ids = [control.id for control in controls]
    rows = (
        await session.execute(
            select(
                ComplianceFindingMapping.control_id,
                CanonicalFinding.status,
                CanonicalFinding.risk_score,
            )
            .join(
                CanonicalFinding,
                CanonicalFinding.id == ComplianceFindingMapping.canonical_finding_id,
            )
            .where(
                ComplianceFindingMapping.organization_id == organization_id,
                CanonicalFinding.organization_id == organization_id,
                ComplianceFindingMapping.control_id.in_(control_ids),
            )
        )
    ).all()
    risks: dict[uuid.UUID, list[float]] = {control_id: [] for control_id in control_ids}
    mapping_counts: dict[uuid.UUID, int] = {control_id: 0 for control_id in control_ids}
    for control_id, status, risk_score in rows:
        mapping_counts[control_id] += 1
        if status not in _RESOLVED_FINDING_STATUSES:
            risks[control_id].append(float(risk_score))
    views: list[ComplianceControlOut] = []
    for control in controls:
        active_risks = risks[control.id]
        effective = _effective_status(
            control.assessment_status, active_risks, mapping_counts[control.id]
        )
        views.append(
            ComplianceControlOut(
                id=control.id,
                framework=control.framework,
                control_id=control.control_id,
                title=control.title,
                family=control.family,
                description=control.description,
                owner_user_id=control.owner_user_id,
                assessment_status=control.assessment_status,
                evidence=control.evidence,
                mapped_finding_count=mapping_counts[control.id],
                active_finding_count=len(active_risks),
                highest_risk_score=max(active_risks) if active_risks else None,
                effective_status=effective,
            )
        )
    return views


def _effective_status(
    assessment_status: str, active_risks: list[float], mapping_count: int
) -> str:
    if assessment_status == "not_applicable":
        return assessment_status
    if not active_risks:
        # A mapped control with no unresolved evidence is satisfied. An unmapped
        # control retains an assessor's explicit state instead of fabricating coverage.
        return "satisfied" if mapping_count else assessment_status
    return "at_risk" if max(active_risks) >= 70 else "partially_satisfied"


__all__ = [
    "add_finding_mapping",
    "create_control",
    "list_controls",
    "list_mappings",
    "overview",
    "remove_finding_mapping",
    "seed_starter_controls",
    "update_control",
]
