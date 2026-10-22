"""Idempotent tenant-local demo data; never launches a scanner or calls a provider."""

from __future__ import annotations

import hashlib
import json
import uuid
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.db.enums import Permission
from app.db.models.assessment import Assessment
from app.db.models.asset import Asset
from app.db.models.canonical import CanonicalFinding, FindingObservation
from app.db.models.control_plane import SecurityResource
from app.db.models.finding import TicketLink
from app.db.models.identity import Organization
from app.db.models.report import Report
from app.db.models.soc import SocIncidentCase
from app.db.repository import tenant_select
from app.integrations.storage import ObjectStorage, report_key
from app.schemas.platform import DemoWorkspaceOut
from app.services import audit as audit_service
from app.services import report as report_service
from app.services.context import Principal

_TITLE = "Cynux Demo Company — Sample Assessment"
_VERSION = "v1"


def demo_fingerprint(organization_id: uuid.UUID, entity_key: str) -> str:
    return hashlib.sha256(
        f"cynux-demo:{_VERSION}:{organization_id}:{entity_key}".encode()
    ).hexdigest()


def demo_report_document(*, assessment_reference: int, assessment_id: str) -> bytes:
    """Return the deterministic, explicitly synthetic demo report artifact."""
    payload = {
        "schema_version": "1.0",
        "synthetic_demo": True,
        "title": "Cynux Demo Company — Executive Exposure Report",
        "assessment": {"id": assessment_id, "reference": assessment_reference},
        "summary": {"assets": 3, "findings": 3, "critical": 1},
        "incident": {
            "key": "DEMO-INC-001",
            "title": "Suspicious access path to payment data",
            "status": "investigating",
        },
        "attack_paths": [
            {
                "entry_point": "shop.cynux-demo.example",
                "crown_jewel": "payments-db.cynux-demo.internal",
                "likelihood": "high",
                "blast_radius": "Payment records and transaction processing",
            }
        ],
        "remediation": [
            "Patch the storefront",
            "Enforce API object authorization",
            "Reduce database identity privileges",
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")


async def create_demo_workspace(
    session: AsyncSession, principal: Principal, *, storage: ObjectStorage
) -> DemoWorkspaceOut:
    """Create a coherent synthetic security story once within the active tenant."""
    principal.require(Permission.ASSESSMENT_CREATE)
    principal.require(Permission.REPORT_GENERATE)
    existing = (
        await session.execute(
            tenant_select(Assessment, principal.organization_id).where(
                Assessment.title == _TITLE,
                Assessment.extra_data.contains({"demo_seed_version": _VERSION}),
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return await _result(session, principal.organization_id, existing, reused=True)

    await session.execute(
        select(Organization).where(Organization.id == principal.organization_id).with_for_update()
    )
    existing = (
        await session.execute(
            tenant_select(Assessment, principal.organization_id).where(
                Assessment.title == _TITLE,
                Assessment.extra_data.contains({"demo_seed_version": _VERSION}),
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return await _result(session, principal.organization_id, existing, reused=True)

    reference = (
        int(
            (
                await session.scalar(
                    tenant_select(Assessment, principal.organization_id).with_only_columns(
                        func.max(Assessment.reference)
                    )
                )
            )
            or 0
        )
        + 1
    )
    now = utcnow()
    assessment = Assessment(
        id=uuid.uuid4(),
        organization_id=principal.organization_id,
        reference=reference,
        created_by_id=principal.user_id,
        title=_TITLE,
        scope="application",
        depth="standard",
        engagement_type="web_application",
        execution_mode="supervised",
        status="COMPLETED",
        current_stage="done",
        progress_percent=100,
        started_at=now,
        completed_at=now,
        request_interpretation={"synthetic_demo": True, "version": _VERSION},
        plan=[{"step": "synthetic_demo", "status": "completed", "external_execution": False}],
        findings_total=3,
        findings_critical=1,
        findings_high=1,
        findings_medium=1,
        assets_discovered=3,
        assets_in_scope=3,
    )
    session.add(assessment)

    asset_specs = [
        ("shop.cynux-demo.example", "domain", "critical", True, 0.93, ["nginx", "Node.js"]),
        ("api.cynux-demo.example", "url", "high", True, 0.81, ["FastAPI", "PostgreSQL"]),
        ("payments-db.cynux-demo.internal", "host", "critical", False, 0.72, ["PostgreSQL"]),
    ]
    assets: list[Asset] = []
    for name, asset_type, criticality, exposed, risk, technology in asset_specs:
        asset = Asset(
            id=uuid.uuid4(),
            organization_id=principal.organization_id,
            assessment_id=assessment.id,
            name=name,
            asset_type=asset_type,
            technology=technology,
            status="active",
            internet_exposed=exposed,
            criticality=criticality,
            criticality_source="operator_tag",
            criticality_rationale="Synthetic demo business context",
            environment="production",
            groups=["Cynux Demo", "Payments"],
            custom_fields={"synthetic_demo": True},
            risk_score=risk,
            selection_rationale="Included in the synthetic first-value journey",
            selected_for_scanning=True,
            evidence={"source": "cynux_demo", "synthetic": True},
            first_seen_at=now,
            last_seen_at=now,
            seen_in_assessments=[str(assessment.id)],
        )
        session.add(asset)
        assets.append(asset)

    finding_specs = [
        (
            "web",
            assets[0],
            "Internet-facing remote code execution",
            "critical",
            ["CVE-2025-29927"],
            96.0,
        ),
        ("api", assets[1], "Broken object authorization exposes payment records", "high", [], 84.0),
        (
            "cloud",
            assets[2],
            "Database service account has excessive privileges",
            "medium",
            [],
            67.0,
        ),
    ]
    findings: list[CanonicalFinding] = []
    for key, asset, title, severity, cves, risk_score in finding_specs:
        finding = CanonicalFinding(
            id=uuid.uuid4(),
            organization_id=principal.organization_id,
            asset_id=asset.id,
            fingerprint=demo_fingerprint(principal.organization_id, f"finding:{key}"),
            title=title,
            severity=severity,
            status="open",
            cve_ids=cves,
            risk_score=risk_score,
            risk_factors={
                "synthetic_demo": True,
                "inputs": {
                    "internet_exposed": asset.internet_exposed,
                    "asset_criticality": asset.criticality,
                    "exploit_available": key == "web",
                },
            },
            intel_evidence={"source": "cynux_demo", "synthetic": True},
            first_seen_at=now,
            last_seen_at=now,
            remediation_plan="Apply the recommended control, then run a targeted verification.",
            remediation_group="Cynux Demo hardening campaign",
            remediation_group_key="cynux demo hardening campaign",
            custom_fields={"synthetic_demo": True},
        )
        session.add(finding)
        session.add(
            FindingObservation(
                id=uuid.uuid4(),
                organization_id=principal.organization_id,
                canonical_finding_id=finding.id,
                provider="cynux_demo",
                external_id=f"demo-{key}",
                cve_id=cves[0] if cves else "",
                source_status="open",
                title=title,
                severity=severity,
                evidence={"synthetic": True, "asset_value": asset.name},
                first_seen_at=now,
                last_seen_at=now,
            )
        )
        findings.append(finding)

    session.add(
        TicketLink(
            id=uuid.uuid4(),
            organization_id=principal.organization_id,
            canonical_finding_id=findings[0].id,
            provider="jira",
            external_key="DEMO-101",
            url=None,
            project_key="DEMO",
            issue_type="Bug",
            external_status="In Progress",
            created_by_id=principal.user_id,
            created_by_agent=True,
        )
    )
    case = SocIncidentCase(
        id=uuid.uuid4(),
        organization_id=principal.organization_id,
        case_key="DEMO-INC-001",
        title="Suspicious access path to payment data",
        summary="Synthetic incident correlating the exposed storefront, API authorization weakness, and over-privileged database identity.",
        severity="critical",
        status="investigating",
        priority=95,
        owner_team="Security Operations",
        event_ids=[],
        asset_ids=[str(item.id) for item in assets],
        finding_ids=[str(item.id) for item in findings],
        evidence_refs=[{"kind": "synthetic_demo", "assessment_id": str(assessment.id)}],
        timeline=[
            {"occurred_at": now.isoformat(), "event": "Synthetic correlated incident created"}
        ],
        opened_at=now,
    )
    session.add(case)

    for kind, name, approved, risk in [
        ("ai_application", "Unapproved support copilot", False, "82.00"),
        ("ai_model", "Approved enterprise reasoning model", True, "18.00"),
        ("ai_agent", "Payments remediation agent", True, "35.00"),
        ("mcp_server", "Demo ticketing MCP server", True, "28.00"),
        ("ai_tool", "Create remediation ticket", True, "22.00"),
    ]:
        session.add(
            SecurityResource(
                id=uuid.uuid4(),
                organization_id=principal.organization_id,
                resource_key=f"cynux-demo:{kind}:{name.casefold().replace(' ', '-')}",
                kind=kind,
                name=name,
                provider="cynux_demo",
                external_id=None,
                owner_team="Security Engineering",
                environment="production",
                internet_exposed=kind == "ai_application",
                approved=approved,
                posture_status="at_risk" if not approved else "healthy",
                risk_score=Decimal(risk),
                sensitivity="confidential",
                classifications=["synthetic_demo"],
                permissions={},
                attributes={"synthetic_demo": True},
                provenance={"source": "cynux_demo"},
                source_count=1,
                identity_confidence=Decimal("1.000"),
                first_seen_at=now,
                last_seen_at=now,
            )
        )

    assessment.extra_data = {
        "demo_seed_version": _VERSION,
        "synthetic": True,
        "attack_paths": [
            {
                "entry_point": assets[0].name,
                "crown_jewel": assets[2].name,
                "asset_ids": [str(item.id) for item in assets],
                "finding_ids": [str(item.id) for item in findings],
                "likelihood": "high",
                "confidence": "high",
                "blast_radius": "Payment records and transaction processing",
                "chokepoints": [
                    "Patch the storefront",
                    "Enforce API object authorization",
                    "Reduce database identity privileges",
                ],
                "evidence_refs": [f"canonical:{item.id}" for item in findings],
            }
        ],
    }
    report = Report(
        id=uuid.uuid4(),
        organization_id=principal.organization_id,
        assessment_id=assessment.id,
        requested_by_id=principal.user_id,
        title="Cynux Demo Company — Executive Exposure Report",
        format="json",
        audience="executive",
        status="pending",
        content_digest={
            "synthetic_demo": True,
            "assets": 3,
            "findings": 3,
            "critical": 1,
            "incident_case": case.case_key,
        },
        degradations=[],
        executive_summary="Synthetic demonstration: a critical internet-facing weakness combines with authorization and identity-control gaps to create a credible path to payment data.",
        summary_ai_generated=False,
    )
    session.add(report)
    await audit_service.record(
        session,
        action=audit_service.AuditAction.ASSESSMENT_CREATE,
        principal=principal,
        resource_type="assessment",
        resource_id=assessment.id,
        detail={"synthetic_demo": True, "version": _VERSION},
    )
    await session.flush()
    artifact = demo_report_document(
        assessment_reference=assessment.reference,
        assessment_id=str(assessment.id),
    )
    stored = await storage.put_bytes(
        report_key(
            principal.organization_id,
            assessment.id,
            report.id,
            "cynux-demo-executive-report.json",
        ),
        artifact,
        content_type="application/json",
        organization_id=principal.organization_id,
        metadata={"synthetic-demo": "true"},
    )
    await report_service.complete_generation(
        session,
        report,
        stored=stored,
        executive_summary=report.executive_summary,
        summary_ai_generated=False,
        ai_model=None,
        content_digest=report.content_digest,
        degradations=[],
    )
    await audit_service.record(
        session,
        action=audit_service.AuditAction.REPORT_GENERATE,
        principal=principal,
        resource_type="report",
        resource_id=report.id,
        detail={
            "assessment_id": str(assessment.id),
            "format": "json",
            "audience": "executive",
            "synthetic_demo": True,
            "size_bytes": stored.size_bytes,
        },
    )
    return DemoWorkspaceOut(
        assessment_id=assessment.id,
        report_id=report.id,
        reused=False,
        assets=3,
        findings=3,
        incidents=1,
        tickets=1,
        attack_paths=1,
        ai_resources=5,
    )


async def _result(
    session: AsyncSession, organization_id: uuid.UUID, assessment: Assessment, *, reused: bool
) -> DemoWorkspaceOut:
    assets = list(
        (
            await session.scalars(
                tenant_select(Asset, organization_id).where(Asset.assessment_id == assessment.id)
            )
        ).all()
    )
    asset_ids = [item.id for item in assets]
    finding_ids = (
        list(
            (
                await session.scalars(
                    tenant_select(CanonicalFinding, organization_id)
                    .with_only_columns(CanonicalFinding.id)
                    .where(CanonicalFinding.asset_id.in_(asset_ids))
                )
            ).all()
        )
        if asset_ids
        else []
    )
    ticket_count = (
        int(
            (
                await session.scalar(
                    tenant_select(TicketLink, organization_id)
                    .with_only_columns(func.count())
                    .where(TicketLink.canonical_finding_id.in_(finding_ids))
                )
            )
            or 0
        )
        if finding_ids
        else 0
    )
    incident_count = int(
        (
            await session.scalar(
                tenant_select(SocIncidentCase, organization_id)
                .with_only_columns(func.count())
                .where(SocIncidentCase.case_key == "DEMO-INC-001")
            )
        )
        or 0
    )
    ai_resource_count = int(
        (
            await session.scalar(
                tenant_select(SecurityResource, organization_id)
                .with_only_columns(func.count())
                .where(SecurityResource.provider == "cynux_demo")
            )
        )
        or 0
    )
    report_id = await session.scalar(
        tenant_select(Report, organization_id)
        .with_only_columns(Report.id)
        .where(Report.assessment_id == assessment.id)
        .limit(1)
    )
    return DemoWorkspaceOut(
        assessment_id=assessment.id,
        report_id=report_id,
        reused=reused,
        assets=len(assets),
        findings=len(finding_ids),
        incidents=incident_count,
        tickets=ticket_count,
        attack_paths=len((assessment.extra_data or {}).get("attack_paths", [])),
        ai_resources=ai_resource_count,
    )


__all__ = ["create_demo_workspace", "demo_fingerprint", "demo_report_document"]
