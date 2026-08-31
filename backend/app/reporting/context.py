"""Assemble the structured snapshot a report is rendered from (FR-030).

This is step one of the three-module pipeline described in :mod:`app.reporting`.  It
turns an :class:`~app.db.models.assessment.Assessment` and everything hanging off it into
a plain, fully-materialized ``dict`` -- no ORM objects, no lazy relationships, nothing
that touches the database once :func:`build_report_context` returns.  The renderer and the
``content_digest`` frozen onto the ``reports`` row both consume this dict, so a report
re-opened months later shows what was true at generation time even though the live data
has moved on.

Two decisions worth recording:

**Every relationship is loaded explicitly, none is walked.**  ``lazy="raise_on_sql"``
means touching an unloaded relationship raises rather than emitting a query, so this
module reads through the tenant-scoped services (``findings_for_assessment``,
``load_enrichments``) and its own ``tenant_select`` queries, then joins them in memory by
id.  Findings are never asked for ``finding.asset`` or ``finding.enrichment`` directly --
the asset map and enrichment map are built once and looked up.

**No LLM here.**  The executive summary is prose and comes from a model, so it is the
renderer's concern (:mod:`app.reporting.generate`), not this module's.  Keeping the
context builder deterministic means the ``content_digest`` is reproducible and the whole
data-gathering path stays free of provider dependencies and prompt-injection surface.
Everything this module produces is *data*; the template escapes it (SEC-005 at render).
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.db.enums import ScannerName
from app.db.models.assessment import Assessment, AssessmentTarget, AuthorizationRecord
from app.db.models.asset import Asset
from app.db.models.finding import Finding, Remediation
from app.db.models.scanner import ScannerJob
from app.db.repository import tenant_select
from app.services import enrichment as enrichment_service
from app.services import finding as finding_service
from app.services.approval import granted_approval

log = structlog.get_logger(__name__)

#: Human-readable tool identity per scanner, so the methodology section names the tool a
#: reader recognises rather than the enum value. The version is read from the job's image
#: tag at render time -- there is no static version to hardcode.
_TOOL_LABELS: dict[str, str] = {
    ScannerName.NMAP.value: "Nmap",
    ScannerName.NUCLEI.value: "Nuclei",
    ScannerName.ZAP.value: "OWASP ZAP",
}


async def build_report_context(
    session: AsyncSession,
    assessment: Assessment,
    *,
    settings: Settings,
) -> dict[str, Any]:
    """Build the fully-materialized rendering context for one assessment.

    Reads are scoped by ``assessment.organization_id`` (this is a post-authorization read
    path, so it takes no principal), and the result is JSON-serializable throughout so it
    can be frozen onto the report row unchanged.
    """
    org_id = assessment.organization_id

    findings = await finding_service.findings_for_assessment(
        session, assessment.id, organization_id=org_id
    )
    finding_ids = [f.id for f in findings]
    enrichments = await enrichment_service.load_enrichments(session, finding_ids)
    remediations = await _remediations_by_finding(session, org_id, finding_ids)
    assets = await _assets(session, org_id, assessment.id)
    asset_by_id = {a.id: a for a in assets}
    scanner_jobs = await _scanner_jobs(session, org_id, assessment.id)

    summary = finding_service.risk_summary(findings)
    targets = await _targets(session, org_id, assessment.id)
    authorizations = await _authorizations(session, org_id, assessment.id)

    return {
        "generated_at": _now().isoformat(),
        "settings": {"public_base_url": settings.public_base_url},
        "assessment": _assessment_block(assessment),
        "scope": {
            "targets": [_target_block(t) for t in targets],
            "authorizations": [_authorization_block(a) for a in authorizations],
            "approval": await _approval_block(session, assessment),
        },
        "methodology": _methodology(scanner_jobs),
        "assets": [_asset_block(a) for a in assets],
        "asset_count": len(assets),
        "summary": summary,
        "findings": [
            _finding_block(
                f,
                enrichment=enrichments.get(f.id),
                remediations=remediations.get(f.id, []),
                asset=asset_by_id.get(f.asset_id) if f.asset_id else None,
            )
            for f in findings
        ],
        "degradations": list(assessment.degradations or []),
        "intelligence_unavailable": summary.get("intelligence_unavailable", []),
    }


# ---------------------------------------------------------------------------
# Section builders -- each returns plain, JSON-safe data
# ---------------------------------------------------------------------------


def _assessment_block(assessment: Assessment) -> dict[str, Any]:
    return {
        "id": str(assessment.id),
        "reference": assessment.reference,
        "title": assessment.title,
        "scope": assessment.scope,
        "depth": assessment.depth,
        "status": assessment.status,
        "current_stage": assessment.current_stage,
        "progress_percent": assessment.progress_percent,
        "started_at": _iso(assessment.started_at),
        "completed_at": _iso(assessment.completed_at),
        "duration_seconds": assessment.duration_seconds,
        "failure_reason": assessment.failure_reason,
        "failure_category": assessment.failure_category,
        "findings_total": assessment.findings_total,
        "assets_discovered": assessment.assets_discovered,
        "assets_in_scope": assessment.assets_in_scope,
    }


def _target_block(target: AssessmentTarget) -> dict[str, Any]:
    return {
        "raw_value": target.raw_value,
        "canonical_value": target.canonical_value,
        "target_type": target.target_type,
        "host": target.host,
        "port": target.port,
        "host_count": target.host_count,
    }


def _authorization_block(record: AuthorizationRecord) -> dict[str, Any]:
    return {
        "target": record.target,
        "confirmed": record.confirmed,
        "attestation_text": record.attestation_text,
        "method": record.method,
        "confirmed_at": _iso(record.confirmed_at),
    }


async def _approval_block(session: AsyncSession, assessment: Assessment) -> dict[str, Any] | None:
    """The granted scan-scope approval, re-read from the table.

    FR-011 is only auditable in the report if both halves survive: what the agent
    *proposed* and what the operator *authorized*. Both live in the approval row.
    """
    approval = await granted_approval(session, assessment.id)
    if approval is None:
        return None
    approved = approval.approved_payload or {}
    requested = approval.requested_payload or {}
    return {
        "decision": approval.decision,
        "risk_level": approval.risk_level,
        "prompt": approval.prompt,
        "rationale": approval.rationale,
        "resolution_note": approval.resolution_note,
        "resolved_at": _iso(approval.resolved_at),
        "requested_asset_count": len(requested.get("asset_ids", [])),
        "requested_scanners": [str(s) for s in requested.get("scanners", [])],
        "approved_asset_count": len(approved.get("asset_ids", [])),
        "approved_scanners": [str(s) for s in approved.get("scanners", [])],
    }


def _methodology(scanner_jobs: list[ScannerJob]) -> list[dict[str, Any]]:
    """One row per scanner job: the tool, its container image (its version) and outcome.

    The tool *version* is the image tag rather than a stored column -- the sandbox pins
    scanners by image, so the image is the ground truth for what actually ran.
    """
    rows: list[dict[str, Any]] = []
    for job in scanner_jobs:
        rows.append(
            {
                "scanner": job.scanner,
                "tool": _TOOL_LABELS.get(job.scanner, job.scanner),
                "image": job.image,
                "version": _version_from_image(job.image),
                "status": job.status,
                "started_at": _iso(job.started_at),
                "completed_at": _iso(job.completed_at),
                "duration_seconds": job.duration_seconds,
                "findings_imported": job.imported_finding_count,
                "exit_code": job.exit_code,
                "failure_code": job.failure_code,
                "failure_detail": job.failure_detail,
                "target_count": len(job.targets or []),
            }
        )
    return rows


def _asset_block(asset: Asset) -> dict[str, Any]:
    return {
        "id": str(asset.id),
        "name": asset.name,
        "asset_type": asset.asset_type,
        "ip_address": asset.ip_address,
        "port": asset.port,
        "protocol": asset.protocol,
        "service": asset.service,
        "technology": list(asset.technology or []),
        "internet_exposed": asset.internet_exposed,
        "http_title": asset.http_title,
        "http_status_code": asset.http_status_code,
        "criticality": asset.criticality,
        "criticality_rationale": asset.criticality_rationale,
        "selected_for_scanning": asset.selected_for_scanning,
        "endpoint": asset.endpoint,
    }


def _finding_block(
    finding: Finding,
    *,
    enrichment: Any,
    remediations: list[Remediation],
    asset: Asset | None,
) -> dict[str, Any]:
    """One finding, joined with its intelligence and remediation.

    ``intelligence`` carries the tri-state exploitation answer (FR-020): ``in_kev`` is
    ``True`` / ``False`` / ``None``, and ``unavailable`` names the providers that could
    not be reached -- "not in KEV" and "we could not ask KEV" must not look the same.
    Evidence is keyed by source id (FR-024): every intelligence claim in the report can
    be traced back to the provider that supplied it.
    """
    return {
        "id": str(finding.id),
        "title": finding.title,
        "severity": finding.severity,
        "priority": finding.priority,
        "status": finding.status,
        "scanner": finding.scanner,
        "endpoint": finding.endpoint,
        "component": finding.component,
        "component_version": finding.component_version,
        "cve_ids": list(finding.cve_ids or []),
        "cwe": finding.cwe,
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "risk_score": finding.risk_score,
        "asset_criticality": finding.asset_criticality,
        "asset": {"name": asset.name, "endpoint": asset.endpoint} if asset is not None else None,
        "analysis": {
            "explanation": finding.ai_explanation,
            "business_impact": finding.ai_business_impact,
            "attack_scenario": finding.ai_attack_scenario,
            "ai_generated": finding.ai_model is not None,
            "skipped_reason": finding.ai_skipped_reason,
        },
        "intelligence": _intelligence_block(finding, enrichment),
        "evidence": enrichment_service.enrichment_evidence(finding, enrichment),
        "remediations": [_remediation_block(r) for r in remediations],
    }


def _intelligence_block(finding: Finding, enrichment: Any) -> dict[str, Any]:
    unavailable = enrichment_service.unavailable_providers(enrichment)
    if enrichment is None:
        return {"in_kev": None, "unavailable": unavailable, "epss_score": None}
    return {
        "in_kev": enrichment.in_kev,
        "kev_date_added": _iso_date(enrichment.kev_date_added),
        "kev_due_date": _iso_date(enrichment.kev_due_date),
        "kev_ransomware_use": enrichment.kev_ransomware_use,
        "epss_score": enrichment.epss_score,
        "epss_percentile": enrichment.epss_percentile,
        "nvd_description": enrichment.nvd_description,
        "unavailable": unavailable,
    }


def _remediation_block(remediation: Remediation) -> dict[str, Any]:
    return {
        "approach": remediation.approach,
        "summary": remediation.summary,
        "steps": list(remediation.steps or []),
        "code_patch": remediation.code_patch,
        "patch_language": remediation.patch_language,
        "configuration_change": remediation.configuration_change,
        "verification": remediation.verification,
        "side_effects": remediation.side_effects,
        "effort": remediation.effort,
        "references": list(remediation.references or []),
        "ai_generated": remediation.ai_model is not None,
    }


# ---------------------------------------------------------------------------
# Loads
# ---------------------------------------------------------------------------


async def _assets(
    session: AsyncSession, org_id: uuid.UUID, assessment_id: uuid.UUID
) -> list[Asset]:
    stmt = (
        tenant_select(Asset, org_id)
        # seen_in_assessments membership, not the first-discovery assessment_id FK, so the
        # report lists every asset in scope even on a re-scan of a previously seen target.
        .where(Asset.seen_in_assessments.contains([str(assessment_id)]))
        .order_by(Asset.risk_score.desc(), Asset.name.asc())
    )
    return list((await session.execute(stmt)).scalars().all())


async def _scanner_jobs(
    session: AsyncSession, org_id: uuid.UUID, assessment_id: uuid.UUID
) -> list[ScannerJob]:
    stmt = (
        tenant_select(ScannerJob, org_id)
        .where(ScannerJob.assessment_id == assessment_id)
        .order_by(ScannerJob.created_at.asc(), ScannerJob.id.asc())
    )
    return list((await session.execute(stmt)).scalars().all())


async def _remediations_by_finding(
    session: AsyncSession, org_id: uuid.UUID, finding_ids: list[uuid.UUID]
) -> dict[uuid.UUID, list[Remediation]]:
    if not finding_ids:
        return {}
    stmt = (
        tenant_select(Remediation, org_id)
        .where(Remediation.finding_id.in_(finding_ids))
        .order_by(Remediation.finding_id, Remediation.generated_at.desc())
    )
    out: dict[uuid.UUID, list[Remediation]] = {}
    for remediation in (await session.execute(stmt)).scalars().all():
        out.setdefault(remediation.finding_id, []).append(remediation)
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _targets(
    session: AsyncSession, org_id: uuid.UUID, assessment_id: uuid.UUID
) -> list[AssessmentTarget]:
    stmt = (
        tenant_select(AssessmentTarget, org_id)
        .where(AssessmentTarget.assessment_id == assessment_id)
        .order_by(AssessmentTarget.host.asc(), AssessmentTarget.id.asc())
    )
    return list((await session.execute(stmt)).scalars().all())


async def _authorizations(
    session: AsyncSession, org_id: uuid.UUID, assessment_id: uuid.UUID
) -> list[AuthorizationRecord]:
    stmt = (
        tenant_select(AuthorizationRecord, org_id)
        .where(AuthorizationRecord.assessment_id == assessment_id)
        .order_by(AuthorizationRecord.target.asc(), AuthorizationRecord.id.asc())
    )
    return list((await session.execute(stmt)).scalars().all())


def _version_from_image(image: str | None) -> str | None:
    if not image or ":" not in image:
        return None
    return image.rsplit(":", 1)[-1] or None


def _iso(value: dt.datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _iso_date(value: dt.date | None) -> str | None:
    return value.isoformat() if value is not None else None


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = ["build_report_context"]
