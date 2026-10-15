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
from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.logging_conf import redact_text
from app.db.enums import ScannerName
from app.db.models.assessment import Assessment, AssessmentTarget, AuthorizationRecord
from app.db.models.asset import Asset
from app.db.models.canonical import (
    AssessmentCanonicalFinding,
    CanonicalFinding,
    FindingHistory,
    FindingObservation,
)
from app.db.models.compliance import ComplianceControl, ComplianceFindingMapping
from app.db.models.finding import Finding, Remediation
from app.db.models.report import Report
from app.db.models.scanner import ScannerJob
from app.db.queries import pg_any
from app.db.repository import tenant_select
from app.services import enrichment as enrichment_service
from app.services import finding as finding_service
from app.services.approval import granted_approval
from app.services.canonical_metrics import RESOLVED_STATUSES, remediation_timestamp

log = structlog.get_logger(__name__)

#: Human-readable tool identity per scanner, so the methodology section names the tool a
#: reader recognises rather than the enum value. The version is read from the job's image
#: tag at render time -- there is no static version to hardcode.
_TOOL_LABELS: dict[str, str] = {
    ScannerName.NMAP.value: "Nmap",
    ScannerName.NUCLEI.value: "Nuclei",
    ScannerName.ZAP.value: "OWASP ZAP",
    ScannerName.PROWLER_AWS.value: "Prowler AWS",
}
_PROWLER_EVIDENCE_FIELDS = {
    "rule_id": 200,
    "account_uid": 128,
    "cloud_provider": 16,
    "region": 64,
    "asset_value": 2000,
}


def _safe_prowler_evidence(value: dict[str, Any] | None) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {
        key: item
        for key, limit in _PROWLER_EVIDENCE_FIELDS.items()
        if isinstance((item := value.get(key)), str)
        and len(item) <= limit
        and redact_text(item) == item
    }


def reportable_native_findings(findings: list[Finding]) -> list[Finding]:
    """Use the same native inclusion rule as cached assessment counters."""
    return [
        finding
        for finding in findings
        if not finding.is_duplicate and not finding.is_false_positive
    ]


async def linked_canonical_findings_for_assessment(
    session: AsyncSession,
    organization_id: uuid.UUID,
    assessment_id: uuid.UUID,
    *,
    native_finding_ids: list[uuid.UUID],
) -> list[tuple[CanonicalFinding, Asset, bool, dict[str, Any] | None]]:
    """Fetch this assessment's canonical findings and detect native duplicates."""
    represented_by_native = exists(
        select(FindingObservation.id).where(
            FindingObservation.organization_id == organization_id,
            FindingObservation.canonical_finding_id == CanonicalFinding.id,
            FindingObservation.provider == "defectdojo",
            FindingObservation.source_record_id.in_(native_finding_ids),
        )
    )
    prowler_evidence = (
        select(FindingObservation.evidence)
        .where(
            FindingObservation.organization_id == organization_id,
            FindingObservation.canonical_finding_id == CanonicalFinding.id,
            FindingObservation.provider == "prowler",
        )
        .order_by(FindingObservation.last_seen_at.desc())
        .limit(1)
        .correlate(CanonicalFinding)
        .scalar_subquery()
    )
    statement = (
        select(CanonicalFinding, Asset, represented_by_native, prowler_evidence)
        .join(
            AssessmentCanonicalFinding,
            AssessmentCanonicalFinding.canonical_finding_id == CanonicalFinding.id,
        )
        .join(Asset, Asset.id == CanonicalFinding.asset_id)
        .where(
            AssessmentCanonicalFinding.organization_id == organization_id,
            AssessmentCanonicalFinding.assessment_id == assessment_id,
            CanonicalFinding.organization_id == organization_id,
            Asset.organization_id == organization_id,
        )
        .order_by(CanonicalFinding.risk_score.desc(), CanonicalFinding.id)
    )
    return list((await session.execute(statement)).all())


def merge_linked_canonical_findings(
    native_summary: dict[str, Any],
    native_blocks: list[dict[str, Any]],
    linked: list[tuple[CanonicalFinding, Asset, bool, dict[str, Any] | None]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Append linked cloud findings, excluding canonical identities already in native rows."""
    summary = dict(native_summary)
    summary["by_severity"] = dict(native_summary["by_severity"])
    summary["by_priority"] = dict(native_summary["by_priority"])
    unavailable = set(native_summary.get("intelligence_unavailable") or [])
    blocks = list(native_blocks)
    for finding, asset, represented_by_native, source_evidence in linked:
        if represented_by_native or finding.status == "false_positive":
            continue
        factors = finding.risk_factors if isinstance(finding.risk_factors, dict) else {}
        raw_inputs = factors.get("inputs")
        inputs = raw_inputs if isinstance(raw_inputs, dict) else {}
        missing = [item for item in factors.get("unavailable") or [] if isinstance(item, str)]
        unavailable.update(missing)
        intel = inputs.get("in_kev")
        priority = finding_service.priority_for_score(
            finding.risk_score,
            exploited=intel is True,
            internet_exposed=inputs.get("internet_exposed") is True,
            excluded=finding.status in {"false_positive", "accepted_risk", "closed"},
        ).value
        blocks.append(
            {
                "id": str(finding.id),
                "title": finding.title,
                "severity": finding.severity,
                "priority": priority,
                "status": finding.status,
                "scanner": ScannerName.PROWLER_AWS.value,
                "endpoint": asset.endpoint,
                "component": None,
                "component_version": None,
                "cve_ids": list(finding.cve_ids or []),
                "cwe": None,
                "cvss_score": inputs.get("cvss_score"),
                "cvss_vector": None,
                "risk_score": finding.risk_score,
                "asset_criticality": asset.criticality,
                "asset": {"name": asset.name, "endpoint": asset.endpoint},
                "analysis": {
                    "explanation": None,
                    "business_impact": None,
                    "attack_scenario": None,
                    "adversary_profile": None,
                    "mitre_tactics": [],
                    "detection_hint": None,
                    "ai_generated": False,
                    "skipped_reason": None,
                },
                "intelligence": {
                    "in_kev": intel,
                    "epss_score": inputs.get("epss_score"),
                    "unavailable": missing,
                },
                "evidence": {
                    "prowler": {
                        "provider": "prowler",
                        **_safe_prowler_evidence(source_evidence),
                    }
                },
                "remediations": [],
                "ssvc": None,
            }
        )
        summary["total"] += 1
        severity = finding.severity
        summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
        summary["by_priority"][priority] = summary["by_priority"].get(priority, 0) + 1
        if intel is True:
            summary["in_kev"] += 1
        elif intel is None:
            summary["kev_undetermined"] += 1
    summary["intelligence_unavailable"] = sorted(unavailable)
    return summary, blocks


def merge_linked_assets(
    native_assets: list[Asset],
    linked: list[tuple[CanonicalFinding, Asset, bool, dict[str, Any] | None]],
) -> list[Asset]:
    """Include scanner-discovered cloud resources in the assessment inventory."""
    by_id = {asset.id: asset for asset in native_assets}
    for _, asset, _, _ in linked:
        by_id.setdefault(asset.id, asset)
    return list(by_id.values())


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

    findings = reportable_native_findings(
        await finding_service.findings_for_assessment(
            session,
            assessment.id,
            organization_id=org_id,
        )
    )
    finding_ids = [f.id for f in findings]
    enrichments = await enrichment_service.load_enrichments(session, finding_ids)
    remediations = await _remediations_by_finding(session, org_id, finding_ids)
    assets = await _assets(session, org_id, assessment.id)
    asset_by_id = {a.id: a for a in assets}
    scanner_jobs = await _scanner_jobs(session, org_id, assessment.id)

    summary = finding_service.risk_summary(findings)
    native_blocks = [
        _finding_block(
            f,
            enrichment=enrichments.get(f.id),
            remediations=remediations.get(f.id, []),
            asset=asset_by_id.get(f.asset_id) if f.asset_id else None,
        )
        for f in findings
    ]
    linked = await linked_canonical_findings_for_assessment(
        session,
        org_id,
        assessment.id,
        native_finding_ids=finding_ids,
    )
    assets = merge_linked_assets(assets, linked)
    summary, report_findings = merge_linked_canonical_findings(
        summary,
        native_blocks,
        linked,
    )
    compliance = await _assessment_compliance_summary(
        session,
        organization_id=org_id,
        canonical_finding_ids=[finding.id for finding, _, _, _ in linked],
    )
    operational_metrics = await _operational_metrics(
        session,
        assessment=assessment,
        report_findings=report_findings,
    )
    targets = await _targets(session, org_id, assessment.id)
    authorizations = await _authorizations(session, org_id, assessment.id)

    assessment_block = _assessment_block(assessment)
    assessment_block["findings_total"] = summary["total"]
    return {
        "generated_at": _now().isoformat(),
        "settings": {"public_base_url": settings.public_base_url},
        "assessment": assessment_block,
        "scope": {
            "targets": [_target_block(t) for t in targets],
            "authorizations": [_authorization_block(a) for a in authorizations],
            "approval": await _approval_block(session, assessment),
        },
        "methodology": _methodology(scanner_jobs),
        "assets": [_asset_block(a) for a in assets],
        "asset_count": len(assets),
        "summary": summary,
        "findings": report_findings,
        "degradations": list(assessment.degradations or []),
        "intelligence_unavailable": summary.get("intelligence_unavailable", []),
        # New intelligence layers
        "attack_paths": _attack_paths_block(assessment),
        "compound_risks": _compound_risks_block(assessment),
        "coverage_gaps": _coverage_gaps_block(assessment),
        "compliance": compliance,
        "operational_metrics": operational_metrics,
    }


# ---------------------------------------------------------------------------
# Section builders -- each returns plain, JSON-safe data
# ---------------------------------------------------------------------------


async def _assessment_compliance_summary(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    canonical_finding_ids: list[uuid.UUID],
) -> dict[str, Any]:
    """Summarize only controls evidenced by this assessment's canonical findings."""
    if not canonical_finding_ids:
        return {"mapped_controls": 0, "at_risk_controls": 0, "frameworks": []}
    rows = (
        await session.execute(
            select(
                ComplianceControl.framework,
                ComplianceControl.control_id,
                ComplianceControl.title,
                CanonicalFinding.status,
                CanonicalFinding.risk_score,
            )
            .join(
                ComplianceFindingMapping,
                ComplianceFindingMapping.control_id == ComplianceControl.id,
            )
            .join(
                CanonicalFinding,
                CanonicalFinding.id == ComplianceFindingMapping.canonical_finding_id,
            )
            .where(
                ComplianceControl.organization_id == organization_id,
                ComplianceFindingMapping.organization_id == organization_id,
                CanonicalFinding.organization_id == organization_id,
                ComplianceFindingMapping.canonical_finding_id.in_(canonical_finding_ids),
            )
        )
    ).all()
    controls: dict[tuple[str, str], dict[str, Any]] = {}
    for framework, control_id, title, finding_status, risk_score in rows:
        key = (framework, control_id)
        control = controls.setdefault(
            key,
            {
                "framework": framework,
                "control_id": control_id,
                "title": title,
                "active_finding_count": 0,
                "highest_risk_score": None,
            },
        )
        if finding_status not in {"closed", "mitigated", "false_positive"}:
            control["active_finding_count"] += 1
            risk = float(risk_score)
            previous = control["highest_risk_score"]
            control["highest_risk_score"] = risk if previous is None else max(previous, risk)
    by_framework: dict[str, list[dict[str, Any]]] = {}
    for control in controls.values():
        control["effective_status"] = (
            "at_risk"
            if (control["highest_risk_score"] or 0) >= 70
            else "partially_satisfied"
            if control["active_finding_count"]
            else "satisfied"
        )
        by_framework.setdefault(control["framework"], []).append(control)
    frameworks = [
        {
            "framework": framework,
            "mapped_control_count": len(items),
            "at_risk_control_count": sum(item["effective_status"] == "at_risk" for item in items),
            "controls": sorted(items, key=lambda item: (item["control_id"], item["title"])),
        }
        for framework, items in sorted(by_framework.items())
    ]
    return {
        "mapped_controls": len(controls),
        "at_risk_controls": sum(
            control["effective_status"] == "at_risk" for control in controls.values()
        ),
        "frameworks": frameworks,
    }


async def _operational_metrics(
    session: AsyncSession,
    *,
    assessment: Assessment,
    report_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build board-ready remediation metrics scoped to the assessment's canonical set."""
    organization_id = assessment.organization_id
    finding_ids = list(
        (
            await session.scalars(
                select(AssessmentCanonicalFinding.canonical_finding_id).where(
                    AssessmentCanonicalFinding.organization_id == organization_id,
                    AssessmentCanonicalFinding.assessment_id == assessment.id,
                )
            )
        ).all()
    )
    scores = [
        float(item["risk_score"])
        for item in report_findings
        if isinstance(item.get("risk_score"), int | float)
    ]
    exposure_score = round(sum(scores) / len(scores), 2) if scores else 0.0
    prior_report = (
        await session.execute(
            tenant_select(Report, organization_id)
            .where(Report.assessment_id == assessment.id, Report.status == "ready")
            .order_by(Report.generated_at.desc().nullslast(), Report.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    prior_metrics = (
        (prior_report.content_digest or {}).get("operational_metrics", {})
        if prior_report is not None
        else {}
    )
    prior_exposure = prior_metrics.get("exposure_score")
    prior_exposure_score = (
        float(prior_exposure) if isinstance(prior_exposure, int | float) else None
    )
    baseline = assessment.started_at or assessment.created_at
    if not finding_ids:
        return {
            "exposure_score": exposure_score,
            "previous_exposure_score": prior_exposure_score,
            "exposure_delta": (
                round(exposure_score - prior_exposure_score, 2)
                if prior_exposure_score is not None
                else None
            ),
            "new_findings": 0,
            "resolved_findings": 0,
            "mean_time_to_remediate_days": None,
            "sla": {"tracked": 0, "within_sla": 0, "overdue": 0, "compliance_percent": None},
        }
    histories = (
        await session.execute(
            select(
                func.count(func.distinct(FindingHistory.canonical_finding_id)).filter(
                    FindingHistory.previous_status.is_(None)
                ),
                func.count(func.distinct(FindingHistory.canonical_finding_id)).filter(
                    FindingHistory.new_status.in_(RESOLVED_STATUSES),
                    FindingHistory.previous_status.is_distinct_from(FindingHistory.new_status),
                ),
            ).where(
                FindingHistory.organization_id == organization_id,
                pg_any(FindingHistory.canonical_finding_id, finding_ids),
                FindingHistory.occurred_at >= baseline,
            )
        )
    ).one()
    now = _now()
    resolved_at = remediation_timestamp()
    resolved = CanonicalFinding.status.in_(RESOLVED_STATUSES)
    active = CanonicalFinding.status.in_(("new", "open", "reopened"))
    sla = (
        await session.execute(
            select(
                func.count(),
                func.count().filter(
                    (active & (CanonicalFinding.due_at > now))
                    | (resolved & (resolved_at <= CanonicalFinding.due_at))
                ),
                func.count().filter(
                    (active & (CanonicalFinding.due_at <= now))
                    | (resolved & (resolved_at > CanonicalFinding.due_at))
                ),
            ).where(
                CanonicalFinding.organization_id == organization_id,
                pg_any(CanonicalFinding.id, finding_ids),
                CanonicalFinding.due_at.is_not(None),
                CanonicalFinding.status.not_in(("false_positive", "accepted_risk")),
            )
        )
    ).one()
    remediation_seconds = await session.scalar(
        select(
            func.avg(
                func.greatest(
                    0, func.extract("epoch", resolved_at - CanonicalFinding.first_seen_at)
                )
            )
        ).where(
            CanonicalFinding.organization_id == organization_id,
            pg_any(CanonicalFinding.id, finding_ids),
            resolved,
            resolved_at.is_not(None),
            CanonicalFinding.first_seen_at.is_not(None),
        )
    )
    tracked, within_sla, overdue = (int(value or 0) for value in sla)
    mttr = (
        round(max(0.0, float(remediation_seconds)) / 86_400.0, 2)
        if remediation_seconds is not None
        else None
    )
    return {
        "exposure_score": exposure_score,
        "previous_exposure_score": prior_exposure_score,
        "exposure_delta": (
            round(exposure_score - prior_exposure_score, 2)
            if prior_exposure_score is not None
            else None
        ),
        "new_findings": int(histories[0] or 0),
        "resolved_findings": int(histories[1] or 0),
        "mean_time_to_remediate_days": mttr,
        "sla": {
            "tracked": tracked,
            "within_sla": within_sla,
            "overdue": overdue,
            "compliance_percent": round((within_sla / tracked) * 100, 2) if tracked else None,
        },
    }


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
            "adversary_profile": getattr(finding, "ai_adversary_profile", None),
            "mitre_tactics": list(getattr(finding, "ai_mitre_tactics", None) or []),
            "detection_hint": getattr(finding, "ai_detection_hint", None),
            "ai_generated": finding.ai_model is not None,
            "skipped_reason": finding.ai_skipped_reason,
        },
        "intelligence": _intelligence_block(finding, enrichment),
        "evidence": enrichment_service.enrichment_evidence(finding, enrichment),
        "remediations": [_remediation_block(r) for r in remediations],
        "ssvc": _ssvc_block(finding),
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


def _ssvc_block(finding: Finding) -> dict[str, Any] | None:
    """Extract SSVC triage result stored in risk_factors by the attack_path node."""
    factors = finding.risk_factors or {}
    ssvc = factors.get("ssvc")
    if not ssvc:
        return None
    return {
        "outcome": ssvc.get("outcome"),
        "exploitation": ssvc.get("exploitation"),
        "automatable": ssvc.get("automatable"),
        "technical_impact": ssvc.get("technical_impact"),
        "mission_prevalence": ssvc.get("mission_prevalence"),
    }


def _attack_paths_block(assessment: Assessment) -> list[dict[str, Any]]:
    """Attack paths generated by the attack_path node, stored in assessment.extra_data."""
    meta = assessment.extra_data or {}
    return list(meta.get("attack_paths") or [])


def _compound_risks_block(assessment: Assessment) -> list[dict[str, Any]]:
    """Compound risks detected by the correlation service."""
    meta = assessment.extra_data or {}
    return list(meta.get("compound_risks") or [])


def _coverage_gaps_block(assessment: Assessment) -> list[str]:
    """Coverage gaps identified by the correlation service."""
    meta = assessment.extra_data or {}
    return list(meta.get("coverage_gaps") or [])


def _iso(value: dt.datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _iso_date(value: dt.date | None) -> str | None:
    return value.isoformat() if value is not None else None


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


__all__ = ["build_report_context"]
