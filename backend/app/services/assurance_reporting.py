"""Seeded quantitative risk and signed OSCAL evidence projections."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import math
import random
import statistics
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from app.core.errors import ConflictError, ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.assurance import (
    AgentEvaluationRun,
    AgentEvaluationSuite,
    AgentRunAssurance,
    AIInteractionReceipt,
    AIToolManifest,
    ComplianceExportPackage,
    DataSecurityAssessment,
    EnforcementTransaction,
    RiskSimulationTrial,
    ThreatResponseAction,
    ValidationRecipe,
)
from app.db.models.compliance import (
    ComplianceAuditWorkspace,
    ComplianceControl,
    ComplianceEvidenceItem,
)
from app.db.models.control_plane import SecurityRiskSimulation
from app.db.repository import tenant_select
from app.services.context import Principal

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.schemas.assurance import MonteCarloSimulationCreateIn, OSCALExportCreateIn

OSCAL_VERSION = "1.1.2"


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _range(value: Sequence[float | int], label: str, *, unit_interval: bool = False) -> tuple[float, float, float]:
    if len(value) != 3:
        raise ValueError(f"{label} requires minimum, likely, and maximum")
    low, likely, high = (float(item) for item in value)
    if not all(math.isfinite(item) for item in (low, likely, high)):
        raise ValueError(f"{label} values must be finite")
    if low < 0 or not low <= likely <= high:
        raise ValueError(f"{label} range must be non-negative and ordered")
    if unit_interval and high > 1:
        raise ValueError(f"{label} range must be within 0 and 1")
    return low, likely, high


def _percentile(sorted_values: Sequence[float], probability: float) -> float:
    if not sorted_values:
        return 0.0
    position = (len(sorted_values) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    fraction = position - lower
    return sorted_values[lower] * (1 - fraction) + sorted_values[upper] * fraction


@dataclass(frozen=True, slots=True)
class RiskTrial:
    iterations: int
    seed: int
    assumptions_version: int
    distributions: dict[str, tuple[float, float, float]]
    percentile_05: float
    percentile_50: float
    percentile_95: float
    mean_annual_loss: float
    standard_deviation: float
    confidence_level: float = 0.95


def run_monte_carlo(
    *,
    iterations: int,
    seed: int,
    frequency: Sequence[float | int],
    primary_loss: Sequence[float | int],
    secondary_loss: Sequence[float | int],
    control_effectiveness: Sequence[float | int],
    assumptions_version: int,
) -> RiskTrial:
    """Model event occurrence and loss magnitude with reproducible triangular inputs."""

    if not 1_000 <= iterations <= 1_000_000:
        raise ValueError("iterations must be between 1000 and 1000000")
    if assumptions_version < 1:
        raise ValueError("assumptions version must be positive")
    distributions = {
        "frequency": _range(frequency, "frequency", unit_interval=True),
        "primary_loss": _range(primary_loss, "primary_loss"),
        "secondary_loss": _range(secondary_loss, "secondary_loss"),
        "control_effectiveness": _range(
            control_effectiveness, "control_effectiveness", unit_interval=True
        ),
    }
    rng = random.Random(seed)
    losses: list[float] = []
    for _ in range(iterations):
        annual_frequency = rng.triangular(*distributions["frequency"])
        occurred = rng.random() < annual_frequency
        if not occurred:
            losses.append(0.0)
            continue
        primary = rng.triangular(*distributions["primary_loss"])
        secondary = rng.triangular(*distributions["secondary_loss"])
        effectiveness = rng.triangular(*distributions["control_effectiveness"])
        losses.append(max(0.0, (primary + secondary) * (1 - effectiveness)))
    losses.sort()
    return RiskTrial(
        iterations=iterations,
        seed=seed,
        assumptions_version=assumptions_version,
        distributions=distributions,
        percentile_05=round(_percentile(losses, 0.05), 2),
        percentile_50=round(_percentile(losses, 0.50), 2),
        percentile_95=round(_percentile(losses, 0.95), 2),
        mean_annual_loss=round(statistics.fmean(losses), 2),
        standard_deviation=round(statistics.pstdev(losses), 2),
    )


def compare_risk_scenarios(
    *, before: Mapping[str, Any], after: Mapping[str, Any]
) -> dict[str, Any]:
    """Use common random numbers so the before/after delta is defensible."""

    before_seed = int(before["seed"])
    after_seed = int(after.get("seed", before_seed))
    if before_seed != after_seed:
        raise ValueError("risk comparisons must reuse the same seed")
    before_trial = run_monte_carlo(**before)
    after_trial = run_monte_carlo(**after)
    reduction = before_trial.mean_annual_loss - after_trial.mean_annual_loss
    percentage = reduction / before_trial.mean_annual_loss * 100 if before_trial.mean_annual_loss else 0
    return {
        "seed": before_seed,
        "before": before_trial,
        "after": after_trial,
        "risk_reduction": round(reduction, 2),
        "risk_reduction_percentage": round(percentage, 2),
    }


def calibrate_risk_model(history: Iterable[Mapping[str, float | int]]) -> dict[str, Any]:
    rows = list(history)
    if not rows:
        raise ValueError("calibration requires historical observations")
    covered = 0
    absolute_errors: list[float] = []
    for row in rows:
        p05, p50, p95, actual = (float(row[key]) for key in ("p05", "p50", "p95", "actual"))
        if not 0 <= p05 <= p50 <= p95 or actual < 0:
            raise ValueError("calibration rows contain invalid intervals")
        covered += int(p05 <= actual <= p95)
        absolute_errors.append(abs(p50 - actual))
    return {
        "sample_size": len(rows),
        "interval_coverage": round(covered / len(rows), 4),
        "median_absolute_error": round(statistics.median(absolute_errors), 2),
        "mean_absolute_error": round(statistics.fmean(absolute_errors), 2),
    }


def resolve_control_inheritance(
    relationships: Iterable[Mapping[str, Any]], control_id: str
) -> dict[str, Any]:
    parent_by_child: dict[str, tuple[str, float]] = {}
    for relationship in relationships:
        child = str(relationship["control_id"])
        parent = str(relationship["parent_control_id"])
        percentage = float(relationship.get("percentage", 100))
        if not 0 <= percentage <= 100:
            raise ValueError("inheritance percentage must be between 0 and 100")
        if child in parent_by_child:
            raise ValueError("a control can have only one effective inheritance parent")
        parent_by_child[child] = (parent, percentage)
    path = [control_id]
    effective = 100.0
    seen = {control_id}
    current = control_id
    while current in parent_by_child:
        parent, percentage = parent_by_child[current]
        if parent in seen:
            raise ValueError("control inheritance cycle detected")
        effective *= percentage / 100
        path.append(parent)
        seen.add(parent)
        current = parent
    return {"path": path, "effective_inherited_percentage": round(effective, 2)}


def _moment(value: Any) -> dt.datetime:
    if isinstance(value, dt.datetime):
        moment = value
    else:
        moment = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return moment if moment.tzinfo else moment.replace(tzinfo=dt.UTC)


def _oscal_uuid(namespace: str, value: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"urn:cynux:{namespace}:{value}"))


def _assessment_results(
    *,
    package_key: str,
    workspace_id: str,
    controls: list[Mapping[str, Any]],
    evidence: list[Mapping[str, Any]],
    findings: list[Mapping[str, Any]],
    generated_at: dt.datetime,
) -> dict[str, Any]:
    observations = [
        {
            "uuid": _oscal_uuid("evidence", str(item["id"])),
            "title": f"Evidence {item['id']}",
            "description": "Automated evidence projection",
            "methods": ["EXAMINE"],
            "collected": _moment(item["captured_at"]).isoformat(),
            "relevant-evidence": [
                {
                    "href": str(item["artifact_ref"]),
                    "description": "Immutable evidence artifact",
                }
            ],
            "props": [
                {"name": "control-id", "value": str(item["control_id"])},
                *[
                    {"name": "asset-ref", "value": str(ref)}
                    for ref in item.get("asset_refs", [])
                ],
                *[
                    {"name": "finding-ref", "value": str(ref)}
                    for ref in item.get("finding_refs", [])
                ],
            ],
        }
        for item in evidence
    ]
    oscal_findings = [
        {
            "uuid": _oscal_uuid("finding", str(item["id"])),
            "title": str(item.get("title", item["id"])),
            "description": "Cynux finding projection",
            "target": {
                "type": "objective-id",
                "target-id": str(item.get("control_id", "platform-control")),
                "status": {"state": "not-satisfied" if item.get("status") != "closed" else "satisfied"},
            },
            "props": [{"name": "finding-ref", "value": str(item["id"])}],
        }
        for item in findings
    ]
    return {
        "assessment-results": {
            "uuid": _oscal_uuid("package", package_key),
            "metadata": {
                "title": f"Cynux automated assessment {package_key}",
                "last-modified": generated_at.isoformat(),
                "version": "1",
                "oscal-version": OSCAL_VERSION,
            },
            "results": [
                {
                    "uuid": _oscal_uuid("result", workspace_id),
                    "title": "Automated assurance result",
                    "description": "Evidence-backed control assessment generated by Cynux",
                    "start": generated_at.isoformat(),
                    "end": generated_at.isoformat(),
                    "reviewed-controls": {
                        "control-selections": [
                            {"include-controls": [{"control-id": str(item["id"])} for item in controls]}
                        ]
                    },
                    "observations": observations,
                    "findings": oscal_findings,
                }
            ],
        }
    }


def _poam(
    *, package_key: str, findings: list[Mapping[str, Any]], generated_at: dt.datetime
) -> dict[str, Any]:
    return {
        "plan-of-action-and-milestones": {
            "uuid": _oscal_uuid("package", package_key),
            "metadata": {
                "title": f"Cynux POA&M {package_key}",
                "last-modified": generated_at.isoformat(),
                "version": "1",
                "oscal-version": OSCAL_VERSION,
            },
            "poam-items": [
                {
                    "uuid": _oscal_uuid("poam", str(item["id"])),
                    "title": str(item.get("title", item["id"])),
                    "description": "Cynux remediation item",
                    "props": [
                        {"name": "finding-ref", "value": str(item["id"])},
                        {"name": "status", "value": str(item.get("status", "open"))},
                    ],
                }
                for item in findings
            ],
        }
    }


def build_oscal_package(
    *,
    model: str,
    package_key: str,
    workspace_id: str,
    controls: list[Mapping[str, Any]],
    evidence: list[Mapping[str, Any]],
    findings: list[Mapping[str, Any]],
    signing_secret: bytes,
    signing_key_id: str,
    generated_at: dt.datetime | None = None,
) -> dict[str, Any]:
    if model not in {"assessment-results", "poam"}:
        raise ValueError("supported OSCAL exports are assessment-results and poam")
    if len(signing_secret) < 32:
        raise ValueError("OSCAL signing secret must contain at least 32 bytes")
    generated = generated_at or dt.datetime.now(dt.UTC)
    fresh: list[Mapping[str, Any]] = []
    stale: list[Mapping[str, Any]] = []
    for item in evidence:
        captured = _moment(item["captured_at"])
        deadline = captured + dt.timedelta(days=int(item.get("freshness_days", 90)))
        (fresh if generated <= deadline else stale).append(item)
    document = (
        _assessment_results(
            package_key=package_key,
            workspace_id=workspace_id,
            controls=controls,
            evidence=fresh,
            findings=findings,
            generated_at=generated,
        )
        if model == "assessment-results"
        else _poam(package_key=package_key, findings=findings, generated_at=generated)
    )
    digest = canonical_digest(document)
    signature = hmac.new(signing_secret, canonical_json(document), hashlib.sha256).hexdigest()
    return {
        "oscal-version": OSCAL_VERSION,
        "model": model,
        "package-key": package_key,
        "workspace-id": workspace_id,
        "generated-at": generated.isoformat(),
        "content-digest": digest,
        "signature": signature,
        "signing-key-id": signing_key_id,
        "manifest": {
            "included_evidence_ids": sorted(str(item["id"]) for item in fresh),
            "stale_evidence_ids": sorted(str(item["id"]) for item in stale),
            "control_ids": sorted(str(item["id"]) for item in controls),
            "finding_ids": sorted(str(item["id"]) for item in findings),
        },
        "document": document,
    }


def verify_oscal_package(package: Mapping[str, Any], signing_secret: bytes) -> bool:
    document = package.get("document")
    if not isinstance(document, dict):
        return False
    expected_digest = canonical_digest(document)
    expected_signature = hmac.new(signing_secret, canonical_json(document), hashlib.sha256).hexdigest()
    return hmac.compare_digest(str(package.get("content-digest", "")), expected_digest) and hmac.compare_digest(
        str(package.get("signature", "")), expected_signature
    )


async def run_persisted_risk_trial(
    session: AsyncSession, principal: Principal, payload: MonteCarloSimulationCreateIn
) -> RiskSimulationTrial:
    principal.require(Permission.ORG_READ)
    simulation = await session.scalar(
        tenant_select(SecurityRiskSimulation, principal.organization_id).where(
            SecurityRiskSimulation.id == payload.simulation_id
        )
    )
    if simulation is None:
        raise ResourceNotFoundError("Risk simulation not found")
    if payload.comparison_trial_id is not None:
        comparison = await session.scalar(
            tenant_select(RiskSimulationTrial, principal.organization_id).where(
                RiskSimulationTrial.id == payload.comparison_trial_id
            )
        )
        if comparison is None:
            raise ResourceNotFoundError("Comparison risk trial not found")
        if comparison.seed != payload.seed:
            raise ConflictError("Risk comparison must reuse the original seed")
    material = payload.model_dump(mode="json")
    run_key = canonical_digest(material)
    existing = await session.scalar(
        tenant_select(RiskSimulationTrial, principal.organization_id).where(
            RiskSimulationTrial.run_key == run_key
        )
    )
    if existing is not None:
        return existing
    trial = run_monte_carlo(
        iterations=payload.iterations,
        seed=payload.seed,
        frequency=(payload.frequency_min, payload.frequency_likely, payload.frequency_max),
        primary_loss=(
            payload.primary_loss_min,
            payload.primary_loss_likely,
            payload.primary_loss_max,
        ),
        secondary_loss=(
            payload.secondary_loss_min,
            payload.secondary_loss_likely,
            payload.secondary_loss_max,
        ),
        control_effectiveness=(
            payload.control_effectiveness_min,
            payload.control_effectiveness_likely,
            payload.control_effectiveness_max,
        ),
        assumptions_version=payload.assumptions_version,
    )
    row = RiskSimulationTrial(
        organization_id=principal.organization_id,
        simulation_id=payload.simulation_id,
        comparison_trial_id=payload.comparison_trial_id,
        run_key=run_key,
        status="completed",
        iterations=trial.iterations,
        seed=trial.seed,
        assumptions_version=trial.assumptions_version,
        distributions={key: list(value) for key, value in trial.distributions.items()},
        percentile_05=Decimal(str(trial.percentile_05)),
        percentile_50=Decimal(str(trial.percentile_50)),
        percentile_95=Decimal(str(trial.percentile_95)),
        mean_annual_loss=Decimal(str(trial.mean_annual_loss)),
        standard_deviation=Decimal(str(trial.standard_deviation)),
        confidence_level=Decimal("0.95"),
        calibration=payload.calibration,
        completed_at=dt.datetime.now(dt.UTC),
    )
    session.add(row)
    await session.flush()
    return row


async def export_workspace_oscal(
    session: AsyncSession,
    principal: Principal,
    payload: OSCALExportCreateIn,
    *,
    signing_secret: bytes,
    signing_key_id: str,
) -> tuple[ComplianceExportPackage, dict[str, Any]]:
    principal.require(Permission.ORG_READ)
    if payload.oscal_version != OSCAL_VERSION:
        raise ConflictError(f"Only OSCAL {OSCAL_VERSION} is supported")
    workspace = await session.scalar(
        tenant_select(ComplianceAuditWorkspace, principal.organization_id).where(
            ComplianceAuditWorkspace.id == payload.workspace_id
        )
    )
    if workspace is None:
        raise ResourceNotFoundError("Compliance workspace not found")
    existing = await session.scalar(
        tenant_select(ComplianceExportPackage, principal.organization_id).where(
            ComplianceExportPackage.package_key == payload.package_key
        )
    )
    if existing is not None:
        raise ConflictError("OSCAL package keys are immutable and must be unique")
    control_ids = []
    for value in workspace.control_ids:
        try:
            control_ids.append(uuid.UUID(str(value)))
        except ValueError:
            continue
    control_rows = await session.scalars(
        tenant_select(ComplianceControl, principal.organization_id).where(
            ComplianceControl.id.in_(control_ids)
        )
    )
    controls = list(control_rows.all())
    evidence_rows = await session.scalars(
        tenant_select(ComplianceEvidenceItem, principal.organization_id).where(
            ComplianceEvidenceItem.control_id.in_([row.id for row in controls]),
            ComplianceEvidenceItem.collection_status.in_(["collected", "verified"]),
        )
    )
    evidence = []
    for item in evidence_rows.all():
        if item.collected_at is None:
            continue
        freshness_days = (
            max(1, (item.valid_until - item.collected_at).days)
            if item.valid_until
            else 90
        )
        metadata = item.metadata_ or {}
        evidence.append(
            {
                "id": str(item.id),
                "control_id": str(item.control_id),
                "captured_at": item.collected_at,
                "freshness_days": freshness_days,
                "artifact_ref": item.source_reference,
                "asset_refs": list(metadata.get("asset_refs") or []),
                "finding_refs": list(metadata.get("finding_refs") or []),
            }
        )
    package = build_oscal_package(
        model=payload.model,
        package_key=payload.package_key,
        workspace_id=str(payload.workspace_id),
        controls=[
            {
                "id": row.control_id,
                "title": row.title,
                "status": row.assessment_status,
            }
            for row in controls
        ],
        evidence=evidence,
        findings=[],
        signing_secret=signing_secret,
        signing_key_id=signing_key_id,
    )
    row = ComplianceExportPackage(
        organization_id=principal.organization_id,
        workspace_id=payload.workspace_id,
        package_key=payload.package_key,
        oscal_model=payload.model,
        oscal_version=payload.oscal_version,
        status="generated",
        artifact_reference=None,
        content_digest=package["content-digest"],
        signature=package["signature"],
        signing_key_id=signing_key_id,
        manifest=package["manifest"],
        generated_at=_moment(package["generated-at"]),
    )
    session.add(row)
    await session.flush()
    return row, package


async def assurance_summary(
    session: AsyncSession, principal: Principal, *, limit: int = 50
) -> dict[str, Any]:
    """Return privacy-safe recent projections for the operator workspace."""

    principal.require(Permission.ORG_READ)
    limit = max(1, min(limit, 200))

    async def recent(model: Any) -> list[Any]:
        rows = await session.scalars(
            tenant_select(model, principal.organization_id).order_by(model.created_at.desc()).limit(limit)
        )
        return list(rows.all())

    transactions = await recent(EnforcementTransaction)
    receipts = await recent(AIInteractionReceipt)
    manifests = await recent(AIToolManifest)
    agents = await recent(AgentRunAssurance)
    evaluation_suites = await recent(AgentEvaluationSuite)
    evaluation_runs = await recent(AgentEvaluationRun)
    recipes = await recent(ValidationRecipe)
    data_assessments = await recent(DataSecurityAssessment)
    responses = await recent(ThreatResponseAction)
    trials = await recent(RiskSimulationTrial)
    exports = await recent(ComplianceExportPackage)
    return {
        "transactions": [
            {
                "id": str(row.id),
                "provider": row.provider,
                "operation": row.operation,
                "status": row.status,
                "diff_digest": row.diff_digest,
                "blast_radius": row.blast_radius,
                "created_at": row.created_at,
            }
            for row in transactions
        ],
        "ai": {
            "receipts": [
                {
                    "id": str(row.id),
                    "provider": row.provider,
                    "model": row.model_key,
                    "decision": row.decision,
                    "reason_codes": row.reason_codes,
                    "created_at": row.created_at,
                }
                for row in receipts
            ],
            "manifests": [
                {
                    "id": str(row.id),
                    "server_key": row.server_key,
                    "tool_name": row.tool_name,
                    "version": row.version,
                    "status": row.status,
                    "approved": row.approved,
                    "schema_digest": row.schema_digest,
                }
                for row in manifests
            ],
        },
        "agent_assurance": [
            {
                "id": str(row.id),
                "run_id": str(row.run_id),
                "verifier_status": row.verifier_status,
                "confidence": str(row.confidence),
                "metrics": row.metrics,
                "finalized_at": row.finalized_at,
            }
            for row in agents
        ],
        "agent_evaluations": {
            "suites": [
                {
                    "id": str(row.id),
                    "suite_key": row.suite_key,
                    "name": row.name,
                    "task_kind": row.task_kind,
                    "version": row.version,
                    "case_count": len(row.case_manifest),
                    "active": row.active,
                }
                for row in evaluation_suites
            ],
            "runs": [
                {
                    "id": str(row.id),
                    "suite_id": str(row.suite_id),
                    "agent_version_id": str(row.agent_version_id),
                    "status": row.status,
                    "metrics": row.metrics,
                    "failed_thresholds": row.failed_thresholds,
                    "passed": row.passed,
                    "completed_at": row.completed_at,
                }
                for row in evaluation_runs
            ],
        },
        "validation_recipes": [
            {
                "id": str(row.id),
                "recipe_key": row.recipe_key,
                "status": row.status,
                "exploitation_verdict": row.exploitation_verdict,
                "reproducibility_score": str(row.reproducibility_score),
            }
            for row in recipes
        ],
        "data_security": [
            {
                "id": str(row.id),
                "provider": row.provider,
                "service": row.service,
                "scan_mode": row.scan_mode,
                "posture_score": str(row.posture_score),
                "findings": row.findings,
                "observed_at": row.observed_at,
            }
            for row in data_assessments
        ],
        "response_actions": [
            {
                "id": str(row.id),
                "action_type": row.action_type,
                "target_ref": row.target_ref,
                "status": row.status,
                "predicted_impact": row.predicted_impact,
            }
            for row in responses
        ],
        "risk_trials": [
            {
                "id": str(row.id),
                "simulation_id": str(row.simulation_id),
                "p05": str(row.percentile_05),
                "p50": str(row.percentile_50),
                "p95": str(row.percentile_95),
                "mean_annual_loss": str(row.mean_annual_loss),
                "iterations": row.iterations,
                "seed": row.seed,
            }
            for row in trials
        ],
        "compliance_exports": [
            {
                "id": str(row.id),
                "package_key": row.package_key,
                "model": row.oscal_model,
                "status": row.status,
                "content_digest": row.content_digest,
                "generated_at": row.generated_at,
            }
            for row in exports
        ],
    }


__all__ = [
    "OSCAL_VERSION",
    "RiskTrial",
    "build_oscal_package",
    "assurance_summary",
    "calibrate_risk_model",
    "canonical_digest",
    "canonical_json",
    "compare_risk_scenarios",
    "resolve_control_inheritance",
    "run_monte_carlo",
    "run_persisted_risk_trial",
    "export_workspace_oscal",
    "verify_oscal_package",
]
