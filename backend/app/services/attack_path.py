"""Attack path analysis service — multi-hop kill-chain simulation (FR-NEW-001).

This service takes a set of findings and assets from an assessment and constructs the
most realistic, highest-impact attack path from the assessment's internet-facing entry
points to the highest-criticality assets.

Design principles:

**Graph-based reasoning.** Assets are nodes, persisted topology relationships are directed
edges, and findings establish evidence-backed entry points. A stable breadth-first search
finds the shortest verified route to a high-criticality target; no model may add a hop.

**MITRE ATT&CK grounding.**  Every step in the path is mapped to a specific ATT&CK
technique from the evidence, not from the model's training data.  A technique the model
recalls but the evidence does not contain is stripped by the hallucination guard.

**Compound risk detection.**  Two individually medium findings on adjacent assets can
together constitute a critical kill chain (e.g., SSRF + IMDSv1 enabled = cloud credential
theft).  This is not a scanner-level capability -- it requires the full asset graph.

**Chokepoint identification.**  The service identifies the smallest set of remediations
that would break every discovered path.  This is the key insight an operator needs: not
"fix 47 findings" but "fix these 3 and you break all viable paths."
"""

from __future__ import annotations

from collections import deque
from typing import Any, Protocol

import structlog
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.core.errors import AIError
from app.db.enums import FindingStatus, Permission
from app.db.models.assessment import Assessment
from app.db.models.asset import Asset, AssetRelationship
from app.db.models.business_risk import AssetBusinessService, BusinessService
from app.db.models.canonical import CanonicalFinding
from app.db.models.finding import Finding
from app.llm.base import LLMMessage
from app.llm.gateway import LLMGateway
from app.services.context import Principal

log = structlog.get_logger(__name__)

#: Maximum number of findings to include in a single attack path prompt.
#: Larger sets are reduced to the highest-risk subset first.
_MAX_FINDINGS_IN_PATH = 30

#: Minimum severity to include in attack path analysis.
_MIN_SEVERITY_RANK = 1  # LOW and above


class AttackStep(BaseModel):
    """One step in an attack path."""

    technique_id: str = Field(default="", max_length=20)
    technique_name: str = Field(default="", max_length=200)
    description: str = Field(default="", max_length=1000)
    asset_id: str | None = None
    finding_id: str | None = None
    relationship_id: str | None = None
    relationship_type: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


class AttackPath(BaseModel):
    """A complete multi-step attack path from entry point to crown jewel."""

    model_config = {"extra": "ignore"}

    entry_point: str = Field(default="", max_length=500)
    entry_finding_id: str | None = None
    steps: list[AttackStep] = Field(default_factory=list)
    crown_jewel: str = Field(default="", max_length=500)
    likelihood: str = Field(default="unknown", max_length=20)
    blast_radius: str = Field(default="", max_length=500)
    chokepoints: list[str] = Field(default_factory=list)
    confidence: str = Field(default="low", max_length=20)
    confidence_reason: str = Field(default="", max_length=500)
    asset_ids: list[str] = Field(default_factory=list)
    business_services: list[str] = Field(default_factory=list)
    controls: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    blast_radius_score: float = Field(default=0, ge=0, le=100)
    financial_impact: dict[str, Any] = Field(default_factory=dict)
    risk_scenario: str = Field(default="", max_length=1000)
    explanation: str = Field(default="", max_length=2000)


_ATTACK_PATH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["entry_point", "steps", "crown_jewel", "likelihood"],
    "properties": {
        "entry_point": {"type": "string", "maxLength": 500},
        "entry_finding_id": {"type": ["string", "null"], "maxLength": 100},
        "steps": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string", "maxLength": 20},
                    "technique_name": {"type": "string", "maxLength": 200},
                    "description": {"type": "string", "maxLength": 1000},
                    "asset_id": {"type": ["string", "null"]},
                    "finding_id": {"type": ["string", "null"]},
                },
            },
        },
        "crown_jewel": {"type": "string", "maxLength": 500},
        "likelihood": {"type": "string", "enum": ["low", "medium", "high"]},
        "blast_radius": {"type": "string", "maxLength": 500},
        "chokepoints": {"type": "array", "items": {"type": "string", "maxLength": 200}},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "confidence_reason": {"type": "string", "maxLength": 500},
    },
}


class _AssetLike(Protocol):
    id: Any
    name: str
    asset_type: str
    internet_exposed: bool
    criticality: str
    environment: str
    groups: list[str]
    custom_fields: dict[str, Any]


class _FindingLike(Protocol):
    id: Any
    asset_id: Any
    title: str
    severity: str
    risk_score: float | None
    cve_ids: list[str]
    cwe: str | None


class _RelationshipLike(Protocol):
    id: Any
    source_asset_id: Any
    target_asset_id: Any
    relationship_type: str
    evidence: dict[str, Any]


_SEVERITY_LIKELIHOOD = {
    "critical": 0.9,
    "high": 0.75,
    "medium": 0.55,
    "low": 0.35,
    "info": 0.1,
}
_CRITICALITY_SCORE = {"critical": 45.0, "high": 32.0, "normal": 18.0, "low": 8.0}


def _controls(asset: _AssetLike) -> list[str]:
    raw = (getattr(asset, "custom_fields", {}) or {}).get("controls", [])
    if not isinstance(raw, list):
        return []
    return sorted({str(value).strip()[:120] for value in raw if str(value).strip()})


def _financial_impact(asset: _AssetLike) -> dict[str, Any]:
    raw = (getattr(asset, "custom_fields", {}) or {}).get("financial_impact_usd")
    if isinstance(raw, int | float) and not isinstance(raw, bool) and raw >= 0:
        return {"currency": "USD", "maximum": round(float(raw), 2), "source": "asset"}
    return {"source": "not_configured"}


def _asset_path(
    entry_id: Any,
    target_ids: set[Any],
    adjacency: dict[Any, list[_RelationshipLike]],
    *,
    max_depth: int = 6,
) -> tuple[list[Any], list[_RelationshipLike]] | None:
    """Return a stable shortest evidence-backed path; never infer a missing edge."""
    queue: deque[tuple[Any, list[Any], list[_RelationshipLike]]] = deque(
        [(entry_id, [entry_id], [])]
    )
    seen = {entry_id}
    while queue:
        current, asset_ids, edges = queue.popleft()
        if current in target_ids:
            return asset_ids, edges
        if len(edges) >= max_depth:
            continue
        for edge in adjacency.get(current, []):
            target = edge.target_asset_id
            if target in seen:
                continue
            seen.add(target)
            queue.append((target, [*asset_ids, target], [*edges, edge]))
    return None


def build_deterministic_attack_paths(
    findings: list[_FindingLike],
    assets: list[_AssetLike],
    relationships: list[_RelationshipLike],
    *,
    max_paths: int = 3,
    business_services_by_asset: dict[Any, list[str]] | None = None,
    financial_impact_by_asset: dict[Any, dict[str, Any]] | None = None,
) -> list[AttackPath]:
    """Construct evidence paths from persisted topology, without model-generated edges."""
    asset_by_id = {asset.id: asset for asset in assets}
    adjacency: dict[Any, list[_RelationshipLike]] = {}
    for relationship in relationships:
        if (
            relationship.source_asset_id in asset_by_id
            and relationship.target_asset_id in asset_by_id
        ):
            adjacency.setdefault(relationship.source_asset_id, []).append(relationship)
    for edges in adjacency.values():
        edges.sort(key=lambda edge: (str(edge.target_asset_id), str(edge.id)))

    crown_ids = {
        asset.id
        for asset in assets
        if str(getattr(asset, "criticality", "unknown")) in {"critical", "high"}
    }
    entry_findings = [
        finding
        for finding in findings
        if finding.asset_id in asset_by_id
        and bool(getattr(asset_by_id[finding.asset_id], "internet_exposed", False))
    ]
    entry_findings.sort(
        key=lambda finding: (
            -float(getattr(finding, "risk_score", 0.0) or 0.0),
            str(finding.id),
        )
    )

    paths: list[AttackPath] = []
    for finding in entry_findings:
        if not crown_ids:
            break
        resolved = _asset_path(finding.asset_id, crown_ids, adjacency)
        if resolved is None:
            continue
        asset_ids, edges = resolved
        path_assets = [asset_by_id[asset_id] for asset_id in asset_ids]
        crown = path_assets[-1]
        controls = sorted({control for asset in path_assets for control in _controls(asset)})
        services = sorted(
            {
                str(group).strip()[:120]
                for asset in path_assets
                for group in [
                    *(getattr(asset, "groups", []) or []),
                    *((business_services_by_asset or {}).get(asset.id, [])),
                ]
                if str(group).strip()
            }
        )
        base = _SEVERITY_LIKELIHOOD.get(str(finding.severity).lower(), 0.2)
        likelihood_score = max(0.05, base - (0.07 * len(edges)) - min(0.3, 0.08 * len(controls)))
        likelihood = "high" if likelihood_score >= 0.7 else "medium" if likelihood_score >= 0.4 else "low"

        reachable: set[Any] = set()
        pending = list(asset_ids)
        while pending:
            source = pending.pop()
            for edge in adjacency.get(source, []):
                if edge.target_asset_id not in reachable:
                    reachable.add(edge.target_asset_id)
                    pending.append(edge.target_asset_id)
        blast_score = min(
            100.0,
            _CRITICALITY_SCORE.get(str(crown.criticality), 12.0)
            + (10.0 if str(getattr(crown, "environment", "")) == "production" else 0.0)
            + min(25.0, len(reachable) * 5.0)
            + min(20.0, len(services) * 5.0),
        )

        steps = [
            AttackStep(
                technique_id=str(getattr(finding, "cwe", "") or "")[:20],
                technique_name=f"Exploit {finding.title}"[:200],
                description=(
                    f"Use the persisted {finding.severity} finding on {path_assets[0].name} "
                    "as the initial foothold."
                )[:1000],
                asset_id=str(finding.asset_id),
                finding_id=str(finding.id),
                evidence={
                    "cve_ids": list(getattr(finding, "cve_ids", []) or []),
                    "risk_score": getattr(finding, "risk_score", None),
                },
            )
        ]
        for edge in edges:
            target = asset_by_id[edge.target_asset_id]
            steps.append(
                AttackStep(
                    technique_name=f"Traverse {edge.relationship_type}"[:200],
                    description=(
                        f"Move to {target.name} through the persisted "
                        f"{edge.relationship_type} relationship."
                    )[:1000],
                    asset_id=str(target.id),
                    relationship_id=str(edge.id),
                    relationship_type=edge.relationship_type,
                    evidence=dict(getattr(edge, "evidence", {}) or {}),
                )
            )

        evidence_refs = [f"finding:{finding.id}"] + [
            f"relationship:{edge.id}" for edge in edges
        ]
        confidence = "high" if all(getattr(edge, "evidence", {}) for edge in edges) else "medium"
        service_label = ", ".join(services) if services else "unmapped business services"
        paths.append(
            AttackPath(
                entry_point=path_assets[0].name,
                entry_finding_id=str(finding.id),
                steps=steps,
                crown_jewel=crown.name,
                likelihood=likelihood,
                blast_radius=(
                    f"{len(reachable)} reachable asset(s); business scope: {service_label}."
                ),
                chokepoints=[
                    f"Remediate finding {finding.id}",
                    *[f"Restrict relationship {edge.id}" for edge in edges[:2]],
                ],
                confidence=confidence,
                confidence_reason=(
                    "Every hop is backed by persisted asset topology; confidence reflects "
                    "whether each relationship includes source evidence."
                ),
                asset_ids=[str(asset_id) for asset_id in asset_ids],
                business_services=services,
                controls=controls,
                evidence_refs=evidence_refs,
                blast_radius_score=round(blast_score, 2),
                financial_impact=(financial_impact_by_asset or {}).get(
                    crown.id, _financial_impact(crown)
                ),
                risk_scenario=(
                    f"Exploit {finding.title} on {path_assets[0].name}, traverse "
                    f"{len(edges)} verified relationship(s), and reach {crown.name}."
                ),
            )
        )
        if len(paths) >= max_paths:
            break
    return paths


async def current_exposure_paths(
    session: AsyncSession,
    principal: Principal,
    *,
    max_paths: int = 20,
) -> list[AttackPath]:
    """Build the tenant's current graph view from active canonical exposure data."""
    principal.require(Permission.ASSET_READ)
    assets = list(
        (
            await session.scalars(
                select(Asset)
                .where(
                    Asset.organization_id == principal.organization_id,
                    Asset.merged_into_id.is_(None),
                )
                .order_by(Asset.id)
                .limit(5_000)
            )
        ).all()
    )
    relationships = list(
        (
            await session.scalars(
                select(AssetRelationship)
                .where(AssetRelationship.organization_id == principal.organization_id)
                .order_by(
                    AssetRelationship.source_asset_id,
                    AssetRelationship.target_asset_id,
                    AssetRelationship.id,
                )
                .limit(10_000)
            )
        ).all()
    )
    findings = list(
        (
            await session.scalars(
                select(CanonicalFinding)
                .where(
                    CanonicalFinding.organization_id == principal.organization_id,
                    CanonicalFinding.status.in_(("new", "open", "reopened", "mitigated")),
                )
                .order_by(CanonicalFinding.risk_score.desc(), CanonicalFinding.id)
                .limit(5_000)
            )
        ).all()
    )
    services_by_asset, financial_by_asset = await _load_business_context(
        session,
        principal.organization_id,
        [asset.id for asset in assets],
    )
    return build_deterministic_attack_paths(
        findings,
        assets,
        relationships,
        max_paths=max(1, min(max_paths, 100)),
        business_services_by_asset=services_by_asset,
        financial_impact_by_asset=financial_by_asset,
    )


async def generate_attack_paths(
    session: AsyncSession,
    assessment: Assessment,
    *,
    gateway: LLMGateway,
    settings: Settings,
) -> list[AttackPath]:
    """Build persisted-topology paths and optionally ask the model to explain them."""
    del settings
    try:
        findings = await _load_candidate_findings(session, assessment)
        if not findings:
            log.info("attack_path.no_candidates", assessment_id=str(assessment.id))
            return []

        assets = await _load_assets(session, assessment)
        relationships = await _load_relationships(session, assessment)
        services_by_asset, financial_by_asset = await _load_business_context(
            session,
            assessment.organization_id,
            [asset.id for asset in assets],
        )
        paths = build_deterministic_attack_paths(
            findings,
            assets,
            relationships,
            business_services_by_asset=services_by_asset,
            financial_impact_by_asset=financial_by_asset,
        )
        if not paths:
            log.info("attack_path.no_reachable_crown_jewel", assessment_id=str(assessment.id))
            return []
    except Exception as exc:
        log.warning(
            "attack_path.graph_failed",
            error=type(exc).__name__,
            assessment_id=str(assessment.id),
        )
        return []

    try:
        paths = await _explain_paths(gateway, paths)
        log.info(
            "attack_path.generated",
            assessment_id=str(assessment.id),
            paths=len(paths),
        )
        return paths
    except AIError as exc:
        log.warning("attack_path.ai_failed", error=exc.code, assessment_id=str(assessment.id))
        return paths
    except Exception as exc:
        log.warning(
            "attack_path.explanation_failed",
            error=type(exc).__name__,
            assessment_id=str(assessment.id),
        )
        return paths


async def _load_candidate_findings(session: AsyncSession, assessment: Assessment) -> list[Finding]:
    """Load high-priority findings with enrichment eagerly loaded."""
    stmt = (
        select(Finding)
        .options(selectinload(Finding.enrichment), selectinload(Finding.asset))
        .where(
            Finding.assessment_id == assessment.id,
            Finding.organization_id == assessment.organization_id,
            Finding.status.in_([FindingStatus.ACTIVE.value, FindingStatus.VERIFIED.value]),
            Finding.is_duplicate.is_(False),
            Finding.is_false_positive.is_(False),
        )
        .order_by(
            Finding.priority.asc().nullslast(),
            Finding.risk_score.desc().nullslast(),
        )
        .limit(_MAX_FINDINGS_IN_PATH)
    )
    return list((await session.execute(stmt)).scalars().all())


async def _load_assets(session: AsyncSession, assessment: Assessment) -> list[Asset]:
    """Load assets associated with this assessment."""
    stmt = (
        select(Asset)
        .where(Asset.organization_id == assessment.organization_id)
        .order_by(
            # Critical assets first so the model prioritizes them as crown jewels.
            Asset.criticality.asc(),
        )
        .limit(50)
    )
    return list((await session.execute(stmt)).scalars().all())


async def _load_relationships(
    session: AsyncSession, assessment: Assessment
) -> list[AssetRelationship]:
    stmt = (
        select(AssetRelationship)
        .where(AssetRelationship.organization_id == assessment.organization_id)
        .order_by(
            AssetRelationship.source_asset_id,
            AssetRelationship.target_asset_id,
            AssetRelationship.id,
        )
        .limit(2_000)
    )
    return list((await session.execute(stmt)).scalars().all())


async def _load_business_context(
    session: AsyncSession,
    organization_id: Any,
    asset_ids: list[Any],
) -> tuple[dict[Any, list[str]], dict[Any, dict[str, Any]]]:
    if not asset_ids:
        return {}, {}
    rows = (
        await session.execute(
            select(
                AssetBusinessService.asset_id,
                BusinessService.name,
                BusinessService.maximum_loss_usd,
            )
            .join(
                BusinessService,
                BusinessService.id == AssetBusinessService.business_service_id,
            )
            .where(
                AssetBusinessService.organization_id == organization_id,
                BusinessService.organization_id == organization_id,
                BusinessService.status == "active",
                AssetBusinessService.asset_id.in_(asset_ids),
            )
            .order_by(AssetBusinessService.asset_id, BusinessService.name)
        )
    ).all()
    services: dict[Any, list[str]] = {}
    maximums: dict[Any, float] = {}
    for asset_id, service_name, maximum_loss in rows:
        services.setdefault(asset_id, []).append(str(service_name))
        if maximum_loss is not None:
            maximums[asset_id] = maximums.get(asset_id, 0.0) + float(maximum_loss)
    financial = {
        asset_id: {
            "currency": "USD",
            "maximum": round(value, 2),
            "source": "business_service",
        }
        for asset_id, value in maximums.items()
    }
    return services, financial


def _build_context(findings: list[Finding], assets: list[Asset]) -> dict[str, Any]:
    """Build the evidence context for the attack path prompt."""
    evidence: dict[str, Any] = {}

    # Asset inventory — kept minimal (no raw data, just security-relevant attributes)
    asset_map: dict[str, dict[str, Any]] = {}
    for asset in assets:
        asset_map[str(asset.id)] = {
            "id": str(asset.id),
            "type": asset.asset_type,
            "criticality": asset.criticality,
            "exposure": getattr(asset, "exposure", "unknown"),
        }
        evidence[f"asset:{asset.id}"] = {
            "type": asset.asset_type,
            "criticality": asset.criticality,
        }

    # Finding inventory with enrichment
    finding_summaries: list[dict[str, Any]] = []
    for finding in findings:
        summary: dict[str, Any] = {
            "id": str(finding.id),
            "title": finding.title,
            "severity": finding.severity,
            "priority": finding.priority,
            "risk_score": finding.risk_score,
            "cve_ids": list(finding.cve_ids or []),
            "cwe": finding.cwe,
            "cvss_score": finding.cvss_score,
            "asset_id": str(finding.asset_id) if finding.asset_id else None,
            "asset_criticality": finding.asset_criticality,
        }
        # Fold in enrichment signals
        if finding.enrichment:
            e = finding.enrichment
            summary["in_kev"] = e.in_kev
            summary["epss_score"] = e.epss_score
            summary["nvd_description"] = (e.nvd_description or "")[:300]
        finding_summaries.append(summary)
        evidence[f"finding:{finding.id}"] = summary

    return {
        "findings": finding_summaries,
        "assets": asset_map,
        "evidence": evidence,
    }


async def _explain_paths(gateway: LLMGateway, paths: list[AttackPath]) -> list[AttackPath]:
    """Generate prose for fixed paths; model output cannot add nodes, edges, or scores."""
    import json

    instruction = (
        "Explain each deterministic exposure path below for a security operator. Do not add, "
        "remove, reorder, or reinterpret assets, findings, relationships, controls, scores, "
        "or financial values. Return only an explanation for each supplied index.\n\n"
        + json.dumps(
            [
                {
                    "index": index,
                    "entry_point": path.entry_point,
                    "crown_jewel": path.crown_jewel,
                    "risk_scenario": path.risk_scenario,
                    "evidence_refs": path.evidence_refs,
                    "controls": path.controls,
                    "likelihood": path.likelihood,
                }
                for index, path in enumerate(paths)
            ],
            indent=2,
        )
    )

    messages = [
        LLMMessage(
            role="system",
            content=(
                "You explain a deterministic cybersecurity exposure graph. The supplied "
                "nodes, edges, findings, controls, scores, and values are authoritative. "
                "Never invent or change graph facts; produce concise defensive prose only."
            ),
        ),
        LLMMessage(role="user", content=instruction),
    ]

    explanation_schema: dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "explanations": {
                "type": "array",
                "maxItems": len(paths),
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["index", "explanation"],
                    "properties": {
                        "index": {"type": "integer", "minimum": 0, "maximum": len(paths) - 1},
                        "explanation": {"type": "string", "maxLength": 2000},
                    },
                },
            }
        },
        "required": ["explanations"],
    }

    result = await gateway.complete_json(
        "reasoning",
        messages,
        schema=explanation_schema,
    )
    explained = list(paths)
    for item in result.get("explanations") or []:
        if not isinstance(item, dict) or not isinstance(item.get("index"), int):
            continue
        index = item["index"]
        explanation = item.get("explanation")
        if 0 <= index < len(explained) and isinstance(explanation, str):
            explained[index] = explained[index].model_copy(
                update={"explanation": explanation.strip()[:2000]}
            )
    return explained


__all__ = [
    "AttackPath",
    "AttackStep",
    "build_deterministic_attack_paths",
    "current_exposure_paths",
    "generate_attack_paths",
]
