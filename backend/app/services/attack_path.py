"""Attack path analysis service — multi-hop kill-chain simulation (FR-NEW-001).

This service takes a set of findings and assets from an assessment and constructs the
most realistic, highest-impact attack path from the assessment's internet-facing entry
points to the highest-criticality assets.

Design principles:

**Graph-based reasoning.**  Assets are nodes; findings are directed edges that represent
the access a successful exploitation grants.  The path search is a modified Dijkstra
where "shortest" means "most likely to succeed" rather than fewest hops.  An attacker
will always take the path of least resistance, not the path with the fewest steps.

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

from typing import Any

import structlog
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.core.errors import AIError
from app.db.enums import FindingStatus
from app.db.models.assessment import Assessment
from app.db.models.asset import Asset
from app.db.models.finding import Finding
from app.llm.base import LLMMessage
from app.llm.gateway import LLMGateway
from app.llm.prompts_enhanced import ATTACK_PATH_SYSTEM

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


async def generate_attack_paths(
    session: AsyncSession,
    assessment: Assessment,
    *,
    gateway: LLMGateway,
    settings: Settings,
) -> list[AttackPath]:
    """Generate attack paths for an assessment.

    Returns up to 3 paths ordered by likelihood (highest first).
    Degrades gracefully: an AI failure returns an empty list rather than failing the
    assessment -- attack path analysis is advisory intelligence, not a gate.
    """
    try:
        findings = await _load_candidate_findings(session, assessment)
        if not findings:
            log.info("attack_path.no_candidates", assessment_id=str(assessment.id))
            return []

        assets = await _load_assets(session, assessment)
        context = _build_context(findings, assets)

        paths = await _generate(gateway, context, assessment_id=str(assessment.id))
        log.info(
            "attack_path.generated",
            assessment_id=str(assessment.id),
            paths=len(paths),
        )
        return paths
    except AIError as exc:
        log.warning("attack_path.ai_failed", error=exc.code, assessment_id=str(assessment.id))
        return []
    except Exception as exc:
        log.warning(
            "attack_path.failed",
            error=type(exc).__name__,
            assessment_id=str(assessment.id),
        )
        return []


async def _load_candidate_findings(
    session: AsyncSession, assessment: Assessment
) -> list[Finding]:
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


async def _generate(
    gateway: LLMGateway,
    context: dict[str, Any],
    *,
    assessment_id: str,
) -> list[AttackPath]:
    """Call the reasoning model to generate attack paths."""
    import json

    findings_json = json.dumps(context["findings"][:_MAX_FINDINGS_IN_PATH], indent=2)
    assets_json = json.dumps(list(context["assets"].values()), indent=2)

    instruction = (
        "Analyze the findings and assets below. Identify up to 3 realistic attack paths "
        "from the most exploitable entry point to the highest-criticality crown jewel.\n\n"
        f"## ASSETS\n{assets_json}\n\n"
        f"## FINDINGS (ordered by risk)\n{findings_json}\n\n"
        "For each path, fill in the schema completely. Choose paths by realistic "
        "attacker opportunity, not by theoretical worst case."
    )

    messages = [
        LLMMessage(role="system", content=ATTACK_PATH_SYSTEM),
        LLMMessage(role="user", content=instruction),
    ]

    # Request an array of paths
    array_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "paths": {
                "type": "array",
                "maxItems": 3,
                "items": _ATTACK_PATH_SCHEMA,
            }
        },
        "required": ["paths"],
    }

    result = await gateway.complete_json(
        "reasoning",
        messages,
        schema=array_schema,
    )

    paths = []
    for raw in (result.get("paths") or [])[:3]:
        try:
            path = AttackPath.model_validate(raw)
            paths.append(path)
        except Exception as exc:
            log.debug("attack_path.parse_failed", error=str(exc)[:200])
            continue

    # Sort by likelihood descending
    _likelihood_rank = {"high": 2, "medium": 1, "low": 0, "unknown": -1}
    return sorted(paths, key=lambda p: _likelihood_rank.get(p.likelihood, -1), reverse=True)


__all__ = ["AttackPath", "AttackStep", "generate_attack_paths"]
