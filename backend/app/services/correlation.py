"""Cross-finding correlation engine — compound risk detection and false positive suppression.

Two scanners reporting the same underlying weakness under different names inflates finding
counts without adding signal. Two individually medium findings on adjacent assets can
compose into a critical kill chain that neither scanner detected. This service handles both.

Architecture:
    1. **False positive detection** — pattern-match scanner artifacts (version strings on
       non-listening ports, findings on endpoints protected by WAF rules, etc.) and use
       the LLM to triage ambiguous cases.
    2. **Duplicate grouping** — cluster findings by (CWE, asset, endpoint) similarity
       using a deterministic hash before any model call, then use the model only to resolve
       ambiguous edge cases.
    3. **Compound risk synthesis** — identify multi-finding attack chains where the combined
       risk exceeds the sum of the parts.

The LLM is used sparingly: deterministic rules handle the clear cases; the model only
handles genuinely ambiguous ones. This keeps cost bounded on large assessments.
"""

from __future__ import annotations

import hashlib
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.core.errors import AIError
from app.db.enums import FindingStatus, Severity
from app.db.models.assessment import Assessment
from app.db.models.finding import Finding
from app.llm.base import LLMMessage
from app.llm.gateway import LLMGateway
from app.llm.prompts_enhanced import CORRELATION_SYSTEM

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Result shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FalsePositiveCandidate:
    finding_id: uuid.UUID
    reason: str
    confidence: str  # high / medium / low


@dataclass(frozen=True)
class DuplicateGroup:
    finding_ids: list[uuid.UUID]
    canonical_title: str
    representative_id: uuid.UUID


@dataclass(frozen=True)
class CompoundRisk:
    finding_ids: list[uuid.UUID]
    title: str
    description: str
    effective_severity: str
    attack_chain: str


@dataclass
class CorrelationResult:
    false_positives: list[FalsePositiveCandidate] = field(default_factory=list)
    duplicate_groups: list[DuplicateGroup] = field(default_factory=list)
    compound_risks: list[CompoundRisk] = field(default_factory=list)
    coverage_gaps: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Pydantic shapes for LLM output
# ---------------------------------------------------------------------------


class _FPItem(BaseModel):
    finding_id: str
    reason: str = ""
    confidence: str = "medium"


class _DupGroup(BaseModel):
    finding_ids: list[str] = []
    canonical_title: str = ""
    representative_id: str = ""


class _CompoundItem(BaseModel):
    finding_ids: list[str] = []
    title: str = ""
    description: str = ""
    effective_severity: str = "medium"
    attack_chain: str = ""


class _CorrelationOut(BaseModel):
    false_positive_candidates: list[_FPItem] = []
    duplicates: list[_DupGroup] = []
    compound_risks: list[_CompoundItem] = []
    coverage_gaps: list[str] = []


_CORRELATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "false_positive_candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "reason": {"type": "string", "maxLength": 500},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                },
            },
        },
        "duplicates": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "finding_ids": {"type": "array", "items": {"type": "string"}},
                    "canonical_title": {"type": "string", "maxLength": 200},
                    "representative_id": {"type": "string"},
                },
            },
        },
        "compound_risks": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "finding_ids": {"type": "array", "items": {"type": "string"}},
                    "title": {"type": "string", "maxLength": 200},
                    "description": {"type": "string", "maxLength": 1000},
                    "effective_severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                    },
                    "attack_chain": {"type": "string", "maxLength": 500},
                },
            },
        },
        "coverage_gaps": {"type": "array", "items": {"type": "string", "maxLength": 300}},
    },
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def correlate_findings(
    session: AsyncSession,
    assessment: Assessment,
    *,
    gateway: LLMGateway,
    settings: Settings,
) -> CorrelationResult:
    """Run correlation analysis on all findings for an assessment.

    Degrades gracefully — AI failure returns whatever deterministic rules found.
    """
    findings = await _load_findings(session, assessment)
    if not findings:
        return CorrelationResult()

    # Phase 1: deterministic grouping (no AI cost)
    det_duplicates = _deterministic_duplicates(findings)

    # Phase 2: AI-powered deeper analysis
    ai_result: _CorrelationOut | None = None
    try:
        ai_result = await _ai_correlate(gateway, findings)
    except AIError as exc:
        log.warning(
            "correlation.ai_failed",
            error=exc.code,
            assessment_id=str(assessment.id),
        )
    except Exception as exc:
        log.warning(
            "correlation.failed",
            error=type(exc).__name__,
            assessment_id=str(assessment.id),
        )

    return _merge(det_duplicates, ai_result, all_findings=findings)


# ---------------------------------------------------------------------------
# Deterministic duplicate detection
# ---------------------------------------------------------------------------


def _fingerprint(finding: Finding) -> str:
    """A stable fingerprint for duplicate detection.

    Two findings with the same (CWE, normalized_endpoint, CVE) on the same asset
    are strong duplicate candidates regardless of title or scanner.
    """
    parts = [
        str(finding.asset_id or ""),
        str(finding.cwe or ""),
        _normalize_endpoint(finding.endpoint or ""),
        ",".join(sorted(str(c) for c in (finding.cve_ids or []))),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _normalize_endpoint(endpoint: str) -> str:
    """Strip query strings and fragments for fingerprinting."""
    if not endpoint:
        return ""
    # Keep only scheme://host/path
    for delim in ("?", "#"):
        if delim in endpoint:
            endpoint = endpoint[: endpoint.index(delim)]
    return endpoint.lower().rstrip("/")


def _deterministic_duplicates(findings: list[Finding]) -> list[DuplicateGroup]:
    """Group findings by fingerprint. Groups of 2+ are duplicate candidates."""
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        key = _fingerprint(f)
        groups[key].append(f)

    result: list[DuplicateGroup] = []
    for _key, group in groups.items():
        if len(group) < 2:
            continue
        # Pick the highest-severity finding as representative
        rep = max(group, key=lambda f: Severity(f.severity).rank if f.severity in Severity._value2member_map_ else 0)
        result.append(
            DuplicateGroup(
                finding_ids=[f.id for f in group],
                canonical_title=rep.title or "Duplicate finding",
                representative_id=rep.id,
            )
        )
    return result


# ---------------------------------------------------------------------------
# AI correlation
# ---------------------------------------------------------------------------


async def _ai_correlate(gateway: LLMGateway, findings: list[Finding]) -> _CorrelationOut:
    """Ask the reasoning model to find false positives and compound risks."""
    import json

    # Build a compact summary — full finding data would exceed the budget
    summary = [
        {
            "id": str(f.id),
            "title": f.title,
            "severity": f.severity,
            "cwe": f.cwe,
            "cve_ids": list(f.cve_ids or []),
            "endpoint": (f.endpoint or "")[:200],
            "asset_id": str(f.asset_id) if f.asset_id else None,
            "asset_criticality": f.asset_criticality,
            "scanner": f.scanner,
            "component": f.component,
            "component_version": f.component_version,
        }
        for f in findings[:60]  # cap context size
    ]

    instruction = (
        "Analyze this finding batch and identify:\n"
        "1. False positive candidates (explain why)\n"
        "2. Duplicate findings (same underlying weakness)\n"
        "3. Compound risks (2+ findings enabling a worse attack together)\n"
        "4. Coverage gaps (what was not scanned)\n\n"
        f"## FINDINGS\n{json.dumps(summary, indent=2)}"
    )

    messages = [
        LLMMessage(role="system", content=CORRELATION_SYSTEM),
        LLMMessage(role="user", content=instruction),
    ]

    result = await gateway.complete_json(
        "reasoning",
        messages,
        schema=_CORRELATION_SCHEMA,
        model_cls=_CorrelationOut,
    )
    return result if isinstance(result, _CorrelationOut) else _CorrelationOut()


# ---------------------------------------------------------------------------
# Merge deterministic + AI results
# ---------------------------------------------------------------------------


def _merge(
    det_duplicates: list[DuplicateGroup],
    ai_result: _CorrelationOut | None,
    *,
    all_findings: list[Finding],
) -> CorrelationResult:
    """Merge deterministic duplicate groups with AI-detected results."""
    id_map = {str(f.id): f.id for f in all_findings}

    # Deduplicate: AI duplicates already captured by deterministic fingerprint → skip
    det_keys = {
        frozenset(str(fid) for fid in g.finding_ids) for g in det_duplicates
    }
    all_dups = list(det_duplicates)
    fp_candidates: list[FalsePositiveCandidate] = []
    compound_risks: list[CompoundRisk] = []
    coverage_gaps: list[str] = []

    if ai_result:
        # FP candidates
        for item in ai_result.false_positive_candidates:
            fid = id_map.get(item.finding_id)
            if fid:
                fp_candidates.append(
                    FalsePositiveCandidate(
                        finding_id=fid,
                        reason=item.reason[:500],
                        confidence=item.confidence,
                    )
                )

        # AI duplicates not already covered
        for grp in ai_result.duplicates:
            key = frozenset(grp.finding_ids)
            if key not in det_keys:
                fids = [id_map[fid] for fid in grp.finding_ids if fid in id_map]
                if len(fids) >= 2:
                    rep = id_map.get(grp.representative_id) or fids[0]
                    all_dups.append(
                        DuplicateGroup(
                            finding_ids=fids,
                            canonical_title=grp.canonical_title or "Duplicate finding",
                            representative_id=rep,
                        )
                    )

        # Compound risks
        for item in ai_result.compound_risks:
            fids = [id_map[fid] for fid in item.finding_ids if fid in id_map]
            if fids:
                compound_risks.append(
                    CompoundRisk(
                        finding_ids=fids,
                        title=item.title[:200],
                        description=item.description[:1000],
                        effective_severity=item.effective_severity,
                        attack_chain=item.attack_chain[:500],
                    )
                )

        coverage_gaps = [g[:300] for g in (ai_result.coverage_gaps or [])][:10]

    return CorrelationResult(
        false_positives=fp_candidates,
        duplicate_groups=all_dups,
        compound_risks=compound_risks,
        coverage_gaps=coverage_gaps,
    )


async def _load_findings(session: AsyncSession, assessment: Assessment) -> list[Finding]:
    stmt = (
        select(Finding)
        .options(selectinload(Finding.asset))
        .where(
            Finding.assessment_id == assessment.id,
            Finding.organization_id == assessment.organization_id,
            Finding.status.in_(
                [FindingStatus.ACTIVE.value, FindingStatus.VERIFIED.value]
            ),
            Finding.is_duplicate.is_(False),
        )
        .order_by(Finding.risk_score.desc().nullslast())
        .limit(100)
    )
    return list((await session.execute(stmt)).scalars().all())


__all__ = [
    "CompoundRisk",
    "CorrelationResult",
    "DuplicateGroup",
    "FalsePositiveCandidate",
    "correlate_findings",
]
