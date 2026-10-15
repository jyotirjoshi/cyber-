"""Bounded, read-only exposure and canonical-finding tools for agent chat."""

from __future__ import annotations

import json
import re
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import InvalidModelResponseError
from app.core.logging_conf import redact_text
from app.db.base import utcnow
from app.db.enums import Permission
from app.db.models.asset import Asset
from app.db.models.canonical import CanonicalFinding, FindingObservation
from app.db.models.finding import Finding
from app.llm.base import LLMMessage
from app.llm.gateway import LLMGateway
from app.schemas.common import PaginationParams
from app.services.context import Principal
from app.services.exposure_feed import list_exposures

_BARE_KEY = re.compile(r"(?i)\b(?:sk-|ghp_|glpat-)[A-Za-z0-9_-]{8,}\b")
_READ_HINTS = ("expos", "finding", "alert", "vulnerab")
_EXPLICIT_READ = re.compile(r"\b(?:how many|count|list|show|latest|recent)\b")
ExposureSource = Literal[
    "defectdojo", "github", "gitlab", "wazuh", "sonarqube", "snyk", "tenable",
    "qualys", "rapid7", "wiz", "crowdstrike", "aws_security_hub", "azure_defender", "gcp_scc",
]
ExposureSeverity = Literal["critical", "high", "medium", "low", "info"]
_SOURCE_ALIASES: dict[ExposureSource, tuple[str, ...]] = {
    "defectdojo": ("defectdojo", "defect dojo"),
    "github": ("github", "git hub"),
    "gitlab": ("gitlab", "git lab"),
    "wazuh": ("wazuh",),
    "sonarqube": ("sonarqube", "sonar qube"),
    "snyk": ("snyk",),
    "tenable": ("tenable", "nessus"),
    "qualys": ("qualys",),
    "rapid7": ("rapid7", "rapid 7", "insightvm"),
    "wiz": ("wiz",),
    "crowdstrike": ("crowdstrike",),
    "aws_security_hub": ("aws_security_hub", "aws security hub", "security hub"),
    "azure_defender": ("azure_defender", "azure defender", "defender for cloud"),
    "gcp_scc": ("gcp_scc", "gcp scc", "google security command center"),
}
_SEVERITIES: tuple[ExposureSeverity, ...] = ("critical", "high", "medium", "low", "info")
_CANONICAL_HINT = re.compile(
    r"\b(?:findings?|vulnerabilities|remediation queue|CVE-\d{4}-\d{4,})\b", re.I
)
_CANONICAL_READ = re.compile(
    r"\b(?:show|list|count|how many|which|what|why|explain|top|highest|overdue|assigned)\b", re.I
)
_ASSET_HINT = re.compile(r"\b(?:assets?|inventory|attack surface|internet[- ]facing|exposed hosts?)\b", re.I)
_ASSET_READ = re.compile(r"\b(?:show|list|count|how many|which|what|top|latest|recent|critical|production|inactive)\b", re.I)
_ACTIVE_STATUSES = ("new", "open", "reopened", "mitigated")
_FINDING_ID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_DUPLICATE_REVIEW_HINT = re.compile(
    r"\b(?:duplicate(?:s)?\s+(?:candidate|suggestion|review|record|finding)|"
    r"(?:candidate|suggestion)s?\s+duplicate(?:s)?)\b",
    re.I,
)


class ExposureReadPlan(BaseModel):
    """The model can select filters, never an arbitrary tool or SQL expression."""

    model_config = ConfigDict(extra="forbid")

    tool: Literal["none", "exposures"] = "none"
    source: ExposureSource | None = None
    severity: ExposureSeverity | None = None


def _safe_text(value: str) -> str:
    return _BARE_KEY.sub("[REDACTED]", redact_text(value[:200]))


def _mentioned_sources(question: str) -> list[ExposureSource]:
    return [
        source
        for source, aliases in _SOURCE_ALIASES.items()
        if any(re.search(rf"\b{re.escape(alias)}\b", question, re.I) for alias in aliases)
    ]


def _risk_factors_for_chat(factors: dict) -> dict:
    """Keep scoring provenance but never pass provider payloads or unknown keys."""
    result: dict = {}
    for section, allowed in (
        (
            "components",
            {
                "severity",
                "exploitation",
                "exploit_probability",
                "exposure",
                "asset_criticality",
                "ransomware",
            },
        ),
        (
            "inputs",
            {
                "severity_label",
                "cvss_score",
                "in_kev",
                "exploit_available",
                "observed_in_the_wild",
                "epss_score",
                "internet_exposed",
                "asset_criticality",
                "ransomware_use",
            },
        ),
    ):
        values = factors.get(section)
        if isinstance(values, dict):
            result[section] = {
                key: _safe_text(value) if isinstance(value, str) else value
                for key, value in values.items()
                if key in allowed and (value is None or isinstance(value, str | int | float | bool))
            }
    missing = factors.get("unavailable")
    if isinstance(missing, list):
        result["unavailable"] = [
            _safe_text(value) for value in missing[:8] if isinstance(value, str)
        ]
    return result


async def _read_finding_detail(
    session: AsyncSession,
    principal: Principal,
    finding_id: uuid.UUID,
) -> str:
    rows = (
        await session.execute(
            select(CanonicalFinding, Asset.name)
            .join(
                Asset,
                and_(
                    Asset.id == CanonicalFinding.asset_id,
                    Asset.organization_id == CanonicalFinding.organization_id,
                ),
            )
            .where(
                CanonicalFinding.organization_id == principal.organization_id,
                CanonicalFinding.id == finding_id,
            )
            .limit(1)
        )
    ).all()
    if not rows:
        return json.dumps(
            {
                "notice": "No accessible canonical finding matched this ID; this is not proof "
                "the issue does not exist.",
                "finding": None,
            }
        )
    finding, asset_name = rows[0]
    sources = (
        (
            await session.execute(
                select(FindingObservation)
                .where(
                    FindingObservation.organization_id == principal.organization_id,
                    FindingObservation.canonical_finding_id == finding_id,
                )
                .order_by(FindingObservation.last_seen_at.desc(), FindingObservation.id)
                .limit(10)
            )
        )
        .scalars()
        .all()
    )
    return json.dumps(
        {
            "notice": "Cached read-only finding and source provenance; not live exploit verification. "
            "Source list is limited to 10. Evidence payloads are omitted.",
            "finding": {
                "id": str(finding.id),
                "asset_id": str(finding.asset_id),
                "asset": _safe_text(asset_name),
                "title": _safe_text(finding.title),
                "severity": finding.severity,
                "status": finding.status,
                "risk_score": finding.risk_score,
                "risk_factors": _risk_factors_for_chat(finding.risk_factors or {}),
                "cves": (finding.cve_ids or [])[:5],
                "assignee_user_id": str(finding.assignee_user_id)
                if finding.assignee_user_id
                else None,
                "due_at": finding.due_at.isoformat() if finding.due_at else None,
                "last_seen_at": finding.last_seen_at.isoformat(),
                "remediation_plan": _safe_text(finding.remediation_plan or ""),
            },
            "sources": [
                {
                    "provider": _safe_text(item.provider),
                    "status": item.source_status,
                    "last_seen_at": item.last_seen_at.isoformat(),
                }
                for item in sources
            ],
        },
        ensure_ascii=True,
        separators=(",", ":"),
    )


async def maybe_read_canonical_findings(
    session: AsyncSession,
    principal: Principal,
    question: str,
) -> str | None:
    """Ground remediation questions in bounded, tenant-owned canonical records.

    Filters are derived only from the user's words; the model cannot choose SQL or
    silently broaden a requested scope. This does not initiate a scan or mutation.
    """
    if not principal.has(Permission.FINDING_READ):
        return None
    if not (_CANONICAL_HINT.search(question) and _CANONICAL_READ.search(question)):
        return None

    ids = list(dict.fromkeys(_FINDING_ID.findall(question)))
    if len(ids) > 1:
        return None
    if ids:
        return await _read_finding_detail(session, principal, uuid.UUID(ids[0]))

    severities = [value for value in _SEVERITIES if re.search(rf"\b{value}\b", question, re.I)]
    cves = list(dict.fromkeys(re.findall(r"\bCVE-\d{4}-\d{4,}\b", question.upper())))
    sources = _mentioned_sources(question)
    if len(severities) > 1 or len(cves) > 1 or len(sources) > 1:
        return None

    mine = bool(re.search(r"\b(?:my|mine|assigned to me)\b", question, re.I))
    overdue = bool(re.search(r"\b(?:overdue|past due|breached)\b", question, re.I))
    status = "closed" if re.search(r"\bclosed\b", question, re.I) else "active"
    filters = [CanonicalFinding.organization_id == principal.organization_id]
    if sources:
        # EXISTS preserves one canonical result even when multiple CVE/source
        # observations point at it. Apply the same predicate to count and sample.
        filters.append(
            exists(
                select(FindingObservation.id).where(
                    FindingObservation.organization_id == principal.organization_id,
                    FindingObservation.canonical_finding_id == CanonicalFinding.id,
                    FindingObservation.provider == sources[0],
                    FindingObservation.source_status != "superseded",
                )
            )
        )
    if mine:
        # A non-human principal has no personal queue to inspect.
        if principal.user_id is None:
            return None
        filters.append(CanonicalFinding.assignee_user_id == principal.user_id)
    if overdue:
        filters.append(CanonicalFinding.due_at < utcnow())
    if severities:
        filters.append(CanonicalFinding.severity == severities[0])
    if cves:
        filters.append(CanonicalFinding.cve_ids.contains([cves[0]]))
    if status == "closed":
        filters.append(CanonicalFinding.status == "closed")
    else:
        filters.append(CanonicalFinding.status.in_(_ACTIVE_STATUSES))

    total = int(
        (
            await session.execute(
                select(func.count()).select_from(CanonicalFinding).where(*filters)
            )
        ).scalar_one()
    )
    rows = (
        await session.execute(
            select(CanonicalFinding, Asset.name)
            .join(
                Asset,
                and_(
                    Asset.id == CanonicalFinding.asset_id,
                    Asset.organization_id == CanonicalFinding.organization_id,
                ),
            )
            .where(*filters)
            .order_by(
                CanonicalFinding.risk_score.desc(),
                CanonicalFinding.last_seen_at.desc(),
                CanonicalFinding.id,
            )
            .limit(10)
        )
    ).all()
    sample = [
        {
            "id": str(row.id),
            "asset_id": str(row.asset_id),
            "asset": _safe_text(asset_name),
            "title": _safe_text(row.title),
            "severity": row.severity,
            "status": row.status,
            "risk_score": row.risk_score,
            "cves": (row.cve_ids or [])[:5],
            "assignee_user_id": str(row.assignee_user_id) if row.assignee_user_id else None,
            "due_at": row.due_at.isoformat() if row.due_at else None,
            "last_seen_at": row.last_seen_at.isoformat(),
            "remediation_plan": _safe_text(row.remediation_plan or ""),
        }
        for row, asset_name in rows
    ]
    return json.dumps(
        {
            "notice": "Cached canonical findings; total matches the filters, sample is limited to 10. "
            "Risk scores are prioritization estimates, not proof of exploitability.",
            "filters": {
                "mine": mine,
                "overdue": overdue,
                "severity": severities[0] if severities else None,
                "cve": cves[0] if cves else None,
                "status": status,
                "source": sources[0] if sources else None,
            },
            "total": total,
            "sample": sample,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    )


async def maybe_read_duplicate_candidates(
    session: AsyncSession,
    principal: Principal,
    question: str,
) -> str | None:
    """Return only deterministic, tenant-local duplicate review candidates.

    This is an advisory queue. It intentionally does not expose model-only groups,
    raw scanner payloads, or a mechanism to alter provider-side duplicate state.
    """
    if not principal.has(Permission.FINDING_READ) or not _DUPLICATE_REVIEW_HINT.search(question):
        return None
    rows = (
        (
            await session.execute(
                select(Finding)
                .where(
                    Finding.organization_id == principal.organization_id,
                    Finding.status.in_(("active", "verified")),
                    Finding.is_duplicate.is_(False),
                    Finding.is_false_positive.is_(False),
                    Finding.risk_factors["duplicate_candidate"]["source"].astext == "correlation",
                    Finding.risk_factors["duplicate_candidate"]["confidence"].astext == "high",
                )
                .order_by(Finding.risk_score.desc().nullslast(), Finding.id)
                .limit(100)
            )
        )
        .scalars()
        .all()
    )
    candidates: list[dict[str, object]] = []
    for finding in rows:
        factor = (finding.risk_factors or {}).get("duplicate_candidate")
        if not isinstance(factor, dict):
            continue
        representative_id = factor.get("representative_finding_id")
        title = factor.get("representative_title")
        group_size = factor.get("group_size")
        reason = factor.get("reason")
        if (
            factor.get("source") != "correlation"
            or factor.get("confidence") != "high"
            or not isinstance(representative_id, str)
            or not isinstance(title, str)
            or not isinstance(group_size, int)
            or isinstance(group_size, bool)
            or group_size < 2
            or not isinstance(reason, str)
        ):
            continue
        candidates.append(
            {
                "finding_id": str(finding.id),
                "title": _safe_text(finding.title),
                "severity": finding.severity,
                "risk_score": finding.risk_score,
                "representative_finding_id": representative_id,
                "representative_title": _safe_text(title),
                "group_size": group_size,
                "reason": _safe_text(reason),
            }
        )
        if len(candidates) == 10:
            break
    return json.dumps(
        {
            "notice": (
                "Evidence-backed duplicate review candidates from cached assessment "
                "correlation. They are not provider-verified duplicates and do not "
                "change any finding status. Up to 10 candidates are shown from the "
                "100 highest-risk matching records; this is not the total queue size."
            ),
            "total_sampled_candidates": len(candidates),
            "sample": candidates,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    )


async def maybe_read_exposures(
    session: AsyncSession,
    principal: Principal,
    gateway: LLMGateway,
    question: str,
) -> str | None:
    """Perform at most one bounded read, then return untrusted data for the LLM."""
    if not principal.has(Permission.FINDING_READ):
        return None
    lowered = question.lower()
    if not any(hint in lowered for hint in _READ_HINTS):
        return None
    mentioned_sources = _mentioned_sources(question)
    mentioned_severities = [
        severity for severity in _SEVERITIES if re.search(rf"\b{severity}\b", lowered)
    ]
    if len(mentioned_sources) > 1 or len(mentioned_severities) > 1:
        return None

    if _EXPLICIT_READ.search(lowered):
        plan = ExposureReadPlan(
            tool="exposures",
            source=mentioned_sources[0] if mentioned_sources else None,
            severity=mentioned_severities[0] if mentioned_severities else None,
        )
    else:
        try:
            plan = await gateway.complete_json(
                "reasoning",
                [
                    LLMMessage(
                        role="system",
                        content=(
                            "Choose a read-only Cynux exposure lookup only if it helps answer the user's "
                            "question. Return a JSON object with tool='exposures' or tool='none', "
                            "and optional source and severity filters. Never request actions. "
                            "A count is available even when only ten sample rows are returned."
                        ),
                    ),
                    LLMMessage(role="user", content=question[:2000]),
                ],
                schema=ExposureReadPlan.model_json_schema(),
                model_cls=ExposureReadPlan,
                max_attempts=1,
            )
        except InvalidModelResponseError:
            return None
    if plan.tool != "exposures":
        return None

    source_filter = plan.source if mentioned_sources == [plan.source] else None
    severity_filter = plan.severity if mentioned_severities == [plan.severity] else None

    rows, total = await list_exposures(
        session,
        principal,
        pagination=PaginationParams(limit=10, offset=0),
        source=source_filter,
        severity=severity_filter,
    )
    sample = [
        {
            "id": str(row["id"]),
            "source": row["source"],
            "title": _safe_text(row["title"]),
            "severity": row["severity"],
            "status": row["status"],
            "resource": _safe_text(row["resource"] or ""),
            "seen_at": row["seen_at"].isoformat() if row["seen_at"] else None,
        }
        for row in rows
    ]
    return json.dumps(
        {
            "notice": "Cached read-only records; total reflects filters, sample is limited to 10.",
            "source_filter": source_filter,
            "severity_filter": severity_filter,
            "total": total,
            "sample": sample,
        },
        ensure_ascii=True,
        separators=(",", ":"),
    )


async def maybe_read_assets(
    session: AsyncSession,
    principal: Principal,
    question: str,
) -> str | None:
    """Return a bounded tenant-local asset inventory slice for natural-language chat."""
    if not principal.has(Permission.ASSET_READ):
        return None
    if not (_ASSET_HINT.search(question) and _ASSET_READ.search(question)):
        return None
    lowered = question.casefold()
    filters = [Asset.organization_id == principal.organization_id]
    status: str | None = None
    if "inactive" in lowered or "unreachable" in lowered or "out of scope" in lowered:
        status = "inactive" if "inactive" in lowered else "unreachable" if "unreachable" in lowered else "out_of_scope"
        filters.append(Asset.status == status)
    internet_exposed = bool(re.search(r"\b(?:internet[- ]facing|externally exposed|public)\b", lowered))
    if internet_exposed:
        filters.append(Asset.internet_exposed.is_(True))
    criticality = "critical" if re.search(r"\bcritical\b", lowered) else "high" if re.search(r"\bhigh[- ]criticality\b", lowered) else None
    if criticality:
        filters.append(Asset.criticality == criticality)
    environment = "production" if re.search(r"\b(?:production|prod)\b", lowered) else "staging" if re.search(r"\bstaging\b", lowered) else None
    if environment:
        filters.append(Asset.environment == environment)
    total = int((await session.execute(select(func.count()).select_from(Asset).where(*filters))).scalar_one())
    rows = (
        await session.execute(
            select(Asset)
            .where(*filters)
            .order_by(
                Asset.internet_exposed.desc(),
                Asset.criticality.asc(),
                Asset.last_seen_at.desc().nullslast(),
                Asset.id,
            )
            .limit(10)
        )
    ).scalars().all()
    return json.dumps(
        {
            "notice": "Cached tenant asset inventory; total reflects these filters and sample is limited to 10.",
            "filters": {
                "status": status,
                "internet_exposed": internet_exposed or None,
                "criticality": criticality,
                "environment": environment,
            },
            "total": total,
            "sample": [
                {
                    "id": str(asset.id),
                    "name": _safe_text(asset.name),
                    "type": asset.asset_type,
                    "status": asset.status,
                    "internet_exposed": asset.internet_exposed,
                    "criticality": asset.criticality,
                    "environment": asset.environment,
                    "owner_team": _safe_text(asset.owner_team or ""),
                    "last_seen_at": asset.last_seen_at.isoformat() if asset.last_seen_at else None,
                }
                for asset in rows
            ],
        },
        ensure_ascii=True,
        separators=(",", ":"),
    )
