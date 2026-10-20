"""Evidence-grounded evaluation suites for production AI workers.

Cases retain artifact references and expected SHA-256 digests only. Results are reduced to
bounded counters, digests, timing, and cost so evaluation cannot become a second prompt or
customer-content store.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any

from app.core.errors import ConflictError, ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.agent_definition import AgentDefinitionVersion
from app.db.models.assurance import AgentEvaluationRun, AgentEvaluationSuite
from app.db.repository import tenant_select
from app.services.context import Principal

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.schemas.assurance import AgentEvaluationRunCreateIn, AgentEvaluationSuiteCreateIn

_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_POSITIVE_METRICS = frozenset(
    {"task_completion_rate", "evidence_grounding_rate", "outcome_match_rate"}
)
_NEGATIVE_METRICS = frozenset(
    {
        "unsafe_action_rate",
        "human_correction_rate",
        "unsupported_claim_rate",
        "cost_per_verified_outcome_usd",
        "mean_verified_closure_seconds",
    }
)


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _decimal(value: Any, *, label: str) -> Decimal:
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{label} must be numeric") from exc
    if not number.is_finite() or number < 0:
        raise ValueError(f"{label} must be finite and non-negative")
    return number


@dataclass(frozen=True, slots=True)
class EvaluationSuiteManifest:
    dataset_digest: str
    case_count: int
    cases: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    metrics: dict[str, float | int | str | None]
    failed_thresholds: tuple[str, ...]
    case_results: tuple[dict[str, Any], ...]
    total_cost_usd: Decimal
    passed: bool


def build_suite_manifest(cases: list[dict[str, Any]]) -> EvaluationSuiteManifest:
    if not 1 <= len(cases) <= 10_000:
        raise ValueError("an evaluation suite must contain between 1 and 10000 cases")
    normalized: list[dict[str, Any]] = []
    keys: set[str] = set()
    for case in cases:
        case_key = str(case.get("case_key", "")).strip()
        if not case_key or len(case_key) > 128:
            raise ValueError("evaluation case keys must contain 1 to 128 characters")
        if case_key in keys:
            raise ValueError("evaluation case keys must be unique")
        keys.add(case_key)
        digest = str(case.get("expected_digest", ""))
        if not _DIGEST.fullmatch(digest):
            raise ValueError("expected_digest must be a SHA-256 hex digest")
        refs = sorted({str(value) for value in case.get("input_evidence_refs") or []})
        if not refs or len(refs) > 100 or any(len(value) > 1000 for value in refs):
            raise ValueError("evaluation cases require 1 to 100 bounded evidence references")
        tags = sorted({str(value)[:80] for value in case.get("tags") or []})[:30]
        normalized.append(
            {
                "case_key": case_key,
                "input_evidence_refs": refs,
                "expected_digest": digest,
                "tags": tags,
            }
        )
    normalized.sort(key=lambda item: item["case_key"])
    return EvaluationSuiteManifest(
        dataset_digest=canonical_digest(normalized),
        case_count=len(normalized),
        cases=tuple(normalized),
    )


def _validate_thresholds(thresholds: dict[str, Any]) -> dict[str, Decimal]:
    unknown = set(thresholds) - _POSITIVE_METRICS - _NEGATIVE_METRICS
    if unknown:
        raise ValueError(f"unsupported evaluation thresholds: {', '.join(sorted(unknown))}")
    result = {key: _decimal(value, label=key) for key, value in thresholds.items()}
    for key in (_POSITIVE_METRICS | {"unsafe_action_rate", "human_correction_rate", "unsupported_claim_rate"}):
        if key in result and result[key] > 1:
            raise ValueError(f"{key} must be between 0 and 1")
    return result


def evaluate_agent_outcomes(
    *,
    case_manifest: list[dict[str, Any]],
    results: list[dict[str, Any]],
    thresholds: dict[str, Any],
) -> EvaluationReport:
    manifest = build_suite_manifest(case_manifest)
    expected = {item["case_key"]: item["expected_digest"] for item in manifest.cases}
    result_keys = [str(item.get("case_key", "")) for item in results]
    if len(result_keys) != len(expected) or set(result_keys) != set(expected) or len(set(result_keys)) != len(result_keys):
        raise ValueError("evaluation requires exactly one result for every known case")
    safe_results: list[dict[str, Any]] = []
    total_cost = Decimal("0")
    total_unsafe = total_corrections = total_unsupported = total_verified = 0
    completion = grounding = matches = 0
    closure_times: list[int] = []
    for item in results:
        case_key = str(item["case_key"])
        outcome_digest = str(item.get("outcome_digest", ""))
        if not _DIGEST.fullmatch(outcome_digest):
            raise ValueError("outcome_digest must be a SHA-256 hex digest")
        unsafe = int(item.get("unsafe_actions", 0))
        corrections = int(item.get("human_corrections", 0))
        unsupported = int(item.get("unsupported_claims", 0))
        verified = int(item.get("verified_outcomes", 0))
        if min(unsafe, corrections, unsupported, verified) < 0:
            raise ValueError("evaluation counters must be non-negative")
        cost = _decimal(item.get("cost_usd", 0), label="cost_usd")
        closure = item.get("closure_seconds")
        if closure is not None:
            closure = int(closure)
            if closure < 0:
                raise ValueError("closure_seconds must be non-negative")
            closure_times.append(closure)
        completed = item.get("task_completed") is True
        grounded = item.get("evidence_grounded") is True
        matched = outcome_digest == expected[case_key]
        completion += int(completed)
        grounding += int(grounded)
        matches += int(matched)
        total_unsafe += unsafe
        total_corrections += corrections
        total_unsupported += unsupported
        total_verified += verified
        total_cost += cost
        safe_results.append(
            {
                "case_key": case_key,
                "outcome_digest": outcome_digest,
                "outcome_matched": matched,
                "task_completed": completed,
                "evidence_grounded": grounded,
                "unsafe_actions": unsafe,
                "human_corrections": corrections,
                "unsupported_claims": unsupported,
                "verified_outcomes": verified,
                "cost_usd": str(cost),
                "closure_seconds": closure,
            }
        )
    count = len(expected)
    metrics: dict[str, float | int | str | None] = {
        "case_count": count,
        "task_completion_rate": completion / count,
        "evidence_grounding_rate": grounding / count,
        "outcome_match_rate": matches / count,
        "unsafe_action_rate": total_unsafe / count,
        "human_correction_rate": total_corrections / count,
        "unsupported_claim_rate": total_unsupported / count,
        "verified_outcomes": total_verified,
        "cost_per_verified_outcome_usd": (
            str(total_cost / total_verified) if total_verified else None
        ),
        "mean_verified_closure_seconds": (
            sum(closure_times) / len(closure_times) if closure_times else None
        ),
    }
    bounded_thresholds = _validate_thresholds(thresholds)
    failed: list[str] = []
    for key, threshold in bounded_thresholds.items():
        value = metrics.get(key)
        if value is None:
            failed.append(key)
            continue
        measured = Decimal(str(value))
        if (key in _POSITIVE_METRICS and measured < threshold) or (
            key in _NEGATIVE_METRICS and measured > threshold
        ):
            failed.append(key)
    safe_results.sort(key=lambda item: item["case_key"])
    return EvaluationReport(
        metrics=metrics,
        failed_thresholds=tuple(sorted(failed)),
        case_results=tuple(safe_results),
        total_cost_usd=total_cost,
        passed=not failed,
    )


async def create_evaluation_suite(
    session: AsyncSession,
    principal: Principal,
    payload: AgentEvaluationSuiteCreateIn,
) -> AgentEvaluationSuite:
    principal.require(Permission.ORG_MANAGE)
    manifest = build_suite_manifest([case.model_dump(mode="json") for case in payload.cases])
    thresholds = {key: str(value) for key, value in _validate_thresholds(payload.thresholds).items()}
    existing = await session.scalar(
        tenant_select(AgentEvaluationSuite, principal.organization_id).where(
            AgentEvaluationSuite.suite_key == payload.suite_key,
            AgentEvaluationSuite.version == payload.version,
        )
    )
    if existing is not None:
        if existing.dataset_digest != manifest.dataset_digest:
            raise ConflictError("An immutable evaluation suite version cannot be overwritten")
        return existing
    row = AgentEvaluationSuite(
        organization_id=principal.organization_id,
        suite_key=payload.suite_key,
        name=payload.name,
        task_kind=payload.task_kind,
        version=payload.version,
        dataset_digest=manifest.dataset_digest,
        case_manifest=list(manifest.cases),
        thresholds=thresholds,
        active=True,
        created_by_id=principal.user_id,
    )
    session.add(row)
    await session.flush()
    return row


async def record_evaluation_run(
    session: AsyncSession,
    principal: Principal,
    payload: AgentEvaluationRunCreateIn,
) -> AgentEvaluationRun:
    principal.require(Permission.ORG_MANAGE)
    suite = await session.scalar(
        tenant_select(AgentEvaluationSuite, principal.organization_id).where(
            AgentEvaluationSuite.id == payload.suite_id,
            AgentEvaluationSuite.active.is_(True),
        )
    )
    if suite is None:
        raise ResourceNotFoundError("Active agent evaluation suite not found")
    version = await session.scalar(
        tenant_select(AgentDefinitionVersion, principal.organization_id).where(
            AgentDefinitionVersion.id == payload.agent_version_id
        )
    )
    if version is None:
        raise ResourceNotFoundError("Agent version not found")
    existing = await session.scalar(
        tenant_select(AgentEvaluationRun, principal.organization_id).where(
            AgentEvaluationRun.run_key == payload.run_key
        )
    )
    if existing is not None:
        return existing
    report = evaluate_agent_outcomes(
        case_manifest=list(suite.case_manifest),
        results=[result.model_dump(mode="json") for result in payload.results],
        thresholds=dict(suite.thresholds),
    )
    row = AgentEvaluationRun(
        organization_id=principal.organization_id,
        suite_id=suite.id,
        agent_version_id=version.id,
        run_key=payload.run_key,
        status="completed",
        metrics=report.metrics,
        failed_thresholds=list(report.failed_thresholds),
        case_results=list(report.case_results),
        passed=report.passed,
        total_cost_usd=report.total_cost_usd,
        completed_at=dt.datetime.now(dt.UTC),
    )
    session.add(row)
    await session.flush()
    return row


async def list_evaluation_suites(
    session: AsyncSession, principal: Principal, *, active_only: bool = True
) -> list[AgentEvaluationSuite]:
    principal.require(Permission.ORG_READ)
    query = tenant_select(AgentEvaluationSuite, principal.organization_id)
    if active_only:
        query = query.where(AgentEvaluationSuite.active.is_(True))
    rows = await session.scalars(
        query.order_by(AgentEvaluationSuite.suite_key, AgentEvaluationSuite.version.desc())
    )
    return list(rows.all())


async def list_evaluation_runs(
    session: AsyncSession,
    principal: Principal,
    *,
    suite_id: uuid.UUID | None = None,
    limit: int = 100,
) -> list[AgentEvaluationRun]:
    principal.require(Permission.ORG_READ)
    query = tenant_select(AgentEvaluationRun, principal.organization_id)
    if suite_id is not None:
        query = query.where(AgentEvaluationRun.suite_id == suite_id)
    rows = await session.scalars(
        query.order_by(AgentEvaluationRun.completed_at.desc()).limit(min(max(limit, 1), 500))
    )
    return list(rows.all())


__all__ = [
    "EvaluationReport",
    "EvaluationSuiteManifest",
    "build_suite_manifest",
    "canonical_digest",
    "create_evaluation_suite",
    "evaluate_agent_outcomes",
    "list_evaluation_runs",
    "list_evaluation_suites",
    "record_evaluation_run",
]
