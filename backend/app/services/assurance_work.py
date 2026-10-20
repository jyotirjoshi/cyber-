"""Immutable work records and bounded, replayable validation recipes."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from app.core.errors import ConflictError, ResourceNotFoundError
from app.core.logging_conf import redact_mapping
from app.db.enums import Permission
from app.db.models.agent import AgentRun
from app.db.models.assessment import AssessmentTarget
from app.db.models.assurance import AgentRunAssurance, ValidationRecipe
from app.db.models.canonical import AttackSimulationCampaign, AttackSimulationRun
from app.db.repository import tenant_select
from app.services.context import Principal

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.schemas.assurance import (
        AgentRunAssuranceCreateIn,
        AgentRunAssuranceFinalizeIn,
        ValidationRecipeCreateIn,
        ValidationRecipeVerifyIn,
    )

SAFE_VALIDATION_ACTIONS = frozenset(
    {
        "http_request",
        "assert_response",
        "browser_navigate",
        "browser_fill",
        "browser_click",
        "browser_assert",
        "dns_lookup",
        "tcp_connect",
        "tls_handshake",
        "cloud_read",
        "code_query",
    }
)
SAFE_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _decimal(value: str | int | float | Decimal, label: str) -> Decimal:
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{label} must be numeric") from exc
    if not number.is_finite() or number < 0:
        raise ValueError(f"{label} must be finite and non-negative")
    return number


@dataclass(slots=True)
class AgentWorkRecord:
    plan_version: int
    plan_digest: str
    input_evidence_refs: list[str]
    budgets: dict[str, Any]
    success_criteria: list[dict[str, Any]]
    tool_receipts: list[dict[str, Any]] = field(default_factory=list)
    artifact_refs: list[str] = field(default_factory=list)
    contradictory_evidence: list[dict[str, Any]] = field(default_factory=list)
    verifier_status: str = "pending"
    verifier_result: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)
    replay_digest: str | None = None
    finalized_at: dt.datetime | None = None


@dataclass(slots=True)
class GovernedValidationRecipe:
    recipe_key: str
    target_digest: str
    authorized_target_refs: list[str]
    actions: list[dict[str, Any]]
    budgets: dict[str, int]
    approval_refs: list[str]
    artifact_refs: list[str] = field(default_factory=list)
    evidence_hashes: list[str] = field(default_factory=list)
    exploitation_verdict: str = "observed"
    reproducibility_score: float = 0.0
    status: str = "approved"
    verification: dict[str, Any] = field(default_factory=dict)
    verified_at: dt.datetime | None = None


def _validate_budgets(budgets: dict[str, Any]) -> dict[str, Any]:
    required = ("max_tool_calls", "max_seconds", "max_cost_usd")
    missing = [key for key in required if key not in budgets]
    if missing:
        raise ValueError(f"missing budgets: {', '.join(missing)}")
    tool_calls = int(budgets["max_tool_calls"])
    seconds = int(budgets["max_seconds"])
    cost = _decimal(budgets["max_cost_usd"], "max_cost_usd")
    if not 1 <= tool_calls <= 10_000:
        raise ValueError("max_tool_calls must be between 1 and 10000")
    if not 1 <= seconds <= 172_800:
        raise ValueError("max_seconds must be between 1 and 172800")
    return {"max_tool_calls": tool_calls, "max_seconds": seconds, "max_cost_usd": str(cost)}


def create_agent_record(
    *,
    plan: dict[str, Any],
    input_evidence_refs: Iterable[str],
    budgets: dict[str, Any],
    success_criteria: list[dict[str, Any]],
) -> AgentWorkRecord:
    version = int(plan.get("version", 0))
    if version < 1:
        raise ValueError("plan version must be positive")
    if not success_criteria:
        raise ValueError("at least one success criterion is required")
    return AgentWorkRecord(
        plan_version=version,
        plan_digest=canonical_digest(plan),
        input_evidence_refs=sorted(set(input_evidence_refs)),
        budgets=_validate_budgets(budgets),
        success_criteria=success_criteria,
    )


def _outcome_metrics(labels: Iterable[str]) -> dict[str, float | int]:
    values = list(labels)
    true_positive = values.count("true_positive")
    false_positive = values.count("false_positive")
    true_negative = values.count("true_negative")
    false_negative = values.count("false_negative")
    precision_denominator = true_positive + false_positive
    recall_denominator = true_positive + false_negative
    return {
        "true_positive": true_positive,
        "false_positive": false_positive,
        "true_negative": true_negative,
        "false_negative": false_negative,
        "precision": true_positive / precision_denominator if precision_denominator else 0.0,
        "recall": true_positive / recall_denominator if recall_denominator else 0.0,
    }


def finalize_agent_record(
    record: AgentWorkRecord | Any,
    *,
    tool_receipts: list[dict[str, Any]],
    artifact_refs: list[str],
    contradictory_evidence: list[dict[str, Any]],
    verifier_result: dict[str, Any],
    outcome_labels: Iterable[str],
    elapsed_seconds: int,
    cost_usd: str | int | float | Decimal,
    now: dt.datetime | None = None,
) -> None:
    if record.finalized_at is not None:
        raise ConflictError("Agent work record is already finalized")
    if len(tool_receipts) > int(record.budgets["max_tool_calls"]):
        raise ConflictError("Agent exceeded its tool-call budget")
    if elapsed_seconds > int(record.budgets["max_seconds"]):
        raise ConflictError("Agent exceeded its runtime budget")
    cost = _decimal(cost_usd, "cost_usd")
    if cost > _decimal(record.budgets["max_cost_usd"], "max_cost_usd"):
        raise ConflictError("Agent exceeded its cost budget")
    status = str(verifier_result.get("status", ""))
    if status not in {"passed", "failed", "inconclusive"}:
        raise ValueError("verifier status is invalid")
    safe_receipts = [
        {
            "tool": str(receipt.get("tool", ""))[:240],
            "status": str(receipt.get("status", "unknown"))[:40],
            "digest": str(receipt.get("digest") or canonical_digest(receipt)),
        }
        for receipt in tool_receipts
    ]
    metrics = _outcome_metrics(outcome_labels)
    metrics.update({"elapsed_seconds": elapsed_seconds, "cost_usd": str(cost)})
    record.tool_receipts = safe_receipts
    record.artifact_refs = sorted(set(artifact_refs))
    record.contradictory_evidence = contradictory_evidence
    record.verifier_status = status
    record.verifier_result = verifier_result
    record.metrics = metrics
    record.replay_digest = canonical_digest(
        {
            "plan_digest": record.plan_digest,
            "input_evidence_refs": record.input_evidence_refs,
            "tool_receipts": safe_receipts,
            "artifact_refs": record.artifact_refs,
            "verifier_result": verifier_result,
        }
    )
    record.finalized_at = now or dt.datetime.now(dt.UTC)


def _normalize_target(target: str) -> str:
    parsed = urlsplit(target)
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}{port}"
    if parsed.scheme in {"network", "aws", "azure", "gcp", "repo"} and (
        parsed.netloc or parsed.path
    ):
        if parsed.username or parsed.password or parsed.fragment:
            raise ValueError("validation target references cannot include credentials or fragments")
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}".rstrip("/")
    raise ValueError("validation targets must use an approved web, network, cloud, or repo scheme")


def _validate_action(action: dict[str, Any]) -> dict[str, Any]:
    kind = str(action.get("kind", ""))
    if kind not in SAFE_VALIDATION_ACTIONS:
        raise ValueError(f"validation action {kind!r} is not allow-listed")
    if any(key in action for key in ("command", "shell", "script", "image", "base_url", "url")):
        raise ValueError("validation actions cannot provide executable commands or arbitrary URLs")
    normalized = json.loads(json.dumps(action))
    if kind == "http_request":
        method = str(action.get("method", "GET")).upper()
        path = str(action.get("path", "/"))
        if method not in SAFE_HTTP_METHODS:
            raise ValueError("HTTP method is not allow-listed")
        if not path.startswith("/") or "://" in path or len(path) > 2048:
            raise ValueError("HTTP validation paths must be bounded relative paths")
        normalized["method"] = method
        normalized["path"] = path
    return normalized


def build_validation_recipe(
    *,
    recipe_key: str,
    authorized_targets: Iterable[str],
    requested_targets: Iterable[str],
    actions: list[dict[str, Any]],
    budgets: dict[str, int],
    approval_refs: list[str],
) -> GovernedValidationRecipe:
    approved = sorted({_normalize_target(target) for target in authorized_targets})
    requested = sorted({_normalize_target(target) for target in requested_targets})
    if not requested or not set(requested).issubset(approved):
        raise ConflictError("One or more validation targets are outside the approved scope")
    if not approval_refs:
        raise ConflictError("Validation requires an approval reference")
    max_actions = int(budgets.get("max_actions", 0))
    max_requests = int(budgets.get("max_requests", 0))
    max_seconds = int(budgets.get("max_seconds", 0))
    if not (1 <= max_actions <= 1000 and 1 <= max_requests <= 100_000 and 1 <= max_seconds <= 86_400):
        raise ValueError("validation budgets are missing or out of range")
    if not actions or len(actions) > max_actions:
        raise ConflictError("Validation actions exceed the approved action budget")
    normalized_actions = [_validate_action(action) for action in actions]
    return GovernedValidationRecipe(
        recipe_key=recipe_key,
        target_digest=canonical_digest(requested),
        authorized_target_refs=requested,
        actions=normalized_actions,
        budgets={
            "max_actions": max_actions,
            "max_requests": max_requests,
            "max_seconds": max_seconds,
        },
        approval_refs=sorted(set(approval_refs)),
    )


def append_validation_evidence(
    recipe: GovernedValidationRecipe | Any, *, artifact_ref: str, content: bytes
) -> str:
    if recipe.status not in {"approved", "executing"}:
        raise ConflictError(f"Cannot append evidence to a {recipe.status} recipe")
    previous = recipe.evidence_hashes[-1] if recipe.evidence_hashes else "0" * 64
    digest = hashlib.sha256(previous.encode() + b"\x00" + content).hexdigest()
    recipe.artifact_refs.append(artifact_ref)
    recipe.evidence_hashes.append(digest)
    recipe.status = "executing"
    return digest


def verify_validation_recipe(
    recipe: GovernedValidationRecipe | Any,
    *,
    action_results: list[dict[str, Any]],
    exploitation_verdict: str,
    now: dt.datetime | None = None,
) -> None:
    if recipe.status != "executing":
        raise ConflictError(f"Cannot verify a {recipe.status} recipe")
    if exploitation_verdict not in {
        "observed",
        "likely_exploitable",
        "proved_exploitable",
        "not_exploitable",
    }:
        raise ValueError("invalid exploitation verdict")
    expected = len(recipe.actions)
    passed = sum(result.get("passed") is True for result in action_results)
    completed = min(len(action_results), expected)
    evidence_coverage = min(len(recipe.evidence_hashes), expected)
    score = 100 * ((passed / expected) * 0.7 + (evidence_coverage / expected) * 0.3)
    recipe.exploitation_verdict = exploitation_verdict
    recipe.reproducibility_score = round(score, 2)
    recipe.verification = {
        "expected_actions": expected,
        "completed_actions": completed,
        "passed_actions": passed,
        "chain_head": recipe.evidence_hashes[-1] if recipe.evidence_hashes else None,
    }
    recipe.status = "verified" if completed == expected else "failed"
    recipe.verified_at = now or dt.datetime.now(dt.UTC)


def confidence_from_evidence(
    *, supporting: Iterable[dict[str, Any]], contradicting: Iterable[dict[str, Any]]
) -> dict[str, Any]:
    support = sum(float(item.get("weight", 0)) for item in supporting)
    contradiction = sum(float(item.get("weight", 0)) for item in contradicting)
    total = support + contradiction
    confidence = support / total if total else 0.0
    reasons = ["contradictory_evidence_present"] if contradiction else []
    if not total:
        reasons.append("insufficient_evidence")
    return {"confidence": round(confidence, 4), "reason_codes": reasons}


async def create_agent_assurance(
    session: AsyncSession, principal: Principal, payload: AgentRunAssuranceCreateIn
) -> AgentRunAssurance:
    principal.require(Permission.AGENT_CHAT)
    run = await session.scalar(
        tenant_select(AgentRun, principal.organization_id).where(AgentRun.id == payload.run_id)
    )
    if run is None:
        raise ResourceNotFoundError("Agent run not found")
    existing = await session.scalar(
        tenant_select(AgentRunAssurance, principal.organization_id).where(
            AgentRunAssurance.run_id == payload.run_id
        )
    )
    if existing is not None:
        if existing.plan_digest != payload.plan_digest:
            raise ConflictError("Agent assurance plan is immutable")
        return existing
    row = AgentRunAssurance(
        organization_id=principal.organization_id,
        run_id=payload.run_id,
        plan_version=payload.plan_version,
        plan_digest=payload.plan_digest,
        input_evidence_refs=sorted(set(payload.input_evidence_refs)),
        budgets=_validate_budgets(payload.budgets),
        success_criteria=payload.success_criteria,
        confidence=Decimal("0"),
    )
    session.add(row)
    await session.flush()
    return row


async def finalize_agent_assurance(
    session: AsyncSession,
    principal: Principal,
    assurance_id: uuid.UUID,
    payload: AgentRunAssuranceFinalizeIn,
) -> AgentRunAssurance:
    principal.require(Permission.AGENT_CHAT)
    row = await session.scalar(
        tenant_select(AgentRunAssurance, principal.organization_id)
        .where(AgentRunAssurance.id == assurance_id)
        .with_for_update()
    )
    if row is None:
        raise ResourceNotFoundError("Agent assurance record not found")
    metrics = dict(payload.metrics)
    finalize_agent_record(
        row,
        tool_receipts=payload.tool_receipts,
        artifact_refs=payload.artifact_refs,
        contradictory_evidence=[redact_mapping(item) for item in payload.contradictory_evidence],
        verifier_result=redact_mapping(payload.verifier_result),
        outcome_labels=list(metrics.get("outcome_labels") or []),
        elapsed_seconds=int(metrics.get("elapsed_seconds", 0)),
        cost_usd=metrics.get("cost_usd", "0"),
    )
    row.approval_refs = sorted(set(payload.approval_refs))
    row.confidence = payload.confidence
    row.reason_codes = list(dict.fromkeys(payload.reason_codes))
    await session.flush()
    return row


async def _authorized_targets(
    session: AsyncSession, principal: Principal, payload: ValidationRecipeCreateIn
) -> list[str]:
    if payload.campaign_id is not None:
        campaign = await session.scalar(
            tenant_select(AttackSimulationCampaign, principal.organization_id).where(
                AttackSimulationCampaign.id == payload.campaign_id
            )
        )
        if campaign is None:
            raise ResourceNotFoundError("Validation campaign not found")
        if campaign.authorization_expires_at <= dt.datetime.now(dt.UTC):
            raise ConflictError("Validation campaign authorization expired")
        return list(campaign.targets)
    if payload.run_id is not None:
        run = await session.scalar(
            tenant_select(AttackSimulationRun, principal.organization_id).where(
                AttackSimulationRun.id == payload.run_id
            )
        )
        if run is None:
            raise ResourceNotFoundError("Validation run not found")
        return list(run.targets_snapshot)
    if payload.assessment_id is not None:
        rows = await session.scalars(
            tenant_select(AssessmentTarget, principal.organization_id).where(
                AssessmentTarget.assessment_id == payload.assessment_id
            )
        )
        targets = [row.canonical_value for row in rows.all()]
        if not targets:
            raise ResourceNotFoundError("Assessment targets not found")
        return targets
    raise ConflictError("Validation recipe must reference an assessment, campaign, or run")


async def create_validation_recipe(
    session: AsyncSession, principal: Principal, payload: ValidationRecipeCreateIn
) -> ValidationRecipe:
    principal.require(Permission.INTEGRATION_MANAGE)
    existing = await session.scalar(
        tenant_select(ValidationRecipe, principal.organization_id).where(
            ValidationRecipe.recipe_key == payload.recipe_key
        )
    )
    if existing is not None:
        return existing
    approved_targets = await _authorized_targets(session, principal, payload)
    built = build_validation_recipe(
        recipe_key=payload.recipe_key,
        authorized_targets=approved_targets,
        requested_targets=payload.targets,
        actions=payload.actions,
        budgets=payload.budgets,
        approval_refs=payload.approval_refs,
    )
    row = ValidationRecipe(
        organization_id=principal.organization_id,
        recipe_key=payload.recipe_key,
        assessment_id=payload.assessment_id,
        campaign_id=payload.campaign_id,
        run_id=payload.run_id,
        original_recipe_id=payload.original_recipe_id,
        target_digest=built.target_digest,
        authorized_target_refs=built.authorized_target_refs,
        actions=built.actions,
        credential_refs=sorted(set(payload.credential_refs)),
        artifact_refs=sorted(set(payload.artifact_refs)),
        evidence_hashes=payload.evidence_hashes,
        budgets=built.budgets,
        approval_refs=built.approval_refs,
        exploitation_verdict=payload.exploitation_verdict,
        reproducibility_score=Decimal("0"),
        status="approved",
    )
    session.add(row)
    await session.flush()
    return row


async def verify_persisted_validation_recipe(
    session: AsyncSession,
    principal: Principal,
    recipe_id: uuid.UUID,
    payload: ValidationRecipeVerifyIn,
) -> ValidationRecipe:
    principal.require(Permission.INTEGRATION_MANAGE)
    row = await session.scalar(
        tenant_select(ValidationRecipe, principal.organization_id)
        .where(ValidationRecipe.id == recipe_id)
        .with_for_update()
    )
    if row is None:
        raise ResourceNotFoundError("Validation recipe not found")
    if row.status == "approved":
        row.status = "executing"
    verify_validation_recipe(
        row,
        action_results=payload.action_results,
        exploitation_verdict=payload.exploitation_verdict,
    )
    await session.flush()
    return row


__all__ = [
    "AgentWorkRecord",
    "GovernedValidationRecipe",
    "SAFE_VALIDATION_ACTIONS",
    "append_validation_evidence",
    "build_validation_recipe",
    "canonical_digest",
    "confidence_from_evidence",
    "create_agent_record",
    "create_agent_assurance",
    "create_validation_recipe",
    "finalize_agent_record",
    "finalize_agent_assurance",
    "verify_persisted_validation_recipe",
    "verify_validation_recipe",
]
