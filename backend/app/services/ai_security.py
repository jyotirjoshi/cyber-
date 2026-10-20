"""Deterministic data classification and AI gateway protection.

Raw content exists only for the duration of the request. Durable records contain a
SHA-256 digest, length, reason codes, and policy decision—never the source text.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Literal

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.control_plane import SecurityEvent, SecurityPolicy, SecurityPolicyEvaluation
from app.db.repository import tenant_select
from app.schemas.control_plane import (
    AIGatewayEvaluateIn,
    AIGatewayEvaluateOut,
    DataClassificationOut,
    Severity,
)
from app.services.audit import record
from app.services.context import Principal

Sensitivity = Literal["public", "internal", "confidential", "restricted"]


@dataclass(frozen=True, slots=True)
class AIAuditProjection:
    content_digest: str
    content_length: int
    labels: tuple[str, ...]
    highest_sensitivity: str
    match_counts: dict[str, int]


_PATTERNS: tuple[tuple[str, str, Sensitivity], ...] = (
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "restricted"),
    ("aws_access_key", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "restricted"),
    ("bearer_token", r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}", "restricted"),
    ("password_assignment", r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[^\s,;]{4,}", "restricted"),
    ("us_ssn", r"\b\d{3}-\d{2}-\d{4}\b", "restricted"),
    ("payment_card", r"\b(?:\d[ -]*?){13,19}\b", "restricted"),
    ("email_address", r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "confidential"),
    ("ipv4_address", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "internal"),
)

_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"ignore\s+(?:all\s+)?previous\s+instructions",
        r"reveal\s+(?:the\s+)?system\s+prompt",
        r"(?:show|print|leak|exfiltrate).{0,40}(?:secret|api key|credential|token)",
        r"(?:developer|system)\s+message\s*[:=]",
        r"bypass.{0,30}(?:policy|guardrail|approval)",
        r"do\s+anything\s+now",
    )
)

_SENSITIVITY_RANK = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}


def _digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _valid_card(candidate: str) -> bool:
    digits = [int(char) for char in candidate if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def classify_sensitive_data(content: str) -> DataClassificationOut:
    labels: list[str] = []
    counts: dict[str, int] = {}
    sensitivity: Sensitivity = "public"
    redacted = content
    for label, pattern, level in _PATTERNS:
        compiled = re.compile(pattern, re.IGNORECASE)
        matches = list(compiled.finditer(content))
        if label == "payment_card":
            matches = [match for match in matches if _valid_card(match.group(0))]
        if not matches:
            continue
        labels.append(label)
        counts[label] = len(matches)
        if _SENSITIVITY_RANK[level] > _SENSITIVITY_RANK[sensitivity]:
            sensitivity = level
        # Re-evaluate against the progressively redacted text to avoid retaining a
        # second raw copy or managing overlapping indexes.
        if label == "payment_card":

            def redact_card(match: re.Match[str], replacement_label: str = label) -> str:
                return (
                    f"[REDACTED:{replacement_label}]"
                    if _valid_card(match.group(0))
                    else match.group(0)
                )

            redacted = compiled.sub(
                redact_card,
                redacted,
            )
        else:
            redacted = compiled.sub(f"[REDACTED:{label}]", redacted)
    return DataClassificationOut(
        labels=labels,
        highest_sensitivity=sensitivity,
        redacted_content=redacted,
        content_digest=_digest(content),
        match_counts=counts,
    )


def build_audit_projection(content: str, result: DataClassificationOut) -> AIAuditProjection:
    return AIAuditProjection(
        content_digest=result.content_digest,
        content_length=len(content),
        labels=tuple(result.labels),
        highest_sensitivity=result.highest_sensitivity,
        match_counts=dict(result.match_counts),
    )


def _has_prompt_injection(content: str) -> bool:
    bounded = content[:100_000]
    return any(pattern.search(bounded) for pattern in _INJECTION_PATTERNS)


def evaluate_ai_content(
    payload: AIGatewayEvaluateIn, *, policy_rules: dict[str, Any]
) -> AIGatewayEvaluateOut:
    classification = classify_sensitive_data(payload.content)
    reasons: list[str] = []
    score = Decimal("0")
    injection = payload.direction == "prompt" and _has_prompt_injection(payload.content)
    if injection:
        reasons.append("prompt_injection")
        score += Decimal("80")
    reasons.extend(classification.labels)
    if classification.highest_sensitivity == "restricted":
        score += Decimal("30")
    elif classification.highest_sensitivity == "confidential":
        score += Decimal("15")

    allowed_tools = set(policy_rules.get("allowed_tools", []))
    unapproved_tools = sorted(set(payload.tool_keys) - allowed_tools) if allowed_tools else []
    if unapproved_tools:
        reasons.append("unapproved_tool")
        score += Decimal("40")
    required_actions = set(policy_rules.get("require_approval_for_actions", []))
    action_needs_approval = payload.requested_action in required_actions
    if action_needs_approval:
        reasons.append("action_requires_approval")
        score += Decimal("30")

    if injection and policy_rules.get("block_prompt_injection", True):
        decision: Literal["allow", "block", "redact", "require_approval"] = "block"
    elif unapproved_tools or action_needs_approval:
        decision = "require_approval"
    elif classification.labels and policy_rules.get("redact_sensitive_data", True):
        decision = "redact"
    else:
        decision = "allow"
    score = min(Decimal("100"), score).quantize(Decimal("0.01"))
    severity: Severity = (
        "critical"
        if score >= 80
        else "high"
        if score >= 50
        else "medium"
        if score >= 20
        else "low"
        if score
        else "info"
    )
    return AIGatewayEvaluateOut(
        decision=decision,
        severity=severity,
        score=score,
        reasons=list(dict.fromkeys(reasons)),
        content_digest=classification.content_digest,
        redacted_content=classification.redacted_content if decision == "redact" else None,
        approval_required=decision == "require_approval",
    )


async def _resolve_policy(
    session: AsyncSession, principal: Principal, policy_id: uuid.UUID | None
) -> SecurityPolicy | None:
    query = tenant_select(SecurityPolicy, principal.organization_id).where(
        SecurityPolicy.kind.in_(("ai_gateway", "ai_guard")),
        SecurityPolicy.status == "active",
    )
    if policy_id is not None:
        query = query.where(SecurityPolicy.id == policy_id)
    policy = await session.scalar(query.order_by(SecurityPolicy.updated_at.desc()).limit(1))
    if policy_id is not None and policy is None:
        raise ResourceNotFoundError("AI security policy not found")
    return policy


async def evaluate_and_record(
    session: AsyncSession, principal: Principal, payload: AIGatewayEvaluateIn
) -> AIGatewayEvaluateOut:
    principal.require(Permission.ORG_READ)
    policy = await _resolve_policy(session, principal, payload.policy_id)
    result = evaluate_ai_content(payload, policy_rules=policy.rules if policy else {})
    event = SecurityEvent(
        organization_id=principal.organization_id,
        event_key=f"ai-gateway:{uuid.uuid4()}",
        category="ai_gateway",
        event_type=f"{payload.direction}_{result.decision}",
        source_kind="cynux_ai_gateway",
        occurred_at=dt.datetime.now(dt.UTC),
        severity=result.severity,
        summary=f"AI gateway {result.decision} decision",
        content_digest=result.content_digest,
        identity_ref=payload.agent_key,
        metrics={"content_length": len(payload.content), "score": str(result.score)},
        evidence={"reason_codes": result.reasons, "tool_count": len(payload.tool_keys)},
    )
    session.add(event)
    await session.flush()
    if policy is not None:
        session.add(
            SecurityPolicyEvaluation(
                organization_id=principal.organization_id,
                policy_id=policy.id,
                event_id=event.id,
                decision=result.decision,
                severity=result.severity,
                score=result.score,
                findings=[{"code": reason} for reason in result.reasons],
                evidence={"direction": payload.direction, "tool_count": len(payload.tool_keys)},
                content_digest=result.content_digest,
                evaluated_at=event.occurred_at,
            )
        )
    await record(
        session,
        action="control_plane.ai_gateway.evaluate",
        principal=principal,
        resource_type="security_event",
        resource_id=event.id,
        detail={
            "decision": result.decision,
            "severity": result.severity,
            "content_digest": result.content_digest,
            "reason_codes": result.reasons,
        },
    )
    return result


async def classify_and_record(
    session: AsyncSession,
    principal: Principal,
    content: str,
    *,
    resource_key: str | None = None,
) -> DataClassificationOut:
    principal.require(Permission.ORG_READ)
    result = classify_sensitive_data(content)
    event = SecurityEvent(
        organization_id=principal.organization_id,
        event_key=f"data-classification:{uuid.uuid4()}",
        category="dlp",
        event_type="content_classified",
        source_kind="cynux_data_security",
        occurred_at=dt.datetime.now(dt.UTC),
        severity="high"
        if result.highest_sensitivity == "restricted"
        else "medium"
        if result.labels
        else "info",
        summary="Transient content classified by data security policy",
        content_digest=result.content_digest,
        metrics={"content_length": len(content), "match_counts": result.match_counts},
        evidence={"labels": result.labels, "resource_key": resource_key},
    )
    session.add(event)
    await session.flush()
    await record(
        session,
        action="control_plane.data.classify",
        principal=principal,
        resource_type="security_event",
        resource_id=event.id,
        detail={"content_digest": result.content_digest, "labels": result.labels},
    )
    return result


__all__ = [
    "AIAuditProjection",
    "build_audit_projection",
    "classify_and_record",
    "classify_sensitive_data",
    "evaluate_ai_content",
    "evaluate_and_record",
]
