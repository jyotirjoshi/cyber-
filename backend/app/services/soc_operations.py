"""Deterministic SOC case lifecycle and bounded detection-rule evaluation."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, ResourceNotFoundError
from app.db.base import utcnow
from app.db.enums import Permission
from app.db.models.control_plane import SecurityEvent
from app.db.models.soc import DetectionRule, DetectionRuleMatch, SocCaseTask, SocIncidentCase
from app.db.repository import tenant_select
from app.schemas.soc import (
    DetectionCondition,
    DetectionRuleCreateIn,
    SocCaseCreateIn,
    SocCaseTaskCreateIn,
    SocCaseTransitionIn,
)
from app.services.context import Principal

_SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_TRANSITIONS = {
    "open": frozenset({"investigating", "dismissed"}),
    "investigating": frozenset({"contained", "resolved", "dismissed"}),
    "contained": frozenset({"investigating", "resolved"}),
    "resolved": frozenset({"investigating"}),
    "dismissed": frozenset({"investigating"}),
}
_MISSING = object()


@dataclass(frozen=True, slots=True)
class DetectionEvaluation:
    matched: bool
    matched_conditions: int
    total_conditions: int
    reason_codes: tuple[str, ...]


def _nested(source: object, path: str) -> object:
    current: object = source
    for part in path.split("."):
        if isinstance(current, Mapping):
            current = current.get(part, _MISSING)
        else:
            current = getattr(current, part, _MISSING)
        if current is _MISSING:
            break
    return current


def _condition_matches(actual: object, condition: DetectionCondition) -> bool:
    if condition.operator == "exists":
        expected = True if condition.value is None else bool(condition.value)
        return (actual is not _MISSING) is expected
    if actual is _MISSING:
        return False
    expected = condition.value
    if condition.operator == "eq":
        return actual == expected
    if condition.operator == "ne":
        return actual != expected
    if condition.operator == "in":
        return isinstance(expected, list | tuple | set) and actual in expected
    if condition.operator == "contains":
        return isinstance(actual, str | list | tuple | set | dict) and expected in actual
    if condition.operator in {"gte", "lte"}:
        if isinstance(actual, bool) or isinstance(expected, bool):
            return False
        if not isinstance(actual, int | float) or not isinstance(expected, int | float):
            return False
        return actual >= expected if condition.operator == "gte" else actual <= expected
    return False


def evaluate_detection_rule(
    event: object,
    *,
    categories: Sequence[str],
    event_types: Sequence[str],
    minimum_severity: str,
    conditions: Sequence[DetectionCondition],
) -> DetectionEvaluation:
    reasons: list[str] = []
    if categories and getattr(event, "category", None) not in categories:
        reasons.append("category_mismatch")
    if event_types and getattr(event, "event_type", None) not in event_types:
        reasons.append("event_type_mismatch")
    event_severity = str(getattr(event, "severity", "info"))
    if _SEVERITY.get(event_severity, -1) < _SEVERITY.get(minimum_severity, 0):
        reasons.append("severity_below_minimum")

    matched_conditions = 0
    for index, condition in enumerate(conditions):
        root: object = event if condition.source == "event" else getattr(event, condition.source, {})
        actual = _nested(root, condition.path)
        if actual is _MISSING and condition.operator != "exists":
            reasons.append(f"condition_{index}_missing")
        elif _condition_matches(actual, condition):
            matched_conditions += 1
        else:
            reasons.append(f"condition_{index}_failed")
    return DetectionEvaluation(
        matched=not reasons and matched_conditions == len(conditions),
        matched_conditions=matched_conditions,
        total_conditions=len(conditions),
        reason_codes=tuple(reasons),
    )


def detection_case_key(rule_key: str, event: object, *, group_by: Sequence[str]) -> str:
    """Return a stable, opaque case key without persisting sensitive group values."""

    values = [
        _nested(event, field.removeprefix("event."))
        if not field.startswith(("metrics.", "evidence."))
        else _nested(getattr(event, field.split(".", 1)[0], {}), field.split(".", 1)[1])
        for field in group_by
    ]
    if not group_by:
        values = [str(getattr(event, "id", getattr(event, "event_key", "ungrouped")))]
    normalized = [None if value is _MISSING else value for value in values]
    digest = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()[:24]
    return f"detection:{rule_key}:{digest}"


def validate_case_transition(current: str, target: str) -> None:
    if target == current:
        return
    if target not in _TRANSITIONS.get(current, frozenset()):
        raise ConflictError(f"Cannot transition SOC case from {current} to {target}")


async def list_cases(
    session: AsyncSession, principal: Principal, *, limit: int, offset: int
) -> tuple[list[SocIncidentCase], int]:
    principal.require(Permission.ORG_READ)
    base = tenant_select(SocIncidentCase, principal.organization_id)
    total = int((await session.scalar(base.with_only_columns(func.count()))) or 0)
    rows = list(
        (
            await session.scalars(
                base.order_by(SocIncidentCase.priority.desc(), SocIncidentCase.updated_at.desc())
                .limit(limit)
                .offset(offset)
            )
        ).all()
    )
    return rows, total


async def create_case(
    session: AsyncSession, principal: Principal, payload: SocCaseCreateIn
) -> SocIncidentCase:
    principal.require(Permission.INTEGRATION_MANAGE)
    existing = await session.scalar(
        tenant_select(SocIncidentCase, principal.organization_id).where(
            SocIncidentCase.case_key == payload.case_key
        )
    )
    if existing is not None:
        raise ConflictError("A SOC case with that key already exists")
    now = utcnow()
    row = SocIncidentCase(
        organization_id=principal.organization_id,
        case_key=payload.case_key,
        title=payload.title,
        summary=payload.summary,
        severity=payload.severity,
        priority=payload.priority,
        assigned_user_id=payload.assigned_user_id,
        owner_team=payload.owner_team,
        event_ids=[str(value) for value in payload.event_ids],
        asset_ids=[str(value) for value in payload.asset_ids],
        finding_ids=[str(value) for value in payload.finding_ids],
        evidence_refs=payload.evidence_refs,
        timeline=[{"at": now.isoformat(), "action": "opened", "actor_id": str(principal.user_id) if principal.user_id else None}],
        opened_at=now,
    )
    session.add(row)
    await session.flush()
    return row


async def transition_case(
    session: AsyncSession,
    principal: Principal,
    case_id: uuid.UUID,
    payload: SocCaseTransitionIn,
) -> SocIncidentCase:
    principal.require(Permission.INTEGRATION_MANAGE)
    row = await session.scalar(
        tenant_select(SocIncidentCase, principal.organization_id).where(SocIncidentCase.id == case_id)
    )
    if row is None:
        raise ResourceNotFoundError("SOC case not found")
    validate_case_transition(row.status, payload.status)
    now = utcnow()
    row.status = payload.status
    row.timeline = [
        *row.timeline,
        {"at": now.isoformat(), "action": "status_changed", "status": payload.status, "note": payload.note, "actor_id": str(principal.user_id) if principal.user_id else None},
    ]
    if payload.status == "contained":
        row.contained_at = now
    if payload.status in {"resolved", "dismissed"}:
        row.resolved_at = now
        row.resolution = payload.resolution or payload.note
    await session.flush()
    return row


async def create_case_task(
    session: AsyncSession,
    principal: Principal,
    case_id: uuid.UUID,
    payload: SocCaseTaskCreateIn,
) -> SocCaseTask:
    principal.require(Permission.INTEGRATION_MANAGE)
    case = await session.scalar(
        tenant_select(SocIncidentCase, principal.organization_id).where(SocIncidentCase.id == case_id)
    )
    if case is None:
        raise ResourceNotFoundError("SOC case not found")
    task = SocCaseTask(
        organization_id=principal.organization_id,
        case_id=case_id,
        title=payload.title,
        description=payload.description,
        assigned_user_id=payload.assigned_user_id,
        due_at=payload.due_at,
        evidence_refs=payload.evidence_refs,
    )
    session.add(task)
    await session.flush()
    return task


async def list_rules(
    session: AsyncSession, principal: Principal, *, limit: int, offset: int
) -> tuple[list[DetectionRule], int]:
    principal.require(Permission.ORG_READ)
    base = tenant_select(DetectionRule, principal.organization_id)
    total = int((await session.scalar(base.with_only_columns(func.count()))) or 0)
    rows = list((await session.scalars(base.order_by(DetectionRule.updated_at.desc()).limit(limit).offset(offset))).all())
    return rows, total


async def create_rule(
    session: AsyncSession, principal: Principal, payload: DetectionRuleCreateIn
) -> DetectionRule:
    principal.require(Permission.INTEGRATION_MANAGE)
    existing = await session.scalar(
        tenant_select(DetectionRule, principal.organization_id).where(DetectionRule.rule_key == payload.rule_key)
    )
    if existing is not None:
        raise ConflictError("A detection rule with that key already exists")
    row = DetectionRule(
        organization_id=principal.organization_id,
        rule_key=payload.rule_key,
        name=payload.name,
        description=payload.description,
        status=payload.status,
        severity=payload.severity,
        minimum_event_severity=payload.minimum_event_severity,
        categories=payload.categories,
        event_types=payload.event_types,
        conditions=[item.model_dump(mode="json") for item in payload.conditions],
        group_by=payload.group_by,
        auto_create_case=payload.auto_create_case,
        created_by_id=principal.user_id,
    )
    session.add(row)
    await session.flush()
    return row


async def dry_run_rule(
    session: AsyncSession,
    principal: Principal,
    rule_id: uuid.UUID,
    *,
    event_ids: Sequence[uuid.UUID],
    limit: int,
) -> tuple[DetectionRule, list[tuple[SecurityEvent, DetectionEvaluation]]]:
    principal.require(Permission.ORG_READ)
    rule = await session.scalar(
        tenant_select(DetectionRule, principal.organization_id).where(DetectionRule.id == rule_id)
    )
    if rule is None:
        raise ResourceNotFoundError("Detection rule not found")
    query = tenant_select(SecurityEvent, principal.organization_id)
    if event_ids:
        query = query.where(SecurityEvent.id.in_(event_ids))
    events = list((await session.scalars(query.order_by(SecurityEvent.occurred_at.desc()).limit(limit))).all())
    conditions = [DetectionCondition.model_validate(item) for item in rule.conditions]
    return rule, [
        (
            event,
            evaluate_detection_rule(
                event,
                categories=rule.categories,
                event_types=rule.event_types,
                minimum_severity=rule.minimum_event_severity,
                conditions=conditions,
            ),
        )
        for event in events
    ]


async def evaluate_rule(
    session: AsyncSession,
    principal: Principal,
    rule_id: uuid.UUID,
    *,
    event_ids: Sequence[uuid.UUID],
    limit: int,
) -> tuple[DetectionRule, list[tuple[SecurityEvent, DetectionEvaluation]]]:
    """Persist idempotent matches and converge grouped signals into durable cases."""

    principal.require(Permission.INTEGRATION_MANAGE)
    rule, results = await dry_run_rule(
        session, principal, rule_id, event_ids=event_ids, limit=limit
    )
    if rule.status != "active":
        raise ConflictError("Only active detection rules can create matches")
    now = utcnow()
    for event, result in results:
        if not result.matched:
            continue
        existing_match = await session.scalar(
            tenant_select(DetectionRuleMatch, principal.organization_id).where(
                DetectionRuleMatch.rule_id == rule.id,
                DetectionRuleMatch.event_id == event.id,
            )
        )
        if existing_match is not None:
            continue
        case: SocIncidentCase | None = None
        if rule.auto_create_case:
            case_key = detection_case_key(rule.rule_key, event, group_by=rule.group_by)
            case = await session.scalar(
                tenant_select(SocIncidentCase, principal.organization_id).where(
                    SocIncidentCase.case_key == case_key
                )
            )
            if case is None:
                case = SocIncidentCase(
                    organization_id=principal.organization_id,
                    case_key=case_key,
                    title=f"{rule.name}: {event.summary[:180]}",
                    summary=f"Detection rule {rule.rule_key} matched {event.event_type} from {event.source_kind}.",
                    severity=rule.severity,
                    priority=20 + _SEVERITY[rule.severity] * 20,
                    event_ids=[str(event.id)],
                    asset_ids=[str(event.asset_id)] if event.asset_id else [],
                    evidence_refs=[{"kind": "security_event", "id": str(event.id)}],
                    timeline=[{"at": now.isoformat(), "action": "created_by_detection", "rule_id": str(rule.id), "event_id": str(event.id)}],
                    opened_at=now,
                )
                session.add(case)
                await session.flush()
            else:
                event_id = str(event.id)
                if event_id not in case.event_ids:
                    case.event_ids = [*case.event_ids, event_id]
                    case.timeline = [*case.timeline, {"at": now.isoformat(), "action": "detection_correlated", "rule_id": str(rule.id), "event_id": event_id}]
                if case.status in {"resolved", "dismissed"}:
                    case.status = "investigating"
                    case.resolved_at = None
                    case.resolution = None
        match = DetectionRuleMatch(
            organization_id=principal.organization_id,
            rule_id=rule.id,
            event_id=event.id,
            case_id=case.id if case else None,
            matched_at=now,
            evidence={"matched_conditions": result.matched_conditions, "total_conditions": result.total_conditions},
        )
        session.add(match)
        rule.last_matched_at = now
    await session.flush()
    return rule, results

