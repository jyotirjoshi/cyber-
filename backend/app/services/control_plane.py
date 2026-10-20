"""CAASM reconciliation, deterministic policy evaluation, and posture operations."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import ConflictError, ResourceNotFoundError
from app.core.logging_conf import redact_mapping, redact_text
from app.db.enums import Permission
from app.db.models.asset import Asset
from app.db.models.business_risk import BusinessRiskScenario, BusinessService
from app.db.models.control_plane import (
    SecurityCanary,
    SecurityCanaryInteraction,
    SecurityEvent,
    SecurityPolicy,
    SecurityPolicyEvaluation,
    SecurityRecommendation,
    SecurityResource,
    SecurityResourceObservation,
    SecurityRiskSimulation,
    SecurityThreatStory,
)
from app.db.models.integration import Integration
from app.db.repository import tenant_select
from app.schemas.control_plane import (
    CanaryInteractionIn,
    DeceptionCanaryCreateIn,
    RiskSimulationCreateIn,
    SecurityEventIn,
    SecurityPolicyCreateIn,
    SecurityRecommendationDecisionIn,
    SecurityResourceUpsertIn,
)
from app.services.audit import record
from app.services.context import Principal

_MONEY = Decimal("0.01")
_CONFIDENCE = Decimal("0.001")


def safe_metadata(value: dict[str, Any]) -> dict[str, Any]:
    """Redact credential-shaped keys and values before durable storage."""

    return redact_mapping(value)


def observation_fingerprint(source_kind: str, source_key: str, attributes: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"source_kind": source_kind, "source_key": source_key, "attributes": attributes},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def calculate_identity_confidence(
    observations: list[tuple[Decimal, dt.datetime]],
    *,
    now: dt.datetime | None = None,
) -> Decimal:
    """Combine independent-source confidence while decaying stale observations."""

    current = now or dt.datetime.now(dt.UTC)
    miss_probability = Decimal("1")
    for confidence, observed_at in observations:
        age = current - observed_at
        weight = Decimal("1")
        if age > dt.timedelta(days=30):
            weight = Decimal("0.25")
        elif age > dt.timedelta(days=7):
            weight = Decimal("0.65")
        adjusted = min(Decimal("1"), max(Decimal("0"), confidence * weight))
        miss_probability *= Decimal("1") - adjusted
    return (Decimal("1") - miss_probability).quantize(_CONFIDENCE, rounding=ROUND_HALF_UP)


def reconcile_resource_values(
    *, current: dict[str, Any], observed: dict[str, Any]
) -> dict[str, Any]:
    """Merge source metadata without erasing curated ownership and classification."""

    merged = dict(current)
    protected = {"owner_team", "environment", "approved"}
    for key, value in observed.items():
        if key == "attributes":
            merged[key] = {**current.get(key, {}), **safe_metadata(value or {})}
        elif key in protected and (value is None or value == "unknown"):
            continue
        elif value is not None:
            merged[key] = value
    return merged


def evaluate_resource_policy(*, resource: dict[str, Any], rules: dict[str, Any]) -> dict[str, Any]:
    """Evaluate the bounded rule vocabulary; no model output participates in decisions."""

    findings: list[dict[str, Any]] = []
    score = Decimal("0")
    if rules.get("require_approved") and resource.get("approved") is not True:
        findings.append({"code": "unapproved_resource", "message": "Resource is not approved"})
        score += Decimal("35")
    denied = set(rules.get("deny_internet_exposed_sensitivities", []))
    if resource.get("internet_exposed") and resource.get("sensitivity") in denied:
        findings.append(
            {
                "code": "sensitive_resource_exposed",
                "message": "Sensitive resource is internet exposed",
            }
        )
        score += Decimal("40")
    max_risk = rules.get("max_risk_score")
    if max_risk is not None and Decimal(str(resource.get("risk_score", 0))) > Decimal(
        str(max_risk)
    ):
        findings.append({"code": "risk_threshold_exceeded", "message": "Risk score exceeds policy"})
        score += Decimal("25")
    required_owner = bool(rules.get("require_owner"))
    if required_owner and not resource.get("owner_team"):
        findings.append({"code": "owner_missing", "message": "Resource has no accountable owner"})
        score += Decimal("20")
    score = min(Decimal("100"), score).quantize(_MONEY)
    if score >= 80:
        severity, decision = "critical", "block"
    elif score >= 50:
        severity, decision = "high", "require_approval"
    elif score > 0:
        severity, decision = "medium", "recommend"
    else:
        severity, decision = "info", "allow"
    return {"decision": decision, "severity": severity, "score": score, "findings": findings}


def next_recommendation_status(current: str, action: str) -> str:
    transitions = {
        ("proposed", "approve"): "approved",
        ("proposed", "reject"): "rejected",
        ("approved", "reject"): "rejected",
        ("approved", "apply"): "applying",
        ("failed", "apply"): "applying",
    }
    next_status = transitions.get((current, action))
    if next_status is None:
        raise ConflictError(f"Cannot {action} a {current} recommendation")
    return next_status


def correlation_key_for_event(
    *,
    organization_id: uuid.UUID,
    occurred_at: dt.datetime,
    asset_id: uuid.UUID | None,
    resource_id: uuid.UUID | None,
    identity_ref: str | None,
) -> str:
    """Create an opaque, stable 24-hour correlation window for related signals."""

    anchor = (
        f"identity:{identity_ref.casefold()}"
        if identity_ref
        else f"asset:{asset_id}"
        if asset_id
        else f"resource:{resource_id}"
        if resource_id
        else "unattributed"
    )
    bucket = int(occurred_at.timestamp()) // 86_400
    raw = f"{organization_id}:{anchor}:{bucket}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def merge_story_values(
    current: dict[str, Any],
    *,
    event_id: str,
    asset_id: str | None,
    identity_ref: str | None,
    occurred_at: dt.datetime,
    severity: str,
    event_type: str,
) -> dict[str, Any]:
    merged = dict(current)
    merged["event_ids"] = list(dict.fromkeys([*current.get("event_ids", []), event_id]))
    merged["asset_ids"] = list(
        dict.fromkeys([*current.get("asset_ids", []), *([asset_id] if asset_id else [])])
    )
    merged["identity_refs"] = list(
        dict.fromkeys(
            [*current.get("identity_refs", []), *([identity_ref] if identity_ref else [])]
        )
    )
    timeline = [*current.get("timeline", [])]
    if event_id not in {str(item.get("event_id")) for item in timeline}:
        timeline.append(
            {
                "event_id": event_id,
                "event_type": event_type,
                "occurred_at": occurred_at.isoformat(),
                "severity": severity,
            }
        )
    merged["timeline"] = sorted(timeline, key=lambda item: str(item["occurred_at"]))
    merged["severity"] = max(
        (str(current.get("severity", "info")), severity), key=lambda item: _SEVERITY_ORDER[item]
    )
    return merged


def calculate_experience_score(
    *, availability: float, latency_ms: float, error_rate: float
) -> Decimal:
    availability_score = Decimal(str(max(0.0, min(1.0, availability)))) * Decimal("50")
    latency_ratio = min(1.0, max(0.0, latency_ms) / 1800.0)
    latency_score = Decimal(str(1.0 - latency_ratio)) * Decimal("30")
    error_penalty = min(1.0, max(0.0, error_rate) * 12.5)
    error_score = Decimal(str(1.0 - error_penalty)) * Decimal("20")
    return (availability_score + latency_score + error_score).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )


def canary_digest(token: str) -> str:
    return hashlib.sha256(f"cynux-canary:{token}".encode()).hexdigest()


def source_address_digest(address: str) -> str:
    return hashlib.sha256(f"cynux-source:{address.casefold()}".encode()).hexdigest()


async def _assert_optional_refs(
    session: AsyncSession, principal: Principal, payload: SecurityResourceUpsertIn
) -> None:
    if payload.asset_id is not None:
        asset = await session.scalar(
            tenant_select(Asset, principal.organization_id).where(Asset.id == payload.asset_id)
        )
        if asset is None:
            raise ResourceNotFoundError("Asset not found")
    if payload.integration_id is not None:
        integration = await session.scalar(
            tenant_select(Integration, principal.organization_id).where(
                Integration.id == payload.integration_id
            )
        )
        if integration is None:
            raise ResourceNotFoundError("Integration not found")


async def upsert_resource(
    session: AsyncSession, principal: Principal, payload: SecurityResourceUpsertIn
) -> SecurityResource:
    principal.require(Permission.INTEGRATION_MANAGE)
    await _assert_optional_refs(session, principal, payload)
    now = dt.datetime.now(dt.UTC)
    resource = await session.scalar(
        tenant_select(SecurityResource, principal.organization_id)
        .where(SecurityResource.resource_key == payload.resource_key)
        .with_for_update()
    )
    observed_values = {
        "kind": payload.kind,
        "name": payload.name.strip(),
        "provider": payload.provider,
        "external_id": payload.external_id,
        "asset_id": payload.asset_id,
        "owner_team": payload.owner_team,
        "environment": payload.environment,
        "internet_exposed": payload.internet_exposed,
        "approved": payload.approved,
        "sensitivity": payload.sensitivity,
        "classifications": sorted(set(payload.classifications)),
        "permissions": safe_metadata(payload.permissions),
        "attributes": safe_metadata(payload.attributes),
        "provenance": safe_metadata(payload.provenance),
    }
    if resource is None:
        resource = SecurityResource(
            organization_id=principal.organization_id,
            resource_key=payload.resource_key,
            posture_status="unknown",
            risk_score=Decimal("0"),
            source_count=0,
            identity_confidence=Decimal("0"),
            first_seen_at=payload.observed_at,
            last_seen_at=payload.observed_at,
            **observed_values,
        )
        session.add(resource)
        await session.flush()
    else:
        current = {key: getattr(resource, key) for key in observed_values}
        for key, value in reconcile_resource_values(
            current=current, observed=observed_values
        ).items():
            setattr(resource, key, value)
        resource.first_seen_at = min(resource.first_seen_at, payload.observed_at)
        resource.last_seen_at = max(resource.last_seen_at, payload.observed_at)

    fingerprint = observation_fingerprint(
        payload.source_kind, payload.source_key, safe_metadata(payload.attributes)
    )
    observation = await session.scalar(
        tenant_select(SecurityResourceObservation, principal.organization_id).where(
            SecurityResourceObservation.source_kind == payload.source_kind,
            SecurityResourceObservation.source_key == payload.source_key,
            SecurityResourceObservation.fingerprint == fingerprint,
        )
    )
    if observation is None:
        observation = SecurityResourceObservation(
            organization_id=principal.organization_id,
            resource_id=resource.id,
            integration_id=payload.integration_id,
            source_kind=payload.source_kind,
            source_key=payload.source_key,
            fingerprint=fingerprint,
            observed_at=payload.observed_at,
            expires_at=payload.expires_at,
            confidence=payload.confidence,
            attributes=safe_metadata(payload.attributes),
            provenance=safe_metadata(payload.provenance),
        )
        session.add(observation)
    else:
        observation.resource_id = resource.id
        observation.integration_id = payload.integration_id
        observation.observed_at = max(observation.observed_at, payload.observed_at)
        observation.expires_at = payload.expires_at
        observation.confidence = payload.confidence
        observation.attributes = safe_metadata(payload.attributes)
        observation.provenance = safe_metadata(payload.provenance)
    await session.flush()

    observations = list(
        (
            await session.scalars(
                tenant_select(SecurityResourceObservation, principal.organization_id).where(
                    SecurityResourceObservation.resource_id == resource.id
                )
            )
        ).all()
    )
    resource.source_count = len({item.source_kind for item in observations})
    resource.identity_confidence = calculate_identity_confidence(
        [(Decimal(str(item.confidence)), item.observed_at) for item in observations], now=now
    )
    active = [item for item in observations if item.expires_at is None or item.expires_at >= now]
    if not active:
        resource.posture_status = "inactive"
    elif resource.approved is False or (
        resource.internet_exposed and resource.sensitivity in {"confidential", "restricted"}
    ):
        resource.posture_status = "non_compliant"
    elif Decimal(str(resource.risk_score)) >= 70:
        resource.posture_status = "at_risk"
    else:
        resource.posture_status = "healthy"
    await session.flush()
    await record(
        session,
        action="control_plane.resource.upsert",
        principal=principal,
        resource_type="security_resource",
        resource_id=resource.id,
        detail={"kind": resource.kind, "source_kind": payload.source_kind},
    )
    return resource


async def list_resources(
    session: AsyncSession,
    principal: Principal,
    *,
    kind: str | None = None,
    posture_status: str | None = None,
    limit: int = 200,
) -> list[SecurityResource]:
    principal.require(Permission.ORG_READ)
    query = tenant_select(SecurityResource, principal.organization_id)
    if kind:
        query = query.where(SecurityResource.kind == kind)
    if posture_status:
        query = query.where(SecurityResource.posture_status == posture_status)
    rows = await session.scalars(query.order_by(SecurityResource.risk_score.desc()).limit(limit))
    return list(rows.all())


async def posture_summary(session: AsyncSession, principal: Principal) -> dict[str, Any]:
    resources = await list_resources(session, principal, limit=10_000)
    observations = list(
        (
            await session.scalars(
                tenant_select(SecurityResourceObservation, principal.organization_id)
            )
        ).all()
    )
    now = dt.datetime.now(dt.UTC)
    source_coverage: dict[str, int] = {}
    for observation in observations:
        source_coverage[observation.source_kind] = (
            source_coverage.get(observation.source_kind, 0) + 1
        )
    kind_coverage: dict[str, int] = {}
    for resource in resources:
        kind_coverage[resource.kind] = kind_coverage.get(resource.kind, 0) + 1
    ai_kinds = {"ai_application", "ai_model", "ai_agent", "mcp_server", "ai_tool"}
    confidences = [Decimal(str(item.identity_confidence)) for item in resources]
    average = sum(confidences, Decimal("0")) / max(1, len(confidences))
    return {
        "total_resources": len(resources),
        "active_sources": len(source_coverage),
        "stale_resources": sum(
            1 for item in resources if item.last_seen_at < now - dt.timedelta(days=30)
        ),
        "unknown_owner": sum(1 for item in resources if not item.owner_team),
        "internet_exposed": sum(1 for item in resources if item.internet_exposed),
        "non_compliant": sum(1 for item in resources if item.posture_status == "non_compliant"),
        "at_risk": sum(1 for item in resources if item.posture_status == "at_risk"),
        "approved_ai": sum(
            1 for item in resources if item.kind in ai_kinds and item.approved is True
        ),
        "unapproved_ai": sum(
            1 for item in resources if item.kind in ai_kinds and item.approved is not True
        ),
        "source_coverage": source_coverage,
        "kind_coverage": kind_coverage,
        "average_identity_confidence": average.quantize(_CONFIDENCE, rounding=ROUND_HALF_UP),
    }


async def create_policy(
    session: AsyncSession, principal: Principal, payload: SecurityPolicyCreateIn
) -> SecurityPolicy:
    principal.require(Permission.INTEGRATION_MANAGE)
    duplicate = await session.scalar(
        tenant_select(SecurityPolicy, principal.organization_id).where(
            SecurityPolicy.name == payload.name.strip()
        )
    )
    if duplicate is not None:
        raise ConflictError("A policy with this name already exists")
    if payload.integration_id:
        integration = await session.scalar(
            tenant_select(Integration, principal.organization_id).where(
                Integration.id == payload.integration_id
            )
        )
        if integration is None:
            raise ResourceNotFoundError("Integration not found")
    row = SecurityPolicy(
        organization_id=principal.organization_id,
        name=payload.name.strip(),
        kind=payload.kind,
        mode=payload.mode,
        status="active",
        version=1,
        rules=safe_metadata(payload.rules),
        integration_id=payload.integration_id,
        created_by_id=principal.user_id,
    )
    session.add(row)
    await session.flush()
    await record(
        session,
        action="control_plane.policy.create",
        principal=principal,
        resource_type="security_policy",
        resource_id=row.id,
        detail={"kind": row.kind, "mode": row.mode},
    )
    return row


async def list_policies(session: AsyncSession, principal: Principal) -> list[SecurityPolicy]:
    principal.require(Permission.ORG_READ)
    rows = await session.scalars(
        tenant_select(SecurityPolicy, principal.organization_id).order_by(SecurityPolicy.name)
    )
    return list(rows.all())


async def evaluate_policy(
    session: AsyncSession, principal: Principal, policy_id: uuid.UUID
) -> list[SecurityPolicyEvaluation]:
    principal.require(Permission.INTEGRATION_MANAGE)
    policy = await session.scalar(
        tenant_select(SecurityPolicy, principal.organization_id).where(
            SecurityPolicy.id == policy_id
        )
    )
    if policy is None:
        raise ResourceNotFoundError("Policy not found")
    resources = await list_resources(session, principal, limit=10_000)
    now = dt.datetime.now(dt.UTC)
    results: list[SecurityPolicyEvaluation] = []
    for resource in resources:
        decision = evaluate_resource_policy(resource=resource.as_dict(), rules=policy.rules)
        evaluation = SecurityPolicyEvaluation(
            organization_id=principal.organization_id,
            policy_id=policy.id,
            resource_id=resource.id,
            decision=decision["decision"],
            severity=decision["severity"],
            score=decision["score"],
            findings=decision["findings"],
            evidence={"policy_version": policy.version, "resource_key": resource.resource_key},
            evaluated_at=now,
        )
        session.add(evaluation)
        results.append(evaluation)
        if decision["decision"] != "allow":
            key = hashlib.sha256(
                f"{policy.id}:{policy.version}:{resource.id}:{decision['decision']}".encode()
            ).hexdigest()[:128]
            existing = await session.scalar(
                tenant_select(SecurityRecommendation, principal.organization_id).where(
                    SecurityRecommendation.idempotency_key == key
                )
            )
            if existing is None:
                enforcement_actions = {
                    "ztna": "zpa.update_application_access",
                    "secure_web_gateway": "zia.update_url_filter_rule",
                    "firewall": "zia.update_firewall_rule",
                }
                session.add(
                    SecurityRecommendation(
                        organization_id=principal.organization_id,
                        policy_id=policy.id,
                        resource_id=resource.id,
                        asset_id=resource.asset_id,
                        integration_id=policy.integration_id,
                        domain=policy.kind
                        if policy.kind in {"ztna", "secure_web_gateway", "firewall"}
                        else "ai_security"
                        if policy.kind in {"ai_gateway", "ai_guard"}
                        else "data_security",
                        title=f"Resolve {policy.name} violation on {resource.name}",
                        rationale="; ".join(item["message"] for item in decision["findings"]),
                        action=enforcement_actions.get(policy.kind, f"remediate_{policy.kind}"),
                        severity=decision["severity"],
                        status="proposed",
                        current_state={"posture_status": resource.posture_status},
                        desired_state={
                            "policy_decision": "allow",
                            "target_external_id": resource.external_id,
                        },
                        idempotency_key=key,
                        provider_receipt={},
                        created_by_id=principal.user_id,
                    )
                )
    await session.flush()
    await record(
        session,
        action="control_plane.policy.evaluate",
        principal=principal,
        resource_type="security_policy",
        resource_id=policy.id,
        detail={"evaluated_resources": len(results)},
    )
    return results


async def list_recommendations(
    session: AsyncSession, principal: Principal, *, status: str | None = None
) -> list[SecurityRecommendation]:
    principal.require(Permission.ORG_READ)
    query = tenant_select(SecurityRecommendation, principal.organization_id)
    if status:
        query = query.where(SecurityRecommendation.status == status)
    rows = await session.scalars(
        query.order_by(SecurityRecommendation.created_at.desc()).limit(500)
    )
    return list(rows.all())


async def decide_recommendation(
    session: AsyncSession,
    principal: Principal,
    recommendation_id: uuid.UUID,
    payload: SecurityRecommendationDecisionIn,
) -> SecurityRecommendation:
    principal.require(Permission.INTEGRATION_MANAGE)
    row = await session.scalar(
        tenant_select(SecurityRecommendation, principal.organization_id)
        .where(SecurityRecommendation.id == recommendation_id)
        .with_for_update()
    )
    if row is None:
        raise ResourceNotFoundError("Recommendation not found")
    row.status = next_recommendation_status(row.status, payload.decision)
    await session.flush()
    await record(
        session,
        action=f"control_plane.recommendation.{payload.decision}",
        principal=principal,
        resource_type="security_recommendation",
        resource_id=row.id,
        detail={"status": row.status, "note": payload.note},
    )
    return row


async def _correlate_event(
    session: AsyncSession, principal: Principal, event: SecurityEvent
) -> SecurityThreatStory:
    key = correlation_key_for_event(
        organization_id=principal.organization_id,
        occurred_at=event.occurred_at,
        asset_id=event.asset_id,
        resource_id=event.resource_id,
        identity_ref=event.identity_ref,
    )
    story = await session.scalar(
        tenant_select(SecurityThreatStory, principal.organization_id)
        .where(SecurityThreatStory.correlation_key == key)
        .with_for_update()
    )
    event_id = str(event.id)
    asset_id = str(event.asset_id) if event.asset_id else None
    if story is None:
        story = SecurityThreatStory(
            organization_id=principal.organization_id,
            correlation_key=key,
            title="Correlated security activity",
            status="open",
            severity=event.severity,
            confidence=Decimal("0.450"),
            summary="Related security signals require analyst review.",
            event_ids=[],
            asset_ids=[],
            finding_ids=[],
            identity_refs=[],
            timeline=[],
            first_seen_at=event.occurred_at,
            last_seen_at=event.occurred_at,
        )
        session.add(story)
    merged = merge_story_values(
        {
            "event_ids": story.event_ids,
            "asset_ids": story.asset_ids,
            "identity_refs": story.identity_refs,
            "timeline": story.timeline,
            "severity": story.severity,
        },
        event_id=event_id,
        asset_id=asset_id,
        identity_ref=event.identity_ref,
        occurred_at=event.occurred_at,
        severity=event.severity,
        event_type=event.event_type,
    )
    story.event_ids = merged["event_ids"]
    story.asset_ids = merged["asset_ids"]
    story.identity_refs = merged["identity_refs"]
    story.timeline = merged["timeline"]
    story.severity = merged["severity"]
    story.first_seen_at = min(story.first_seen_at, event.occurred_at)
    story.last_seen_at = max(story.last_seen_at, event.occurred_at)
    story.confidence = min(
        Decimal("0.990"), Decimal("0.350") + Decimal("0.100") * len(story.event_ids)
    )
    await session.flush()
    return story


async def ingest_event(
    session: AsyncSession, principal: Principal, payload: SecurityEventIn
) -> SecurityEvent:
    principal.require(Permission.INTEGRATION_MANAGE)
    existing = await session.scalar(
        tenant_select(SecurityEvent, principal.organization_id).where(
            SecurityEvent.event_key == payload.event_key
        )
    )
    if existing is not None:
        return existing
    if payload.asset_id is not None:
        asset = await session.scalar(
            tenant_select(Asset, principal.organization_id).where(Asset.id == payload.asset_id)
        )
        if asset is None:
            raise ResourceNotFoundError("Asset not found")
    if payload.resource_id is not None:
        resource = await session.scalar(
            tenant_select(SecurityResource, principal.organization_id).where(
                SecurityResource.id == payload.resource_id
            )
        )
        if resource is None:
            raise ResourceNotFoundError("Security resource not found")
    event = SecurityEvent(
        organization_id=principal.organization_id,
        event_key=payload.event_key,
        category=payload.category,
        event_type=payload.event_type,
        source_kind=payload.source_kind,
        occurred_at=payload.occurred_at,
        severity=payload.severity,
        summary=redact_text(payload.summary),
        content_digest=payload.content_digest,
        asset_id=payload.asset_id,
        resource_id=payload.resource_id,
        identity_ref=payload.identity_ref,
        metrics=safe_metadata(payload.metrics),
        evidence=safe_metadata(payload.evidence),
    )
    session.add(event)
    await session.flush()
    if payload.category in {"incident", "identity", "deception", "access", "endpoint"}:
        await _correlate_event(session, principal, event)
    await record(
        session,
        action="control_plane.event.ingest",
        principal=principal,
        resource_type="security_event",
        resource_id=event.id,
        detail={"category": event.category, "event_type": event.event_type},
    )
    return event


async def list_events(
    session: AsyncSession,
    principal: Principal,
    *,
    category: str | None = None,
    limit: int = 200,
) -> list[SecurityEvent]:
    principal.require(Permission.ORG_READ)
    query = tenant_select(SecurityEvent, principal.organization_id)
    if category:
        query = query.where(SecurityEvent.category == category)
    rows = await session.scalars(query.order_by(SecurityEvent.occurred_at.desc()).limit(limit))
    return list(rows.all())


async def list_threat_stories(
    session: AsyncSession, principal: Principal, *, status: str | None = None
) -> list[SecurityThreatStory]:
    principal.require(Permission.ORG_READ)
    query = tenant_select(SecurityThreatStory, principal.organization_id)
    if status:
        query = query.where(SecurityThreatStory.status == status)
    rows = await session.scalars(query.order_by(SecurityThreatStory.last_seen_at.desc()).limit(500))
    return list(rows.all())


async def experience_summary(session: AsyncSession, principal: Principal) -> dict[str, Any]:
    events = await list_events(session, principal, category="experience", limit=10_000)
    scores: list[Decimal] = []
    journeys: set[str] = set()
    degraded: set[str] = set()
    for event in events:
        metrics = event.metrics
        score = calculate_experience_score(
            availability=float(metrics.get("availability", 0)),
            latency_ms=float(metrics.get("latency_ms", 0)),
            error_rate=float(metrics.get("error_rate", 0)),
        )
        scores.append(score)
        journey = str(metrics.get("journey_key", event.event_type))
        journeys.add(journey)
        if score < 70:
            degraded.add(journey)
    average = (sum(scores, Decimal("0")) / len(scores) if scores else Decimal("0")).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )
    impact = (
        "unknown"
        if not scores
        else "critical"
        if average < 30
        else "high"
        if average < 50
        else "moderate"
        if average < 70
        else "low"
    )
    return {
        "event_count": len(events),
        "monitored_journeys": len(journeys),
        "degraded_journeys": len(degraded),
        "average_score": average,
        "business_impact": impact,
        "latest_at": max((event.occurred_at for event in events), default=None),
    }


async def create_canary(
    session: AsyncSession, principal: Principal, payload: DeceptionCanaryCreateIn
) -> SecurityCanary:
    principal.require(Permission.INTEGRATION_MANAGE)
    if payload.asset_id is not None:
        asset = await session.scalar(
            tenant_select(Asset, principal.organization_id).where(Asset.id == payload.asset_id)
        )
        if asset is None:
            raise ResourceNotFoundError("Asset not found")
    duplicate = await session.scalar(
        tenant_select(SecurityCanary, principal.organization_id).where(
            SecurityCanary.name == payload.name.strip()
        )
    )
    if duplicate is not None:
        raise ConflictError("A canary with this name already exists")
    row = SecurityCanary(
        organization_id=principal.organization_id,
        name=payload.name.strip(),
        kind=payload.kind,
        token_digest=canary_digest(payload.token),
        asset_id=payload.asset_id,
        status="active",
        placement=safe_metadata(payload.placement),
    )
    session.add(row)
    await session.flush()
    await record(
        session,
        action="control_plane.canary.create",
        principal=principal,
        resource_type="security_canary",
        resource_id=row.id,
        detail={"kind": row.kind},
    )
    return row


async def list_canaries(session: AsyncSession, principal: Principal) -> list[SecurityCanary]:
    principal.require(Permission.ORG_READ)
    rows = await session.scalars(
        tenant_select(SecurityCanary, principal.organization_id).order_by(SecurityCanary.name)
    )
    return list(rows.all())


async def record_canary_interaction(
    session: AsyncSession,
    principal: Principal,
    canary_id: uuid.UUID,
    payload: CanaryInteractionIn,
) -> SecurityCanaryInteraction:
    principal.require(Permission.INTEGRATION_MANAGE)
    canary = await session.scalar(
        tenant_select(SecurityCanary, principal.organization_id)
        .where(SecurityCanary.id == canary_id)
        .with_for_update()
    )
    if canary is None:
        raise ResourceNotFoundError("Canary not found")
    existing = await session.scalar(
        tenant_select(SecurityCanaryInteraction, principal.organization_id).where(
            SecurityCanaryInteraction.interaction_key == payload.interaction_key
        )
    )
    if existing is not None:
        return existing
    event = await ingest_event(
        session,
        principal,
        SecurityEventIn(
            event_key=f"canary:{payload.interaction_key}",
            category="deception",
            event_type="canary_triggered",
            source_kind="cynux_deception",
            occurred_at=payload.occurred_at,
            severity=payload.severity,
            summary=f"{canary.kind} canary interaction detected",
            asset_id=canary.asset_id,
            identity_ref=payload.identity_ref,
            evidence={"canary_id": str(canary.id), **safe_metadata(payload.evidence)},
        ),
    )
    interaction = SecurityCanaryInteraction(
        organization_id=principal.organization_id,
        canary_id=canary.id,
        event_id=event.id,
        interaction_key=payload.interaction_key,
        occurred_at=payload.occurred_at,
        source_ip_digest=source_address_digest(payload.source_ip) if payload.source_ip else None,
        identity_ref=payload.identity_ref,
        protocol=payload.protocol,
        severity=payload.severity,
        evidence=safe_metadata(payload.evidence),
    )
    session.add(interaction)
    canary.status = "triggered"
    canary.last_triggered_at = payload.occurred_at
    await session.flush()
    return interaction


async def create_risk_simulation(
    session: AsyncSession, principal: Principal, payload: RiskSimulationCreateIn
) -> SecurityRiskSimulation:
    principal.require(Permission.ASSET_TAG)
    if payload.business_service_id is not None:
        business_service = await session.scalar(
            tenant_select(BusinessService, principal.organization_id).where(
                BusinessService.id == payload.business_service_id
            )
        )
        if business_service is None:
            raise ResourceNotFoundError("Business service not found")
    if payload.scenario_id is not None:
        scenario = await session.scalar(
            tenant_select(BusinessRiskScenario, principal.organization_id).where(
                BusinessRiskScenario.id == payload.scenario_id
            )
        )
        if scenario is None:
            raise ResourceNotFoundError("Business risk scenario not found")
    row = SecurityRiskSimulation(
        organization_id=principal.organization_id,
        status="completed",
        acceptance_status="unreviewed",
        narrative=None,
        created_by_id=principal.user_id,
        **payload.model_dump(),
    )
    row.narrative = (
        f"Expected residual annual loss is {row.residual_annual_loss}; controls reduce "
        f"the modeled inherent annual loss by {row.control_effectiveness * 100} percent."
    )
    session.add(row)
    await session.flush()
    await record(
        session,
        action="control_plane.risk.simulate",
        principal=principal,
        resource_type="security_risk_simulation",
        resource_id=row.id,
        detail={"residual_annual_loss": str(row.residual_annual_loss)},
    )
    return row


async def list_risk_simulations(
    session: AsyncSession, principal: Principal
) -> list[SecurityRiskSimulation]:
    principal.require(Permission.ORG_READ)
    rows = await session.scalars(
        tenant_select(SecurityRiskSimulation, principal.organization_id).order_by(
            SecurityRiskSimulation.created_at.desc()
        )
    )
    return list(rows.all())


__all__ = [
    "calculate_experience_score",
    "calculate_identity_confidence",
    "canary_digest",
    "correlation_key_for_event",
    "create_canary",
    "create_policy",
    "create_risk_simulation",
    "decide_recommendation",
    "evaluate_policy",
    "evaluate_resource_policy",
    "experience_summary",
    "ingest_event",
    "list_canaries",
    "list_events",
    "list_policies",
    "list_recommendations",
    "list_resources",
    "list_risk_simulations",
    "list_threat_stories",
    "merge_story_values",
    "next_recommendation_status",
    "observation_fingerprint",
    "posture_summary",
    "reconcile_resource_values",
    "safe_metadata",
    "source_address_digest",
    "record_canary_interaction",
    "upsert_resource",
]
