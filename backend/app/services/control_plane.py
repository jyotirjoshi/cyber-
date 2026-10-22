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
    PrivateAccessEvaluateIn,
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


def evaluate_private_access_policy(
    *, request: dict[str, Any], rules: dict[str, Any], policy_mode: str
) -> dict[str, Any]:
    """Make a deterministic, default-deny private-application access decision.

    Identity and device claims are expected to have been attested by the caller. The
    evaluator is deliberately pure so the API, endpoint gateway, and connector agents
    all apply exactly the same policy semantics.
    """

    def values(name: str, source: dict[str, Any]) -> set[str]:
        raw = source.get(name, [])
        if isinstance(raw, str):
            raw = [raw]
        if not isinstance(raw, list):
            return set()
        return {str(value).strip().casefold() for value in raw if str(value).strip()}

    identity = str(request.get("identity_ref", "")).strip().casefold()
    groups = values("groups", request)
    application_tags = values("application_tags", request)
    posture = values("device_posture", request)
    country = str(request.get("source_country", "")).strip().upper()
    denied_identities = values("denied_identities", rules)
    denied_groups = values("denied_groups", rules)
    allowed_identities = values("allowed_identities", rules)
    allowed_groups = values("allowed_groups", rules)
    required_tags = values("required_application_tags", rules)
    required_posture = values("required_device_posture", rules)
    allowed_countries = {value.upper() for value in values("allowed_countries", rules)}
    denied_countries = {value.upper() for value in values("denied_countries", rules)}

    violations: list[str] = []
    if identity and identity in denied_identities:
        violations.append("identity_denied")
    if groups & denied_groups:
        violations.append("group_denied")
    if country and country in denied_countries:
        violations.append("country_denied")
    if allowed_countries and country not in allowed_countries:
        violations.append("country_not_allowed")
    for tag in sorted(required_tags - application_tags):
        violations.append(f"application_tag_missing:{tag}")
    for signal in sorted(required_posture - posture):
        violations.append(f"device_posture_failed:{signal}")
    if rules.get("require_mfa") is True and request.get("mfa") is not True:
        violations.append("mfa_required")

    max_risk = rules.get("max_identity_risk_score")
    if max_risk is not None:
        risk = Decimal(str(request.get("identity_risk_score", 100)))
        if risk > Decimal(str(max_risk)):
            violations.append("identity_risk_exceeded")

    allow_reason: str | None = None
    if identity and identity in allowed_identities:
        allow_reason = "explicit_identity_allow"
    elif groups & allowed_groups:
        allow_reason = "explicit_group_allow"
    elif str(rules.get("default_action", "deny")).casefold() == "allow":
        allow_reason = "default_allow"

    would_block = bool(violations) or allow_reason is None
    reason_codes = violations or (["no_explicit_allow"] if allow_reason is None else [allow_reason])
    enforced = policy_mode == "enforce"
    requested_minutes = max(1, int(request.get("requested_session_minutes", 15)))
    maximum_minutes = max(1, int(rules.get("max_session_minutes", requested_minutes)))
    return {
        "decision": "deny" if would_block and enforced else "allow",
        "enforced": enforced,
        "would_block": would_block,
        "session_minutes": min(requested_minutes, maximum_minutes),
        "reason_codes": reason_codes,
    }


_AI_RESOURCE_KINDS = frozenset({"ai_application", "ai_model", "ai_agent", "mcp_server", "ai_tool"})


def evaluate_native_ai_posture(resource: dict[str, Any]) -> dict[str, Any]:
    """Assess AI assets using Cynux-owned posture logic and normalized metadata.

    This evaluator is intentionally connector- and model-independent.  A resource can be
    entered by a user, discovered by a Cynux collector, or produced by an agent and is then
    assessed with the same bounded rule vocabulary.
    """

    if resource.get("kind") not in _AI_RESOURCE_KINDS:
        return {
            "decision": "not_applicable",
            "severity": "info",
            "score": Decimal("0.00"),
            "findings": [],
            "recommended_controls": [],
        }

    findings: list[dict[str, Any]] = []
    controls: list[str] = []
    score = Decimal("0")

    def add(code: str, message: str, weight: str, control: str) -> None:
        nonlocal score
        findings.append({"code": code, "message": message, "weight": weight})
        controls.append(control)
        score += Decimal(weight)

    attributes = resource.get("attributes") or {}
    permissions = resource.get("permissions") or {}
    if not isinstance(attributes, dict):
        attributes = {}
    if not isinstance(permissions, dict):
        permissions = {}

    if resource.get("approved") is not True:
        add(
            "unapproved_ai_resource",
            "AI resource has not completed organizational approval",
            "20",
            "Complete owner and security approval before production use",
        )
    if not resource.get("owner_team"):
        add(
            "ai_owner_missing",
            "AI resource has no accountable owner",
            "10",
            "Assign an accountable team and escalation contact",
        )
    if resource.get("internet_exposed") and resource.get("sensitivity") in {
        "confidential",
        "restricted",
    }:
        add(
            "sensitive_ai_endpoint_exposed",
            "Internet-exposed AI resource handles sensitive data",
            "25",
            "Restrict network exposure or place the endpoint behind governed access",
        )

    authentication = str(attributes.get("authentication", "")).strip().casefold()
    if resource.get("internet_exposed") and authentication in {"", "none", "anonymous"}:
        add(
            "anonymous_ai_access",
            "Internet-exposed AI resource does not declare strong authentication",
            "20",
            "Require workload identity or SSO and disable anonymous access",
        )

    principals = permissions.get("principals", [])
    if isinstance(principals, str):
        principals = [principals]
    if isinstance(principals, list) and any(
        str(value).strip().casefold() in {"*", "all", "public", "anonymous"} for value in principals
    ):
        add(
            "wildcard_principal",
            "AI resource grants access to a wildcard or public principal",
            "20",
            "Replace wildcard access with named least-privilege identities",
        )

    scopes = permissions.get("tool_scopes", [])
    if isinstance(scopes, str):
        scopes = [scopes]
    privileged_scopes = {"admin", "owner", "root", "write", "execute", "*"}
    if isinstance(scopes, list) and any(
        str(value).strip().casefold() in privileged_scopes for value in scopes
    ):
        add(
            "privileged_tool_scope",
            "AI resource can invoke privileged tool operations",
            "15",
            "Limit tool scopes and require approval for state-changing operations",
        )

    data_connections = attributes.get("data_connections", [])
    if isinstance(data_connections, dict):
        data_connections = [data_connections]
    if isinstance(data_connections, list) and any(
        isinstance(item, dict) and item.get("reviewed") is not True for item in data_connections
    ):
        add(
            "unreviewed_data_connection",
            "AI resource has a data connection without a completed review",
            "15",
            "Review, classify, and approve each connected data source",
        )

    if attributes.get("configuration_drift") is True:
        add(
            "configuration_drift",
            "Observed AI configuration differs from its approved baseline",
            "15",
            "Restore the approved configuration or approve the recorded change",
        )

    score = min(Decimal("100"), score).quantize(_MONEY)
    if score >= 80:
        severity, decision = "critical", "block"
    elif score >= 50:
        severity, decision = "high", "require_approval"
    elif score > 0:
        severity, decision = "medium", "recommend"
    else:
        severity, decision = "info", "allow"
    return {
        "decision": decision,
        "severity": severity,
        "score": score,
        "findings": findings,
        "recommended_controls": controls,
    }


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
        f"resource-identity:{resource_id}:{identity_ref.casefold()}"
        if resource_id and identity_ref
        else f"identity:{identity_ref.casefold()}"
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
    resource_id: str | None = None,
) -> dict[str, Any]:
    merged = dict(current)
    merged["event_ids"] = list(dict.fromkeys([*current.get("event_ids", []), event_id]))[-500:]
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
                "resource_id": resource_id,
            }
        )
    merged["timeline"] = sorted(timeline, key=lambda item: str(item["occurred_at"]))[-500:]
    merged["severity"] = max(
        (str(current.get("severity", "info")), severity), key=lambda item: _SEVERITY_ORDER[item]
    )
    return merged


def should_correlate_security_event(*, category: str, severity: str) -> bool:
    if category == "endpoint":
        return severity in {"high", "critical"}
    return category in {"incident", "identity", "deception", "access"}


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
    return await _upsert_resource(session, principal, payload)


async def _upsert_resource(
    session: AsyncSession, principal: Principal, payload: SecurityResourceUpsertIn
) -> SecurityResource:
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


async def evaluate_private_access(
    session: AsyncSession, principal: Principal, payload: PrivateAccessEvaluateIn
) -> dict[str, Any]:
    """Evaluate and durably audit one native private-application access request."""

    principal.require(Permission.INTEGRATION_MANAGE)
    policy = await session.scalar(
        tenant_select(SecurityPolicy, principal.organization_id).where(
            SecurityPolicy.id == payload.policy_id
        )
    )
    if policy is None or policy.kind != "ztna":
        raise ResourceNotFoundError("Private access policy not found")
    if policy.status != "active":
        raise ConflictError("Private access policy is not active")

    decision = evaluate_private_access_policy(
        request=payload.model_dump(exclude={"policy_id", "request_id"}),
        rules=policy.rules,
        policy_mode=policy.mode,
    )
    now = dt.datetime.now(dt.UTC)
    event = await _ingest_event(
        session,
        principal,
        SecurityEventIn(
            event_key=f"private-access:{policy.id}:{policy.version}:{payload.request_id}",
            category="access",
            event_type=f"private_access_{decision['decision']}",
            source_kind="cynux_private_access",
            occurred_at=now,
            severity="info" if decision["decision"] == "allow" else "high",
            summary=f"Private application access {decision['decision']}",
            identity_ref=payload.identity_ref,
            metrics={"session_minutes": decision["session_minutes"]},
            evidence={
                "policy_id": str(policy.id),
                "policy_version": policy.version,
                "application_ref": payload.application_ref,
                "reason_codes": decision["reason_codes"],
                "would_block": decision["would_block"],
                "enforced": decision["enforced"],
            },
        ),
    )
    await record(
        session,
        action="control_plane.private_access.evaluate",
        principal=principal,
        resource_type="security_policy",
        resource_id=policy.id,
        detail={
            "decision": decision["decision"],
            "event_id": str(event.id),
            "request_id": payload.request_id,
        },
    )
    return {
        "policy_id": policy.id,
        "policy_version": policy.version,
        "event_id": event.id,
        **decision,
    }


_NATIVE_AI_POLICY_NAME = "Cynux Native AI Security Baseline"
_NATIVE_AI_POLICY_VERSION = 1


async def run_native_ai_posture_assessment(
    session: AsyncSession, principal: Principal
) -> dict[str, Any]:
    """Assess and prioritize every normalized AI resource without a provider API.

    The operation is safe to repeat.  Evaluations are immutable run evidence, while
    recommendations use finding-aware idempotency keys and obsolete proposals are
    superseded when the posture changes.
    """

    principal.require(Permission.INTEGRATION_MANAGE)
    policy = await session.scalar(
        tenant_select(SecurityPolicy, principal.organization_id).where(
            SecurityPolicy.name == _NATIVE_AI_POLICY_NAME
        )
    )
    if policy is None:
        policy = SecurityPolicy(
            organization_id=principal.organization_id,
            name=_NATIVE_AI_POLICY_NAME,
            kind="ai_guard",
            mode="recommend",
            status="active",
            version=_NATIVE_AI_POLICY_VERSION,
            rules={
                "engine": "cynux-native-ai-posture",
                "engine_version": _NATIVE_AI_POLICY_VERSION,
                "external_connector_required": False,
            },
            integration_id=None,
            created_by_id=principal.user_id,
        )
        session.add(policy)
        await session.flush()

    resources = await list_resources(session, principal, limit=10_000)
    ai_resources = [item for item in resources if item.kind in _AI_RESOURCE_KINDS]
    now = dt.datetime.now(dt.UTC)
    evaluation_ids: list[uuid.UUID] = []
    recommendation_ids: list[uuid.UUID] = []
    finding_counts: dict[str, int] = {}
    compliant = 0
    at_risk = 0
    critical = 0
    created = 0

    for resource in ai_resources:
        previous_posture_status = resource.posture_status
        previous_risk_score = str(resource.risk_score)
        decision = evaluate_native_ai_posture(resource.as_dict())
        content = {
            "engine_version": _NATIVE_AI_POLICY_VERSION,
            "resource_id": str(resource.id),
            "decision": decision["decision"],
            "score": str(decision["score"]),
            "finding_codes": sorted(item["code"] for item in decision["findings"]),
        }
        digest = hashlib.sha256(
            json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        evaluation = SecurityPolicyEvaluation(
            organization_id=principal.organization_id,
            policy_id=policy.id,
            resource_id=resource.id,
            decision=decision["decision"],
            severity=decision["severity"],
            score=decision["score"],
            findings=decision["findings"],
            evidence={
                "engine": "cynux-native-ai-posture",
                "engine_version": _NATIVE_AI_POLICY_VERSION,
                "external_connector_required": False,
                "resource_key": resource.resource_key,
                "recommended_controls": decision["recommended_controls"],
            },
            content_digest=digest,
            evaluated_at=now,
        )
        session.add(evaluation)
        await session.flush()
        evaluation_ids.append(evaluation.id)

        for finding in decision["findings"]:
            code = str(finding["code"])
            finding_counts[code] = finding_counts.get(code, 0) + 1

        resource.risk_score = decision["score"]
        if decision["decision"] == "allow":
            resource.posture_status = "healthy"
            compliant += 1
        elif decision["severity"] == "critical":
            resource.posture_status = "non_compliant"
            critical += 1
            at_risk += 1
        else:
            resource.posture_status = "at_risk"
            at_risk += 1

        active_recommendations = list(
            (
                await session.scalars(
                    tenant_select(SecurityRecommendation, principal.organization_id).where(
                        SecurityRecommendation.resource_id == resource.id,
                        SecurityRecommendation.policy_id == policy.id,
                        SecurityRecommendation.status.in_(["proposed", "approved", "failed"]),
                    )
                )
            ).all()
        )
        if decision["decision"] == "allow":
            for previous in active_recommendations:
                previous.status = "superseded"
            continue

        finding_codes = sorted(item["code"] for item in decision["findings"])
        key = hashlib.sha256(
            (
                f"native-ai-posture:v{_NATIVE_AI_POLICY_VERSION}:"
                f"{resource.id}:{','.join(finding_codes)}"
            ).encode()
        ).hexdigest()
        recommendation = next(
            (item for item in active_recommendations if item.idempotency_key == key), None
        )
        for previous in active_recommendations:
            if previous.idempotency_key != key:
                previous.status = "superseded"
        if recommendation is None:
            recommendation = await session.scalar(
                tenant_select(SecurityRecommendation, principal.organization_id).where(
                    SecurityRecommendation.idempotency_key == key
                )
            )
        if recommendation is not None and recommendation.status in {
            "applied",
            "rejected",
            "superseded",
        }:
            recommendation.status = "proposed"
            recommendation.provider_receipt = {}
            recommendation.applied_by_id = None
            recommendation.applied_at = None
        if recommendation is None:
            recommendation = SecurityRecommendation(
                organization_id=principal.organization_id,
                policy_id=policy.id,
                resource_id=resource.id,
                asset_id=resource.asset_id,
                integration_id=None,
                domain="ai_security",
                title=f"Harden native AI posture for {resource.name}",
                rationale="; ".join(item["message"] for item in decision["findings"]),
                action="native.remediate_ai_posture",
                severity=decision["severity"],
                status="proposed",
                current_state={
                    "posture_status": previous_posture_status,
                    "risk_score": previous_risk_score,
                    "finding_codes": finding_codes,
                },
                desired_state={
                    "posture_status": "healthy",
                    "risk_score": "0.00",
                    "controls": decision["recommended_controls"],
                    "external_connector_required": False,
                },
                idempotency_key=key,
                provider_receipt={},
                created_by_id=principal.user_id,
            )
            session.add(recommendation)
            await session.flush()
            created += 1
        recommendation_ids.append(recommendation.id)

    await session.flush()
    await record(
        session,
        action="control_plane.native_ai_posture.assess",
        principal=principal,
        resource_type="security_policy",
        resource_id=policy.id,
        detail={
            "assessed_resources": len(ai_resources),
            "at_risk_resources": at_risk,
            "recommendations_created": created,
        },
    )
    return {
        "policy_id": policy.id,
        "assessed_resources": len(ai_resources),
        "compliant_resources": compliant,
        "at_risk_resources": at_risk,
        "critical_resources": critical,
        "recommendations_created": created,
        "evaluation_ids": evaluation_ids,
        "recommendation_ids": recommendation_ids,
        "finding_counts": finding_counts,
        "external_connector_required": False,
    }


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
        resource_id=str(event.resource_id) if event.resource_id else None,
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
    return await _ingest_event(session, principal, payload)


async def _ingest_event(
    session: AsyncSession, principal: Principal, payload: SecurityEventIn
) -> SecurityEvent:
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
    if should_correlate_security_event(category=payload.category, severity=payload.severity):
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
