"""Provider-neutral DSPM posture and evidence-driven SOC operations."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import re
import uuid
from collections import Counter
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from app.core.errors import ConflictError, ResourceNotFoundError
from app.core.logging_conf import redact_mapping
from app.db.enums import Permission
from app.db.models.assurance import DataSecurityAssessment, ThreatResponseAction
from app.db.models.control_plane import SecurityEvent, SecurityResource, SecurityThreatStory
from app.db.repository import tenant_select
from app.services.ai_security import classify_sensitive_data
from app.services.context import Principal

if TYPE_CHECKING:
    from redis.asyncio import Redis
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.core.config import Settings
    from app.schemas.assurance import (
        DataSecurityAssessmentCreateIn,
        OCSFEventCreateIn,
        ThreatResponseActionCreateIn,
    )

_RESPONSE_ACTIONS: dict[str, tuple[str, frozenset[str]]] = {
    "crowdstrike": ("isolate_endpoint", frozenset()),
    "zscaler": ("restrict_access", frozenset({"provider_action", "desired_state"})),
    "jira": ("create_ticket", frozenset({"summary", "description", "finding_id", "labels"})),
    "servicenow": (
        "create_ticket",
        frozenset({"summary", "description", "finding_id"}),
    ),
    "slack": ("notify", frozenset({"text", "channel"})),
    "manual": ("manual", frozenset()),
}
_ZSCALER_RESPONSE_ACTIONS = frozenset(
    {
        "zpa.update_application_access",
        "zpa.update_segment_group",
        "zpa.update_server_group",
        "zpa.update_connector_group",
        "zia.update_url_filter_rule",
        "zia.update_firewall_rule",
    }
)


def canonical_digest(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(data).hexdigest()


def normalize_response_request(
    *, provider: str, action_type: str, requested_action: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate and bound the provider request that is covered by human approval."""

    specification = _RESPONSE_ACTIONS.get(provider)
    if specification is None:
        raise ValueError("unsupported response provider")
    expected_action, allowed_keys = specification
    if provider != "manual" and action_type != expected_action:
        raise ValueError(f"{provider} does not support {action_type}")
    extra = set(requested_action) - allowed_keys
    if extra:
        raise ValueError(f"response request contains unsupported fields: {', '.join(sorted(extra))}")
    if len(json.dumps(requested_action, default=str)) > 32_000:
        raise ValueError("response request exceeds the maximum size")
    safe = redact_mapping(dict(requested_action))
    if provider == "zscaler":
        provider_action = str(safe.get("provider_action", ""))
        desired_state = safe.get("desired_state")
        if provider_action not in _ZSCALER_RESPONSE_ACTIONS or not isinstance(
            desired_state, dict
        ):
            raise ValueError("Zscaler response requires an allow-listed action and desired state")
    elif provider in {"jira", "servicenow"}:
        summary = str(safe.get("summary", "")).strip()
        description = str(safe.get("description", "")).strip()
        if not summary or not description:
            raise ValueError("ticket response requires summary and description")
        safe["summary"] = summary[:255]
        safe["description"] = classify_sensitive_data(description[:4000]).redacted_content
        safe["finding_id"] = str(safe.get("finding_id") or "soc-response")[:160]
        if provider == "jira":
            labels = safe.get("labels") or []
            if not isinstance(labels, list) or len(labels) > 20:
                raise ValueError("Jira labels must be a bounded list")
            safe["labels"] = [str(value)[:80] for value in labels]
    elif provider == "slack":
        text = str(safe.get("text", "")).strip()
        if not text:
            raise ValueError("Slack response requires message text")
        safe["text"] = classify_sensitive_data(text[:3000]).redacted_content
        channel = safe.get("channel")
        if channel is not None and not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", str(channel)):
            raise ValueError("Slack channel is invalid")
    elif provider in {"crowdstrike", "manual"} and safe:
        raise ValueError(f"{provider} response does not accept provider arguments")
    return safe


@dataclass(frozen=True, slots=True)
class DataStoreAssessment:
    resource_ref: str
    provider: str
    service: str
    region: str | None
    scan_mode: str
    classifications: tuple[str, ...]
    identity_access: tuple[dict[str, Any], ...]
    encryption: dict[str, Any]
    retention: dict[str, Any]
    residency: dict[str, Any]
    findings: tuple[dict[str, Any], ...]
    recommendations: tuple[dict[str, Any], ...]
    posture_score: float
    assessment_digest: str


def controlled_sample_projection(values: Iterable[str], *, max_items: int) -> dict[str, Any]:
    """Classify transient samples and retain counts/digests, never values."""

    if not 1 <= max_items <= 10_000:
        raise ValueError("max_items must be between 1 and 10000")
    counts: Counter[str] = Counter()
    digests: list[str] = []
    sampled = 0
    for value in values:
        if sampled >= max_items:
            break
        text = str(value)
        result = classify_sensitive_data(text)
        counts.update(result.labels)
        digests.append(result.content_digest)
        sampled += 1
    return {
        "sampled_items": sampled,
        "classification_counts": dict(sorted(counts.items())),
        "sample_set_digest": canonical_digest(digests),
        "truncated": sampled >= max_items,
    }


def assess_data_store(
    *, resource: Mapping[str, Any], metadata: Mapping[str, Any], scan_mode: str
) -> DataStoreAssessment:
    """Assess a cloud/SaaS datastore using inventory metadata and safe sample summaries."""

    if scan_mode not in {"metadata_only", "controlled_sample", "full_authorized"}:
        raise ValueError("invalid DSPM scan mode")
    findings: list[dict[str, Any]] = []
    recommendations: list[dict[str, Any]] = []

    def add(code: str, severity: str, recommendation: str, penalty: int) -> None:
        findings.append({"code": code, "severity": severity, "penalty": penalty})
        recommendations.append({"code": code, "action": recommendation})

    if metadata.get("public_access") is True:
        add("public_data_store", "critical", "remove public access", 35)
    identities = list(metadata.get("identities") or [])
    if any(str(item.get("principal")) == "*" for item in identities if isinstance(item, dict)):
        add("wildcard_principal", "critical", "replace wildcard principals", 25)
    if metadata.get("encrypted") is not True:
        add("encryption_disabled", "high", "enable encryption at rest", 20)
    if int(metadata.get("retention_days") or 0) <= 0:
        add("retention_missing", "medium", "configure a retention policy", 10)
    approved_regions = set(metadata.get("approved_regions") or [])
    region = str(resource.get("region")) if resource.get("region") else None
    if approved_regions and region not in approved_regions:
        add("residency_violation", "high", "move data to an approved region", 20)
    if metadata.get("key_rotation_days") is not None and int(metadata["key_rotation_days"]) > 365:
        add("stale_encryption_key", "medium", "rotate the encryption key", 10)
    score = max(0, 100 - sum(int(item["penalty"]) for item in findings))
    safe_material = {
        "resource": {
            "id": str(resource.get("id", "")),
            "provider": str(resource.get("provider", "")),
            "service": str(resource.get("service", "")),
            "region": region,
        },
        "scan_mode": scan_mode,
        "classifications": sorted(set(metadata.get("classifications") or [])),
        "findings": findings,
        "score": score,
    }
    return DataStoreAssessment(
        resource_ref=str(resource.get("id", "")),
        provider=str(resource.get("provider", "")),
        service=str(resource.get("service", "")),
        region=region,
        scan_mode=scan_mode,
        classifications=tuple(safe_material["classifications"]),
        identity_access=tuple(redact_mapping(item) for item in identities if isinstance(item, dict)),
        encryption={"enabled": metadata.get("encrypted") is True},
        retention={"days": int(metadata.get("retention_days") or 0)},
        residency={"region": region, "approved": not approved_regions or region in approved_regions},
        findings=tuple(findings),
        recommendations=tuple(recommendations),
        posture_score=float(score),
        assessment_digest=canonical_digest(safe_material),
    )


def _event_time(value: Any) -> str:
    if isinstance(value, int | float):
        moment = dt.datetime.fromtimestamp(float(value) / 1000, tz=dt.UTC)
    elif isinstance(value, dt.datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=dt.UTC)
    else:
        moment = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=dt.UTC)
    return moment.astimezone(dt.UTC).isoformat()


def normalize_ocsf_event(payload: Mapping[str, Any], *, source: str) -> dict[str, Any]:
    """Project an OCSF event into bounded correlation fields with provenance."""

    class_uid = int(payload.get("class_uid", 0))
    category_uid = int(payload.get("category_uid", 0))
    type_uid = int(payload.get("type_uid", 0))
    if class_uid <= 0 or not 1 <= category_uid <= 8 or type_uid <= 0:
        raise ValueError("invalid OCSF class, category, or type UID")
    severity = int(payload.get("severity_id", 0))
    if not 0 <= severity <= 6:
        raise ValueError("invalid OCSF severity")
    actor = payload.get("actor") if isinstance(payload.get("actor"), dict) else {}
    user = actor.get("user") if isinstance(actor.get("user"), dict) else {}
    device = payload.get("device") if isinstance(payload.get("device"), dict) else {}
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    product = metadata.get("product") if isinstance(metadata.get("product"), dict) else {}
    observables = [
        {"name_digest": canonical_digest(str(item.get("name", ""))), "type": item.get("type")}
        for item in list(payload.get("observables") or [])[:1000]
        if isinstance(item, dict)
    ]
    attacks = [
        {
            "technique_id": str(item.get("technique_id") or item.get("technique", {}).get("uid", "")),
            "tactic": str(item.get("tactic") or item.get("tactic", {}).get("name", "")),
        }
        for item in list(payload.get("attacks") or [])[:100]
        if isinstance(item, dict)
    ]
    message = classify_sensitive_data(str(payload.get("message", ""))[:4000])
    material = {
        "class_uid": class_uid,
        "category_uid": category_uid,
        "activity_id": int(payload.get("activity_id", 0)),
        "type_uid": type_uid,
        "time": _event_time(payload.get("time")),
        "severity_id": severity,
        "status_id": payload.get("status_id"),
        "message": message.redacted_content,
        "message_digest": message.content_digest,
        "actor_ref": str(user.get("uid") or user.get("name") or "") or None,
        "device_ref": str(device.get("uid") or device.get("hostname") or "") or None,
        "observables": observables,
        "attacks": attacks,
        "source": source,
        "schema_version": str(metadata.get("version", ""))[:40],
        "product": str(product.get("name", ""))[:160],
    }
    return {"event_key": canonical_digest(material), **material}


def correlate_threat_story(
    events: Iterable[Mapping[str, Any]], *, contradictory: Iterable[Mapping[str, Any]] = ()
) -> dict[str, Any]:
    ordered = sorted(events, key=lambda item: str(item.get("time", "")))
    if not ordered:
        raise ValueError("at least one normalized event is required")
    contradictory_items = [redact_mapping(dict(item)) for item in contradictory]
    support = sum(float(item.get("evidence_weight", 0.5)) for item in ordered)
    contradiction = sum(float(item.get("weight", 0.5)) for item in contradictory_items)
    severity = max(int(item.get("severity_id", 0)) for item in ordered)
    confidence = support / (support + contradiction) if support + contradiction else 0
    score = min(100.0, severity / 6 * 70 + confidence * 30)
    progression: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for event in ordered:
        for attack in event.get("attacks") or []:
            key = (str(attack.get("technique_id", "")), str(attack.get("tactic", "")))
            if key not in seen:
                seen.add(key)
                progression.append(
                    {
                        "technique_id": key[0],
                        "tactic": key[1],
                        "first_seen": event.get("time"),
                        "event_key": event.get("event_key"),
                    }
                )
    return {
        "story_key": canonical_digest([item.get("event_key") for item in ordered]),
        "actor_refs": sorted({str(item["actor_ref"]) for item in ordered if item.get("actor_ref")}),
        "device_refs": sorted(
            {str(item["device_ref"]) for item in ordered if item.get("device_ref")}
        ),
        "event_keys": [str(item.get("event_key")) for item in ordered],
        "attack_progression": progression,
        "supporting_evidence_count": len(ordered),
        "contradictory_evidence": contradictory_items,
        "identity_compromise_score": round(score, 2),
        "confidence": round(confidence, 4),
    }


def preview_response_action(action: Any, *, context: Mapping[str, Any]) -> dict[str, Any]:
    active_sessions = max(0, int(context.get("active_sessions", 0)))
    critical_services = max(0, int(context.get("critical_services", 0)))
    impact_score = min(100, active_sessions * 5 + critical_services * 40)
    scope = {
        "action_type": action.action_type,
        "target_ref": action.target_ref,
        "idempotency_key": action.idempotency_key,
        "provider": str(getattr(action, "provider", "manual")),
        "requested_action": redact_mapping(dict(getattr(action, "requested_action", {}) or {})),
        "impact_score": impact_score,
    }
    preview = {
        "affected_sessions": active_sessions,
        "critical_services": critical_services,
        "impact_score": impact_score,
        "risk_level": "critical" if impact_score >= 80 else "high" if impact_score >= 40 else "low",
        "scope_digest": canonical_digest(scope),
    }
    action.predicted_impact = preview
    return preview


def approve_response_action(
    action: Any,
    *,
    approved_by_id: uuid.UUID | None,
    expected_scope_digest: str,
    now: dt.datetime | None = None,
) -> None:
    """Bind a human decision to the exact provider/action preview digest."""

    if approved_by_id is None:
        raise ConflictError("Response actions require approval by an authenticated human")
    if action.status != "proposed":
        raise ConflictError(f"Cannot approve a {action.status} response action")
    actual = str(action.predicted_impact.get("scope_digest", ""))
    if not actual or not hmac.compare_digest(actual, expected_scope_digest):
        raise ConflictError("Response approval does not match the exact action scope")
    action.approval_scope_digest = actual
    action.approved_by_id = approved_by_id
    action.approved_at = now or dt.datetime.now(dt.UTC)
    action.status = "approved"


async def execute_response_action(
    action: Any,
    *,
    approval_scope_digest: str,
    apply: Callable[[dict[str, object]], Awaitable[dict[str, object]]],
    now: dt.datetime | None = None,
) -> None:
    expected = str(action.predicted_impact.get("scope_digest", ""))
    if not expected or not hmac.compare_digest(approval_scope_digest, expected):
        raise ConflictError("Response approval does not match the exact action scope")
    approved_scope = getattr(action, "approval_scope_digest", None)
    if getattr(action, "approved_by_id", None) and not hmac.compare_digest(
        str(approved_scope or ""), approval_scope_digest
    ):
        raise ConflictError("Response action changed after human approval")
    if action.status in {"executed", "verified"} and action.provider_receipt:
        return
    has_human_approval = bool(
        getattr(action, "approved_by_id", None) or getattr(action, "approval_id", None)
    )
    if action.status != "approved" or not has_human_approval:
        raise ConflictError("Response action requires an explicit approval")
    action.status = "executing"
    receipt = await apply(
        {
            "action_type": action.action_type,
            "target_ref": action.target_ref,
            "idempotency_key": action.idempotency_key,
        }
    )
    action.provider_receipt = redact_mapping(receipt)
    action.executed_at = now or dt.datetime.now(dt.UTC)
    action.status = "executed"


def verify_response_action(
    action: Any, *, effective: bool, evidence: Mapping[str, Any], now: dt.datetime | None = None
) -> None:
    if action.status != "executed":
        raise ConflictError(f"Cannot verify a {action.status} response action")
    action.verification = {"effective": effective, **redact_mapping(dict(evidence))}
    action.verified_at = now or dt.datetime.now(dt.UTC)
    action.status = "verified" if effective else "failed"


async def create_data_security_assessment(
    session: AsyncSession, principal: Principal, payload: DataSecurityAssessmentCreateIn
) -> DataSecurityAssessment:
    principal.require(Permission.INTEGRATION_MANAGE)
    resource = await session.scalar(
        tenant_select(SecurityResource, principal.organization_id).where(
            SecurityResource.id == payload.resource_id
        )
    )
    if resource is None:
        raise ResourceNotFoundError("Data-store resource not found")
    existing = await session.scalar(
        tenant_select(DataSecurityAssessment, principal.organization_id).where(
            DataSecurityAssessment.assessment_key == payload.assessment_key
        )
    )
    if existing is not None:
        return existing
    metadata = {
        "public_access": bool(payload.sharing.get("public")),
        "encrypted": bool(payload.encryption.get("enabled")),
        "identities": payload.identity_access,
        "retention_days": payload.retention.get("days", 0),
        "classifications": payload.classifications,
        "approved_regions": payload.residency.get("approved_regions", []),
        "key_rotation_days": payload.key_posture.get("rotation_days"),
    }
    projected = assess_data_store(
        resource={
            "id": str(payload.resource_id),
            "provider": payload.provider,
            "service": payload.service,
            "region": payload.residency.get("region"),
        },
        metadata=metadata,
        scan_mode=payload.scan_mode,
    )
    row = DataSecurityAssessment(
        organization_id=principal.organization_id,
        resource_id=payload.resource_id,
        assessment_key=payload.assessment_key,
        provider=payload.provider,
        service=payload.service,
        scan_mode=payload.scan_mode,
        sample_policy=redact_mapping(payload.sample_policy),
        classifications=sorted(set(payload.classifications)),
        lineage=[redact_mapping(item) for item in payload.lineage],
        duplicate_group=payload.duplicate_group,
        sharing=redact_mapping(payload.sharing),
        identity_access=list(projected.identity_access),
        encryption=redact_mapping(payload.encryption),
        key_posture=redact_mapping(payload.key_posture),
        retention=redact_mapping(payload.retention),
        residency=redact_mapping(payload.residency),
        findings=list(projected.findings),
        recommendations=list(projected.recommendations),
        posture_score=Decimal(str(projected.posture_score)),
        observed_at=payload.observed_at,
    )
    session.add(row)
    await session.flush()
    return row


async def ingest_ocsf_event(
    session: AsyncSession,
    principal: Principal,
    payload: OCSFEventCreateIn,
    *,
    source: str,
) -> SecurityEvent:
    principal.require(Permission.INTEGRATION_MANAGE)
    normalized = normalize_ocsf_event(payload.model_dump(mode="json"), source=source)
    existing = await session.scalar(
        tenant_select(SecurityEvent, principal.organization_id).where(
            SecurityEvent.event_key == normalized["event_key"]
        )
    )
    if existing is not None:
        return existing
    severity = {0: "info", 1: "info", 2: "low", 3: "medium", 4: "high", 5: "high", 6: "critical"}[
        normalized["severity_id"]
    ]
    row = SecurityEvent(
        organization_id=principal.organization_id,
        event_key=normalized["event_key"],
        category="incident",
        event_type=f"ocsf:{normalized['class_uid']}:{normalized['activity_id']}",
        source_kind=source,
        occurred_at=_moment_from_iso(normalized["time"]),
        severity=severity,
        summary=normalized["message"],
        content_digest=normalized["message_digest"],
        identity_ref=normalized["actor_ref"],
        metrics={
            "category_uid": normalized["category_uid"],
            "class_uid": normalized["class_uid"],
            "type_uid": normalized["type_uid"],
            "severity_id": normalized["severity_id"],
        },
        evidence={
            "device_ref": normalized["device_ref"],
            "observables": normalized["observables"],
            "attacks": normalized["attacks"],
            "product": normalized["product"],
            "schema_version": normalized["schema_version"],
        },
    )
    session.add(row)
    await session.flush()
    return row


def _moment_from_iso(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


async def create_threat_response_action(
    session: AsyncSession, principal: Principal, payload: ThreatResponseActionCreateIn
) -> ThreatResponseAction:
    principal.require(Permission.INTEGRATION_MANAGE)
    story = await session.scalar(
        tenant_select(SecurityThreatStory, principal.organization_id).where(
            SecurityThreatStory.id == payload.story_id
        )
    )
    if story is None:
        raise ResourceNotFoundError("Threat story not found")
    existing = await session.scalar(
        tenant_select(ThreatResponseAction, principal.organization_id).where(
            ThreatResponseAction.idempotency_key == payload.idempotency_key
        )
    )
    if existing is not None:
        return existing
    requested_action = normalize_response_request(
        provider=payload.provider,
        action_type=payload.action_type,
        requested_action=payload.requested_action,
    )
    row = ThreatResponseAction(
        organization_id=principal.organization_id,
        story_id=payload.story_id,
        action_type=payload.action_type,
        target_ref=payload.target_ref,
        provider=payload.provider,
        requested_action=requested_action,
        status="proposed",
        predicted_impact={},
        idempotency_key=payload.idempotency_key,
    )
    preview_response_action(row, context=payload.predicted_impact)
    session.add(row)
    await session.flush()
    return row


async def approve_persisted_response_action(
    session: AsyncSession,
    principal: Principal,
    action_id: uuid.UUID,
    *,
    expected_scope_digest: str,
) -> ThreatResponseAction:
    principal.require(Permission.INTEGRATION_MANAGE)
    row = await session.scalar(
        tenant_select(ThreatResponseAction, principal.organization_id)
        .where(ThreatResponseAction.id == action_id)
        .with_for_update()
    )
    if row is None:
        raise ResourceNotFoundError("Threat response action not found")
    approve_response_action(
        row,
        approved_by_id=principal.user_id,
        expected_scope_digest=expected_scope_digest,
    )
    await session.flush()
    return row


async def _dispatch_response_action(
    session: AsyncSession,
    principal: Principal,
    action: ThreatResponseAction,
    *,
    settings: Settings,
    redis: Redis | None,
) -> dict[str, object]:
    from app.db.enums import IntegrationKind
    from app.integrations.control_enforcement import EnforcementCommand
    from app.integrations.crowdstrike import CrowdStrikeClient
    from app.integrations.jira import JiraClient
    from app.integrations.servicenow import ServiceNowClient
    from app.integrations.slack import SlackClient
    from app.integrations.zscaler import ZscalerClient
    from app.services.integration import resolve_settings

    kind_by_provider = {
        "crowdstrike": IntegrationKind.CROWDSTRIKE,
        "zscaler": IntegrationKind.ZSCALER,
        "jira": IntegrationKind.JIRA,
        "servicenow": IntegrationKind.SERVICENOW,
        "slack": IntegrationKind.SLACK,
    }
    kind = kind_by_provider.get(action.provider)
    if kind is None:
        raise ConflictError("Manual response actions cannot be executed by the API")
    scoped = await resolve_settings(session, principal, kind, settings=settings, require=True)
    requested = dict(action.requested_action)
    if action.provider == "crowdstrike":
        client = CrowdStrikeClient(scoped, redis)
        try:
            return await client.isolate_host(
                action.target_ref, idempotency_key=action.idempotency_key
            )
        finally:
            await client.aclose()
    if action.provider == "zscaler":
        client = ZscalerClient(scoped, redis)
        try:
            receipt = await client.apply(
                EnforcementCommand(
                    action=str(requested["provider_action"]),
                    target_external_id=action.target_ref,
                    desired_state=dict(requested["desired_state"]),
                    idempotency_key=action.idempotency_key,
                    dry_run=False,
                )
            )
            return {"provider": "zscaler", **receipt}
        finally:
            await client.aclose()
    if action.provider == "jira":
        client = JiraClient(scoped, redis)
        try:
            issue = await client.create_issue(
                summary=str(requested["summary"]),
                description=str(requested["description"]),
                finding_id=str(requested["finding_id"]),
                labels=list(requested.get("labels") or []),
            )
            return {"provider": "jira", "ticket_key": issue.key, "ticket_url": issue.url}
        finally:
            await client.aclose()
    if action.provider == "servicenow":
        client = ServiceNowClient(scoped, redis)
        try:
            issue = await client.create_issue(
                summary=str(requested["summary"]),
                description=str(requested["description"]),
                finding_id=str(requested["finding_id"]),
            )
            return {
                "provider": "servicenow",
                "ticket_key": issue.key,
                "ticket_url": issue.url,
            }
        finally:
            await client.aclose()
    client = SlackClient(scoped, redis)
    try:
        message = await client.notify(
            str(requested["text"]), channel=str(requested["channel"]) if requested.get("channel") else None
        )
        return {
            "provider": "slack",
            "channel": message.channel,
            "message_ts": message.ts,
        }
    finally:
        await client.aclose()


async def execute_persisted_response_action(
    session: AsyncSession,
    principal: Principal,
    action_id: uuid.UUID,
    *,
    expected_scope_digest: str,
    settings: Settings,
    redis: Redis | None,
) -> ThreatResponseAction:
    principal.require(Permission.INTEGRATION_MANAGE)
    row = await session.scalar(
        tenant_select(ThreatResponseAction, principal.organization_id)
        .where(ThreatResponseAction.id == action_id)
        .with_for_update()
    )
    if row is None:
        raise ResourceNotFoundError("Threat response action not found")

    async def apply(_request: dict[str, object]) -> dict[str, object]:
        return await _dispatch_response_action(
            session, principal, row, settings=settings, redis=redis
        )

    try:
        await execute_response_action(
            row,
            approval_scope_digest=expected_scope_digest,
            apply=apply,
        )
    except Exception as exc:
        row.status = "failed"
        row.failure_code = type(exc).__name__[:120]
        await session.commit()
        raise
    await session.flush()
    return row


async def verify_persisted_response_action(
    session: AsyncSession,
    principal: Principal,
    action_id: uuid.UUID,
    *,
    effective: bool,
    evidence: Mapping[str, Any],
) -> ThreatResponseAction:
    principal.require(Permission.INTEGRATION_MANAGE)
    row = await session.scalar(
        tenant_select(ThreatResponseAction, principal.organization_id)
        .where(ThreatResponseAction.id == action_id)
        .with_for_update()
    )
    if row is None:
        raise ResourceNotFoundError("Threat response action not found")
    verify_response_action(row, effective=effective, evidence=evidence)
    await session.flush()
    return row


__all__ = [
    "DataStoreAssessment",
    "approve_response_action",
    "assess_data_store",
    "canonical_digest",
    "controlled_sample_projection",
    "correlate_threat_story",
    "create_data_security_assessment",
    "create_threat_response_action",
    "approve_persisted_response_action",
    "execute_persisted_response_action",
    "execute_response_action",
    "ingest_ocsf_event",
    "normalize_ocsf_event",
    "preview_response_action",
    "verify_response_action",
    "verify_persisted_response_action",
    "normalize_response_request",
]
