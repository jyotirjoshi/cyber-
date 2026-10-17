"""Strictly validated, auditable remediation automation definitions."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import secrets
import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.crypto import get_cipher
from app.core.errors import AuthenticationError, ConflictError, CynuxError, ResourceNotFoundError
from app.core.targets import TargetType, classify
from app.db.base import utcnow
from app.db.enums import (
    AgentRunStatus,
    AssetEnvironment,
    AuditOutcome,
    NotificationChannel,
    NotificationEvent,
    Permission,
    Severity,
)
from app.db.models.agent import AgentRun, AgentSession
from app.db.models.assessment import Assessment
from app.db.models.asset import Asset
from app.db.models.canonical import AutomationExecution, AutomationRule, CanonicalFinding
from app.db.models.identity import Membership, Organization
from app.db.models.report import Report
from app.db.repository import tenant_select
from app.schemas.assessment import AssessmentCreateIn, AuthorizationIn
from app.schemas.asset import AssetTagIn
from app.schemas.canonical import CanonicalWorkIn
from app.schemas.organization import OrgPolicy
from app.services import audit as audit_service
from app.services import canonical_work as canonical_work_service
from app.services import remediation_governance
from app.services.automation_expression import evaluate_expression, validate_expression
from app.services.codeowners import owners_for_path
from app.services.context import Principal
from app.services.notification import NotificationContent, dispatch
from app.services.scheduling import next_cron_time
from app.worker.dispatch import stage_assessment_run, stage_run_dispatch
from app.worker.protocol import RunAction

if TYPE_CHECKING:
    from app.db.models.asset import Asset
    from app.schemas.automation import AutomationManualRunIn, AutomationRuleIn


_TRIGGERS = frozenset(
    {
        "finding.created",
        "finding.updated",
        "ticket.closed",
        "retest.confirmed",
        "retest.cleared",
        "sla.breached",
        "asset.created",
        "asset.updated",
        "assessment.started",
        "assessment.completed",
        "engagement.created",
        "engagement.status_changed",
        "scan.failed",
        "integration.error",
        "webhook.received",
        "manual",
    }
)
_CONDITIONS = frozenset(
    {
        "severity_at_least",
        "asset_environment",
        "asset_criticality_at_least",
        "in_kev",
        "asset_group",
        "risk_score_at_least",
        "internet_exposed",
        "expression",
    }
)
_ACTIONS = frozenset(
    {
        "create_ticket",
        "notify",
        "request_retest",
        "schedule_retest",
        "assign_owner",
        "assign_codeowner",
        "set_remediation_group",
        "refresh_intelligence",
        "send_webhook",
        "add_asset_tag",
        "set_finding_field",
        "generate_report",
        "run_agent",
    }
)
_TICKET_PROVIDERS = frozenset({"jira", "github", "gitlab", "servicenow", "azure_devops", "linear"})
_NOTIFICATION_CHANNELS = frozenset(channel.value for channel in NotificationChannel)
_RETEST_ASSET_TARGET_TYPES = {
    "domain": frozenset({TargetType.DOMAIN}),
    "subdomain": frozenset({TargetType.DOMAIN}),
    "hostname": frozenset({TargetType.DOMAIN}),
    "ip": frozenset({TargetType.IP}),
    "ip_address": frozenset({TargetType.IP}),
    "host": frozenset({TargetType.DOMAIN, TargetType.IP}),
    "url": frozenset({TargetType.URL}),
    "website": frozenset({TargetType.URL}),
    "repo": frozenset({TargetType.REPOSITORY}),
    "repository": frozenset({TargetType.REPOSITORY}),
    "container": frozenset({TargetType.CONTAINER_IMAGE}),
    "container_image": frozenset({TargetType.CONTAINER_IMAGE}),
    "image": frozenset({TargetType.CONTAINER_IMAGE}),
    "cloud_account": frozenset({TargetType.CLOUD_ACCOUNT}),
}
_MAX_AUTOMATION_ATTEMPTS = 5
_AUTOMATION_RETRY_BASE_SECONDS = 30
_AUTOMATION_RETRY_MAX_SECONDS = 60 * 60

AUTOMATION_TEMPLATES: tuple[dict[str, Any], ...] = (
    {
        "id": "critical-production-response",
        "name": "Critical production response",
        "description": "Route critical production findings, notify responders and open a ticket.",
        "definition": {
            "trigger": "finding.created",
            "conditions": {
                "severity_at_least": "critical",
                "asset_environment": "production",
                "internet_exposed": True,
            },
            "actions": [
                {"type": "create_ticket", "provider": "jira"},
                {"type": "notify"},
            ],
        },
    },
    {
        "id": "closed-ticket-retest",
        "name": "Verify closed tickets",
        "description": "Schedule an evidence-producing retest when remediation closes.",
        "definition": {
            "trigger": "ticket.closed",
            "conditions": {},
            "actions": [
                {
                    "type": "schedule_retest",
                    "authorization_reference": "Replace with the approved scope reference",
                }
            ],
        },
    },
    {
        "id": "integration-failure-response",
        "name": "Integration failure response",
        "description": "Notify the operations team when a connector reports an error.",
        "definition": {
            "trigger": "integration.error",
            "conditions": {},
            "actions": [{"type": "notify"}],
        },
    },
)
_SENSITIVE_CONTEXT_MARKERS = (
    "api_key",
    "authorization",
    "cookie",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
)


def automation_catalog() -> dict[str, Any]:
    """Return the closed rule vocabulary used by both API clients and the builder."""
    return {
        "triggers": sorted(_TRIGGERS),
        "conditions": sorted(_CONDITIONS),
        "actions": sorted(_ACTIONS),
        "templates": list(AUTOMATION_TEMPLATES),
    }


def _bounded_event_context(context: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(context, dict):
        raise ValueError("automation event context must be an object")
    try:
        encoded = json.dumps(context, ensure_ascii=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ValueError("automation event context must be JSON serializable") from exc
    if len(encoded.encode("utf-8")) > 32_768:
        raise ValueError("automation event context exceeds 32 KiB")

    def sanitize(value: Any, *, key: str = "") -> Any:
        normalized = key.lower().replace("-", "_")
        if any(marker in normalized for marker in _SENSITIVE_CONTEXT_MARKERS):
            return "[REDACTED]"
        if isinstance(value, dict):
            return {str(child_key): sanitize(child, key=str(child_key)) for child_key, child in value.items()}
        if isinstance(value, list):
            return [sanitize(child) for child in value]
        return value

    return sanitize(context)


def automation_webhook_signature(secret: str, timestamp: int, body: bytes) -> str:
    signed = str(timestamp).encode("ascii") + b"." + body
    return hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()


def verify_automation_webhook(
    *,
    secret: str,
    timestamp: int,
    signature: str,
    body: bytes,
    now: int | None = None,
) -> bool:
    """Verify a five-minute, exact-body HMAC envelope in constant time."""
    current = int(dt.datetime.now(dt.UTC).timestamp()) if now is None else now
    if abs(current - timestamp) > 300:
        return False
    supplied = signature.removeprefix("sha256=")
    if len(supplied) != 64:
        return False
    expected = automation_webhook_signature(secret, timestamp, body)
    return hmac.compare_digest(expected, supplied)


def validate_rule_definition(
    *, trigger: str, conditions: dict[str, Any], actions: list[dict[str, Any]]
) -> dict[str, Any]:
    """Validate declarative automation; no arbitrary code or network instruction is accepted."""
    if trigger not in _TRIGGERS:
        raise ValueError("unsupported automation trigger")
    if not isinstance(conditions, dict) or set(conditions) - _CONDITIONS:
        raise ValueError("unsupported automation condition")
    severity = conditions.get("severity_at_least")
    if severity is not None:
        try:
            Severity(str(severity))
        except ValueError as exc:
            raise ValueError("severity_at_least must be a canonical severity") from exc
    environment = conditions.get("asset_environment")
    if environment is not None:
        try:
            AssetEnvironment(str(environment))
        except ValueError as exc:
            raise ValueError("asset_environment must be a canonical environment") from exc
    criticality = conditions.get("asset_criticality_at_least")
    if criticality is not None and criticality not in {"critical", "high", "normal", "low"}:
        raise ValueError("asset_criticality_at_least must be critical, high, normal, or low")
    if "in_kev" in conditions and not isinstance(conditions["in_kev"], bool):
        raise ValueError("in_kev must be a boolean")
    risk_score = conditions.get("risk_score_at_least")
    if risk_score is not None and (
        isinstance(risk_score, bool)
        or not isinstance(risk_score, int | float)
        or not 0 <= float(risk_score) <= 100
    ):
        raise ValueError("risk_score_at_least must be a number between 0 and 100")
    if "internet_exposed" in conditions and not isinstance(conditions["internet_exposed"], bool):
        raise ValueError("internet_exposed must be a boolean")
    if "asset_group" in conditions and (
        not isinstance(conditions["asset_group"], str) or not conditions["asset_group"].strip()
    ):
        raise ValueError("asset_group must be a non-empty string")
    expression = conditions.get("expression")
    if expression is not None:
        if not isinstance(expression, str):
            raise ValueError("automation expression must be a string")
        conditions = {**conditions, "expression": validate_expression(expression)}
    if len(actions) < 1 or len(actions) > 10:
        raise ValueError("automation rules need one to ten actions")
    clean_actions: list[dict[str, Any]] = []
    for action in actions:
        if not isinstance(action, dict):
            raise ValueError("automation action has unsupported fields")
        kind = action.get("type")
        provider = action.get("provider")
        if kind not in _ACTIONS:
            raise ValueError("unsupported automation action")
        allowed_fields = {"type", "provider"}
        if kind == "assign_owner":
            allowed_fields = {"type", "assignee_user_id"}
            try:
                uuid.UUID(str(action.get("assignee_user_id")))
            except (TypeError, ValueError) as exc:
                raise ValueError("assign_owner requires a UUID assignee_user_id") from exc
        elif kind == "set_remediation_group":
            allowed_fields = {"type", "remediation_group"}
            group = action.get("remediation_group")
            if (
                not isinstance(group, str)
                or not group.strip()
                or len(group.strip()) > 160
                or any(ord(character) < 32 or ord(character) == 127 for character in group)
            ):
                raise ValueError(
                    "set_remediation_group requires a non-empty remediation_group of at most 160 characters"
                )
        elif kind == "schedule_retest":
            allowed_fields = {"type", "authorization_reference"}
            reference = action.get("authorization_reference")
            if trigger != "ticket.closed":
                raise ValueError("schedule_retest is valid only for ticket.closed")
            if (
                not isinstance(reference, str)
                or not reference.strip()
                or len(reference.strip()) > 1024
                or any(ord(character) < 32 or ord(character) == 127 for character in reference)
            ):
                raise ValueError("schedule_retest requires a valid authorization_reference")
        elif kind == "notify":
            allowed_fields = {"type", "channels"}
            raw_channels = action.get("channels")
            if raw_channels is not None and (
                not isinstance(raw_channels, list)
                or not raw_channels
                or len(raw_channels) > len(_NOTIFICATION_CHANNELS)
                or any(
                    not isinstance(channel, str) or channel not in _NOTIFICATION_CHANNELS
                    for channel in raw_channels
                )
                or len(set(raw_channels)) != len(raw_channels)
            ):
                raise ValueError("notify channels must be unique supported notification channels")
        elif kind in {"assign_codeowner", "refresh_intelligence", "send_webhook"}:
            allowed_fields = {"type"}
        elif kind == "add_asset_tag":
            allowed_fields = {"type", "key", "value"}
            key = action.get("key")
            value = action.get("value")
            if (
                not isinstance(key, str)
                or not key.strip()
                or len(key.strip()) > 60
                or any(ord(character) < 32 or ord(character) == 127 for character in key)
            ):
                raise ValueError("add_asset_tag requires a valid key")
            if value is not None and (not isinstance(value, str) or len(value) > 200):
                raise ValueError("add_asset_tag value must be a string of at most 200 characters")
        elif kind == "set_finding_field":
            allowed_fields = {"type", "field", "value"}
            field = action.get("field")
            value = action.get("value")
            if field not in {"remediation_plan", "remediation_group", "due_in_days"}:
                raise ValueError("set_finding_field field is not mutable by automation")
            if field == "due_in_days":
                if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 3650:
                    raise ValueError("due_in_days must be an integer between 0 and 3650")
            elif value is not None and (
                not isinstance(value, str)
                or len(value.strip()) > (4000 if field == "remediation_plan" else 160)
            ):
                raise ValueError("set_finding_field value is invalid")
        elif kind == "generate_report":
            allowed_fields = {"type", "assessment_id", "format", "audience", "title"}
            try:
                uuid.UUID(str(action.get("assessment_id")))
            except (TypeError, ValueError) as exc:
                raise ValueError("generate_report requires an assessment UUID") from exc
            if action.get("format", "pdf") not in {"html", "pdf", "json"}:
                raise ValueError("generate_report format is unsupported")
            if action.get("audience", "executive") not in {"executive", "technical"}:
                raise ValueError("generate_report audience is unsupported")
            title = action.get("title")
            if title is not None and (
                not isinstance(title, str) or not title.strip() or len(title.strip()) > 300
            ):
                raise ValueError("generate_report title is invalid")
        elif kind == "run_agent":
            allowed_fields = {"type", "session_id", "objective"}
            try:
                uuid.UUID(str(action.get("session_id")))
            except (TypeError, ValueError) as exc:
                raise ValueError("run_agent requires an agent session UUID") from exc
            objective = action.get("objective")
            if not isinstance(objective, str) or not objective.strip() or len(objective) > 4000:
                raise ValueError("run_agent requires an objective of at most 4,000 characters")
        if set(action) - allowed_fields:
            raise ValueError("automation action has unsupported fields")
        if kind == "create_ticket" and provider not in _TICKET_PROVIDERS:
            raise ValueError("unsupported ticket provider")
        if kind != "create_ticket" and provider is not None:
            raise ValueError("provider is valid only for create_ticket")
        clean_action: dict[str, Any] = {"type": kind}
        if kind == "create_ticket":
            clean_action["provider"] = provider
        elif kind == "assign_owner":
            clean_action["assignee_user_id"] = str(action["assignee_user_id"])
        elif kind == "set_remediation_group":
            clean_action["remediation_group"] = str(action["remediation_group"]).strip()
        elif kind == "schedule_retest":
            clean_action["authorization_reference"] = str(action["authorization_reference"]).strip()
        elif kind == "notify" and action.get("channels") is not None:
            clean_action["channels"] = list(action["channels"])
        elif kind == "add_asset_tag":
            clean_action["key"] = str(action["key"]).strip().lower()
            if action.get("value") is not None:
                clean_action["value"] = str(action["value"])
        elif kind == "set_finding_field":
            clean_action["field"] = str(action["field"])
            clean_action["value"] = action.get("value")
        elif kind == "generate_report":
            clean_action.update(
                {
                    "assessment_id": str(uuid.UUID(str(action["assessment_id"]))),
                    "format": str(action.get("format", "pdf")),
                    "audience": str(action.get("audience", "executive")),
                }
            )
            if action.get("title") is not None:
                clean_action["title"] = str(action["title"]).strip()
        elif kind == "run_agent":
            clean_action["session_id"] = str(uuid.UUID(str(action["session_id"])))
            clean_action["objective"] = str(action["objective"]).strip()
        clean_actions.append(clean_action)
    return {"trigger": trigger, "conditions": dict(conditions), "actions": clean_actions}


async def _codeowner_assignee(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    finding: CanonicalFinding,
) -> uuid.UUID | None:
    """Resolve a canonical finding's saved repository path to a live tenant member."""
    path = finding.custom_fields.get("repository_path") or finding.custom_fields.get("path")
    if not isinstance(path, str) or not path.strip():
        return None
    organization = await session.get(Organization, organization_id)
    if organization is None:
        return None
    try:
        policy = OrgPolicy.model_validate(organization.policy or {})
    except ValueError:
        return None
    if not policy.codeowners or not policy.codeowner_members:
        return None
    for owner in owners_for_path(policy.codeowners, path):
        user_id = policy.codeowner_members.get(owner)
        if user_id is None:
            continue
        membership = (
            await session.execute(
                select(Membership.id).where(
                    Membership.organization_id == organization_id,
                    Membership.user_id == user_id,
                )
            )
        ).scalar_one_or_none()
        if membership is not None:
            return user_id
    return None


def _notification_channels(action: dict[str, Any]) -> tuple[NotificationChannel, ...] | None:
    """Return validated explicit targets, or use the platform event default when omitted."""
    raw = action.get("channels")
    return tuple(NotificationChannel(channel) for channel in raw) if raw is not None else None


def _retest_target_for_asset(asset: Asset) -> str:
    """Return an inventory-backed target only when its stored identity is assessable."""
    allowed = _RETEST_ASSET_TARGET_TYPES.get(asset.asset_type)
    if not allowed or asset.name.startswith("sha256:"):
        raise ValueError("finding asset cannot be used as a retest target")
    if classify(asset.name) not in allowed:
        raise ValueError("finding asset identity is not a valid retest target")
    return asset.name


async def _create_scheduled_assessment(
    session: AsyncSession,
    principal: Principal,
    payload: AssessmentCreateIn,
    settings: Settings,
) -> Any:
    """Load assessment orchestration lazily to avoid its canonical-ingest import cycle."""
    from app.services import assessment as assessment_service

    return await assessment_service.create_assessment(
        session, principal, payload, settings, authorization_method="scheduled"
    )


async def schedule_ticket_close_retest(
    session: AsyncSession,
    *,
    principal: Principal,
    finding: CanonicalFinding,
    authorization_reference: str,
    settings: Settings,
) -> dict[str, str]:
    """Stage a tenant-scoped retest through the normal, approval-gated assessment path."""
    asset = (
        (
            await session.execute(
                tenant_select(Asset, principal.organization_id).where(Asset.id == finding.asset_id)
            )
        )
        .scalars()
        .one_or_none()
    )
    if asset is None:
        raise ValueError("finding asset is unavailable for retest")
    target = _retest_target_for_asset(asset)

    # Acquire the durable per-finding verification first.  Automation executions are retried
    # at least once, and creating the assessment before this idempotency gate used to create a
    # fresh assessment on every replay even though only one retest request could be scheduled.
    request = await remediation_governance.request_retest(
        session,
        principal,
        finding.id,
        note="Automatically scheduled after remediation ticket closure.",
    )
    if request.status != "requested":
        outcome = {"type": "schedule_retest", "request_id": str(request.id), "reused": "true"}
        if request.assessment_id is not None:
            outcome["assessment_id"] = str(request.assessment_id)
        return outcome

    assessment = await _create_scheduled_assessment(
        session,
        principal,
        AssessmentCreateIn(
            targets=[target],
            title=f"Retest: {finding.title}"[:300],
            objective=f"Verify remediation for canonical finding {finding.id} after ticket closure.",
            authorization=AuthorizationIn(
                confirmed=True,
                attestation_text=(
                    "A closed remediation ticket triggered this retest. "
                    "Active scanner execution remains subject to the assessment approval gate."
                ),
                evidence_reference=authorization_reference,
            ),
        ),
        settings,
    )
    run_id, _ = stage_assessment_run(session, principal, assessment)
    await remediation_governance.schedule_retest(
        session,
        organization_id=principal.organization_id,
        request_id=request.id,
        assessment_id=assessment.id,
    )
    return {
        "type": "schedule_retest",
        "request_id": str(request.id),
        "assessment_id": str(assessment.id),
        "run_id": str(run_id),
    }


_schedule_ticket_close_retest = schedule_ticket_close_retest


async def queue_due_automation_schedules(
    session: AsyncSession, *, now: Any | None = None, limit: int = 50
) -> int:
    """Queue each due scheduled rule once, then advance its durable cursor."""
    current = now or utcnow()
    rules = (
        (
            await session.execute(
                select(AutomationRule)
                .where(
                    AutomationRule.is_enabled.is_(True),
                    AutomationRule.cron_expression.is_not(None),
                    AutomationRule.next_run_at <= current,
                )
                .order_by(AutomationRule.next_run_at, AutomationRule.id)
                .limit(max(1, min(limit, 100)))
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    queued = 0
    for rule in rules:
        due_at = rule.next_run_at
        if due_at is None or rule.cron_expression is None:
            continue
        event_key = f"cron:{rule.id}:{due_at.isoformat()}"
        inserted = await session.execute(
            pg_insert(AutomationExecution)
            .values(
                id=uuid.uuid4(),
                organization_id=rule.organization_id,
                rule_id=rule.id,
                canonical_finding_id=None,
                event_key=event_key,
                status="dry_run" if rule.dry_run else "pending",
                dry_run=rule.dry_run,
                result={"trigger": "cron"},
            )
            .on_conflict_do_nothing(constraint="unique_automation_execution_event")
        )
        queued += int(inserted.rowcount or 0)
        rule.next_run_at = next_cron_time(rule.cron_expression, rule.timezone, due_at)
    return queued


def conditions_match(
    conditions: dict[str, Any],
    *,
    severity: str,
    asset_environment: str | None,
    in_kev: bool | None,
    asset_groups: set[str],
    risk_score: float = 0.0,
    internet_exposed: bool = False,
    asset_criticality: str | None = None,
    trigger: str | None = None,
    source: str | None = None,
    status: str | None = None,
) -> bool:
    """Return whether the immutable finding context satisfies every declared condition.

    This is deliberately a closed, data-only evaluator: a tenant rule cannot invoke
    arbitrary expressions or inspect data from another organization.
    """
    threshold = conditions.get("severity_at_least")
    if threshold is not None:
        try:
            if Severity.parse(severity).rank < Severity(str(threshold)).rank:
                return False
        except ValueError:
            return False
    if "asset_environment" in conditions and asset_environment != conditions["asset_environment"]:
        return False
    if "asset_criticality_at_least" in conditions:
        ranks = {"unknown": 0, "low": 1, "normal": 2, "high": 3, "critical": 4}
        if (
            ranks.get(str(asset_criticality), 0)
            < ranks[str(conditions["asset_criticality_at_least"])]
        ):
            return False
    if "in_kev" in conditions and in_kev is not conditions["in_kev"]:
        return False
    if "risk_score_at_least" in conditions and risk_score < float(
        conditions["risk_score_at_least"]
    ):
        return False
    if "internet_exposed" in conditions and internet_exposed is not conditions["internet_exposed"]:
        return False
    if "asset_group" in conditions and conditions["asset_group"] not in asset_groups:
        return False
    expression = conditions.get("expression")
    if expression is not None:
        try:
            return evaluate_expression(
                str(expression),
                {
                    "severity": severity,
                    "risk_score": risk_score,
                    "in_kev": in_kev,
                    "internet_exposed": internet_exposed,
                    "asset_environment": asset_environment,
                    "asset_criticality": asset_criticality,
                    "asset_groups": sorted(asset_groups),
                    "trigger": trigger,
                    "source": source,
                    "status": status,
                },
            )
        except ValueError:
            return False
    return True


def _canonical_kev_state(finding: CanonicalFinding) -> bool | None:
    """Read canonical KEV evidence without turning an unavailable feed into ``False``.

    Canonical risk factors store inputs under ``inputs`` while refresh snapshots are
    keyed by CVE.  Earlier automation code looked for a top-level key in either
    structure, which made a confirmed KEV invisible and let an ``in_kev: false`` rule
    match a finding whose intelligence was actually unavailable.
    """
    risk_factors = getattr(finding, "risk_factors", None)
    factors = risk_factors if isinstance(risk_factors, dict) else {}
    inputs = factors.get("inputs")
    if isinstance(inputs, dict) and isinstance(inputs.get("in_kev"), bool):
        return inputs["in_kev"]
    intel_evidence = getattr(finding, "intel_evidence", None)
    snapshots = intel_evidence if isinstance(intel_evidence, dict) else {}
    values = [
        snapshot.get("in_kev")
        for snapshot in snapshots.values()
        if isinstance(snapshot, dict) and isinstance(snapshot.get("in_kev"), bool)
    ]
    if True in values:
        return True
    if False in values:
        return False
    return None


async def create_rule(
    session: AsyncSession,
    principal: Principal,
    payload: AutomationRuleIn,
) -> AutomationRule:
    """Create one tenant-isolated, auditable unattended automation definition."""
    principal.require(Permission.ORG_MANAGE)
    definition = validate_rule_definition(
        trigger=payload.trigger, conditions=payload.conditions, actions=payload.actions
    )
    next_run_at = (
        next_cron_time(payload.cron_expression, payload.timezone, utcnow())
        if payload.cron_expression
        else None
    )
    rule = AutomationRule(
        id=uuid.uuid4(),
        organization_id=principal.organization_id,
        created_by_id=principal.user_id,
        name=payload.name,
        trigger=definition["trigger"],
        conditions=definition["conditions"],
        actions=definition["actions"],
        cron_expression=payload.cron_expression,
        timezone=payload.timezone,
        next_run_at=next_run_at,
        is_enabled=payload.is_enabled,
        dry_run=payload.dry_run,
    )
    session.add(rule)
    await session.flush()
    await audit_service.record(
        session,
        action=audit_service.AuditAction.AUTOMATION_RULE_CREATE,
        principal=principal,
        resource_type="automation_rule",
        resource_id=rule.id,
        detail={
            "trigger": rule.trigger,
            "dry_run": rule.dry_run,
            "action_count": len(rule.actions),
        },
    )
    return rule


async def update_rule(
    session: AsyncSession,
    principal: Principal,
    rule_id: uuid.UUID,
    payload: AutomationRuleIn,
) -> AutomationRule:
    """Replace one rule's declarative definition within its owning tenant."""
    principal.require(Permission.ORG_MANAGE)
    rule = (
        await session.execute(
            tenant_select(AutomationRule, principal.organization_id)
            .where(AutomationRule.id == rule_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if rule is None:
        from app.core.errors import TenantIsolationError

        raise TenantIsolationError("automation rule not found in organization")
    definition = validate_rule_definition(
        trigger=payload.trigger, conditions=payload.conditions, actions=payload.actions
    )
    rule.name = payload.name
    rule.trigger = definition["trigger"]
    if rule.trigger != "webhook.received":
        rule.inbound_secret_ciphertext = None
        rule.inbound_secret_rotated_at = None
    rule.conditions = definition["conditions"]
    rule.actions = definition["actions"]
    rule.cron_expression = payload.cron_expression
    rule.timezone = payload.timezone
    rule.next_run_at = (
        next_cron_time(payload.cron_expression, payload.timezone, utcnow())
        if payload.cron_expression
        else None
    )
    rule.is_enabled = payload.is_enabled
    rule.dry_run = payload.dry_run
    await audit_service.record(
        session,
        action=audit_service.AuditAction.AUTOMATION_RULE_UPDATE,
        principal=principal,
        resource_type="automation_rule",
        resource_id=rule.id,
        detail={
            "trigger": rule.trigger,
            "dry_run": rule.dry_run,
            "action_count": len(rule.actions),
        },
    )
    return rule


async def list_rules(session: AsyncSession, principal: Principal) -> list[AutomationRule]:
    """Return only the caller's organization rules, newest first."""
    principal.require(Permission.ORG_READ)
    rows = await session.execute(
        tenant_select(AutomationRule, principal.organization_id).order_by(
            AutomationRule.created_at.desc(), AutomationRule.id.desc()
        )
    )
    return list(rows.scalars().all())


async def list_rules_paged(
    session: AsyncSession,
    principal: Principal,
    *,
    limit: int = 25,
    offset: int = 0,
) -> tuple[list[AutomationRule], int]:
    """Paginated tenant-scoped rule listing."""
    from sqlalchemy import func

    principal.require(Permission.ORG_READ)
    total = (
        await session.execute(
            select(func.count())
            .select_from(AutomationRule)
            .where(AutomationRule.organization_id == principal.organization_id)
        )
    ).scalar_one()
    rows = (
        (
            await session.execute(
                tenant_select(AutomationRule, principal.organization_id)
                .order_by(AutomationRule.created_at.desc(), AutomationRule.id.desc())
                .limit(max(1, min(limit, 100)))
                .offset(max(0, offset))
            )
        )
        .scalars()
        .all()
    )
    return list(rows), int(total)


async def get_rule(
    session: AsyncSession, principal: Principal, rule_id: uuid.UUID
) -> AutomationRule:
    from app.core.errors import ResourceNotFoundError

    principal.require(Permission.ORG_READ)
    rule = (
        await session.execute(
            tenant_select(AutomationRule, principal.organization_id).where(
                AutomationRule.id == rule_id
            )
        )
    ).scalar_one_or_none()
    if rule is None or rule.organization_id != principal.organization_id:
        raise ResourceNotFoundError("Automation rule not found")
    return rule


async def delete_rule(session: AsyncSession, principal: Principal, rule_id: uuid.UUID) -> None:
    principal.require(Permission.ORG_MANAGE)
    rule = await get_rule(session, principal, rule_id)
    await session.delete(rule)
    await audit_service.record(
        session,
        action=audit_service.AuditAction.AUTOMATION_RULE_DELETE,
        principal=principal,
        resource_type="automation_rule",
        resource_id=rule_id,
        detail={"rule_name": rule.name},
    )


async def list_executions(session: AsyncSession, principal: Principal) -> list[AutomationExecution]:
    """Return the tenant's durable automation outcomes, newest first."""
    principal.require(Permission.ORG_READ)
    rows = await session.execute(
        tenant_select(AutomationExecution, principal.organization_id).order_by(
            AutomationExecution.created_at.desc(), AutomationExecution.id.desc()
        )
    )
    return list(rows.scalars().all())


async def list_executions_paged(
    session: AsyncSession,
    principal: Principal,
    *,
    limit: int = 25,
    offset: int = 0,
) -> tuple[list[AutomationExecution], int]:
    from sqlalchemy import func

    principal.require(Permission.ORG_READ)
    total = (
        await session.execute(
            select(func.count())
            .select_from(AutomationExecution)
            .where(AutomationExecution.organization_id == principal.organization_id)
        )
    ).scalar_one()
    rows = (
        (
            await session.execute(
                tenant_select(AutomationExecution, principal.organization_id)
                .order_by(AutomationExecution.created_at.desc(), AutomationExecution.id.desc())
                .limit(max(1, min(limit, 100)))
                .offset(max(0, offset))
            )
        )
        .scalars()
        .all()
    )
    return list(rows), int(total)


async def list_executions_for_rule(
    session: AsyncSession,
    principal: Principal,
    rule_id: uuid.UUID,
    *,
    limit: int = 25,
    offset: int = 0,
) -> tuple[list[AutomationExecution], int]:
    from sqlalchemy import func

    principal.require(Permission.ORG_READ)
    # Verify rule belongs to tenant
    await get_rule(session, principal, rule_id)
    total = (
        await session.execute(
            select(func.count())
            .select_from(AutomationExecution)
            .where(
                AutomationExecution.organization_id == principal.organization_id,
                AutomationExecution.rule_id == rule_id,
            )
        )
    ).scalar_one()
    rows = (
        (
            await session.execute(
                tenant_select(AutomationExecution, principal.organization_id)
                .where(AutomationExecution.rule_id == rule_id)
                .order_by(AutomationExecution.created_at.desc(), AutomationExecution.id.desc())
                .limit(max(1, min(limit, 100)))
                .offset(max(0, offset))
            )
        )
        .scalars()
        .all()
    )
    return list(rows), int(total)


async def queue_finding_event(
    session: AsyncSession,
    *,
    finding: CanonicalFinding,
    asset: Asset,
    trigger: str,
    event_key_suffix: str = "",
) -> int:
    """Persist matching rule executions before any provider call is attempted.

    The unique ``(rule_id, event_key)`` key makes this at-least-once-safe: callers may
    reprocess a source observation without creating a second ticket workflow.
    """
    if trigger not in _TRIGGERS:
        raise ValueError("unsupported automation trigger")
    if finding.organization_id != asset.organization_id:
        raise ValueError("finding and asset belong to different organizations")
    result = await session.execute(
        tenant_select(AutomationRule, finding.organization_id).where(
            AutomationRule.trigger == trigger, AutomationRule.is_enabled.is_(True)
        )
    )
    in_kev = _canonical_kev_state(finding)
    event_key = f"{trigger}:{finding.id}{event_key_suffix}"
    queued = 0
    for rule in result.scalars().all():
        if rule.organization_id != finding.organization_id:
            continue
        if not conditions_match(
            rule.conditions,
            severity=finding.severity,
            asset_environment=asset.environment,
            asset_criticality=getattr(asset, "criticality", None),
            in_kev=in_kev,
            asset_groups=set(asset.groups or []),
            risk_score=float(getattr(finding, "risk_score", 0.0) or 0.0),
            internet_exposed=bool(getattr(asset, "internet_exposed", False)),
            trigger=trigger,
            source=str(getattr(finding, "primary_source", "canonical")),
            status=str(getattr(finding, "status", "open")),
        ):
            continue
        inserted = await session.execute(
            pg_insert(AutomationExecution)
            .values(
                id=uuid.uuid4(),
                organization_id=finding.organization_id,
                rule_id=rule.id,
                canonical_finding_id=finding.id,
                event_key=event_key,
                status="dry_run" if rule.dry_run else "pending",
                dry_run=rule.dry_run,
                result={"trigger": trigger},
            )
            .on_conflict_do_nothing(constraint="unique_automation_execution_event")
        )
        queued += int(inserted.rowcount or 0)
    if isinstance(finding, CanonicalFinding) and isinstance(asset, Asset):
        from app.services.workflow import queue_finding_workflows

        queued += await queue_finding_workflows(
            session,
            finding=finding,
            asset=asset,
            trigger=trigger,
            event_key_suffix=event_key_suffix,
        )
    return queued


async def queue_rule_event(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    trigger: str,
    event_key: str,
    context: dict[str, Any],
    rule_id: uuid.UUID | None = None,
) -> list[uuid.UUID]:
    """Queue a bounded non-finding event with durable replay protection."""
    if trigger not in _TRIGGERS:
        raise ValueError("unsupported automation trigger")
    clean_context = _bounded_event_context(context)
    query = tenant_select(AutomationRule, organization_id).where(
        AutomationRule.trigger == trigger,
        AutomationRule.is_enabled.is_(True),
    )
    if rule_id is not None:
        query = query.where(AutomationRule.id == rule_id)
    rules = list((await session.execute(query)).scalars().all())
    inserted_ids: list[uuid.UUID] = []
    for rule in rules:
        groups = clean_context.get("asset_groups", [])
        if not isinstance(groups, list) or any(not isinstance(item, str) for item in groups):
            groups = []
        if not conditions_match(
            rule.conditions,
            severity=str(clean_context.get("severity", "info")),
            asset_environment=(
                str(clean_context["asset_environment"])
                if clean_context.get("asset_environment") is not None
                else None
            ),
            asset_criticality=(
                str(clean_context["asset_criticality"])
                if clean_context.get("asset_criticality") is not None
                else None
            ),
            in_kev=(clean_context.get("in_kev") if isinstance(clean_context.get("in_kev"), bool) else None),
            asset_groups=set(groups),
            risk_score=(
                float(clean_context.get("risk_score", 0.0))
                if isinstance(clean_context.get("risk_score", 0.0), int | float)
                and not isinstance(clean_context.get("risk_score", 0.0), bool)
                else 0.0
            ),
            internet_exposed=bool(clean_context.get("internet_exposed", False)),
            trigger=trigger,
            source=(str(clean_context["source"]) if clean_context.get("source") else None),
            status=(str(clean_context["status"]) if clean_context.get("status") else None),
        ):
            continue
        execution_id = uuid.uuid4()
        inserted = await session.execute(
            pg_insert(AutomationExecution)
            .values(
                id=execution_id,
                organization_id=organization_id,
                rule_id=rule.id,
                canonical_finding_id=None,
                event_key=event_key,
                status="dry_run" if rule.dry_run else "pending",
                dry_run=rule.dry_run,
                result={"trigger": trigger, "context": clean_context},
            )
            .on_conflict_do_nothing(constraint="unique_automation_execution_event")
        )
        if int(inserted.rowcount or 0):
            inserted_ids.append(execution_id)
    return inserted_ids


async def queue_manual_run(
    session: AsyncSession,
    principal: Principal,
    rule_id: uuid.UUID,
    payload: AutomationManualRunIn,
) -> AutomationExecution:
    """Start a manual rule once for a caller-supplied idempotency key."""
    principal.require(Permission.ORG_MANAGE)
    rule = await get_rule(session, principal, rule_id)
    if rule.trigger != "manual" or not rule.is_enabled:
        raise ConflictError("Only enabled manual rules can be started manually")
    event_key = f"manual:{payload.idempotency_key}"
    ids = await queue_rule_event(
        session,
        organization_id=principal.organization_id,
        trigger="manual",
        event_key=event_key,
        context=payload.context,
        rule_id=rule.id,
    )
    if not ids:
        existing = (
            await session.execute(
                tenant_select(AutomationExecution, principal.organization_id).where(
                    AutomationExecution.rule_id == rule.id,
                    AutomationExecution.event_key == event_key,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing
        raise ConflictError("Manual event did not satisfy this rule's conditions")
    execution = await session.get(AutomationExecution, ids[0])
    if execution is None:  # pragma: no cover - defensive against a broken unit of work
        raise ResourceNotFoundError("Automation execution was not persisted")
    return execution


async def rotate_inbound_secret(
    session: AsyncSession,
    principal: Principal,
    rule_id: uuid.UUID,
    settings: Settings,
) -> tuple[str, dt.datetime]:
    """Rotate a webhook rule's encrypted signing secret and reveal it exactly once."""
    principal.require(Permission.ORG_MANAGE)
    rule = await get_rule(session, principal, rule_id)
    if rule.trigger != "webhook.received":
        raise ConflictError("Inbound secrets are available only for webhook rules")
    secret = secrets.token_urlsafe(32)
    rule.inbound_secret_ciphertext = get_cipher(settings).encrypt(secret)
    rule.inbound_secret_rotated_at = utcnow()
    await audit_service.record(
        session,
        action=audit_service.AuditAction.AUTOMATION_RULE_UPDATE,
        principal=principal,
        resource_type="automation_rule",
        resource_id=rule.id,
        detail={"inbound_secret_rotated": True},
    )
    return secret, rule.inbound_secret_rotated_at


async def queue_inbound_webhook(
    session: AsyncSession,
    *,
    rule_id: uuid.UUID,
    settings: Settings,
    timestamp: int,
    signature: str,
    event_id: str,
    body: bytes,
) -> list[uuid.UUID]:
    """Authenticate an exact request body and enqueue it without disclosing tenant data."""
    clean_event_id = event_id.strip()
    if (
        len(body) > 32_768
        or not clean_event_id
        or len(clean_event_id) > 160
        or not clean_event_id[0].isascii()
        or not clean_event_id[0].isalnum()
        or any(
            not character.isascii()
            or (not character.isalnum() and character not in "._:-")
            for character in clean_event_id
        )
    ):
        raise AuthenticationError("Invalid automation webhook")
    rule = (
        await session.execute(
            select(AutomationRule).where(
                AutomationRule.id == rule_id,
                AutomationRule.trigger == "webhook.received",
                AutomationRule.is_enabled.is_(True),
            )
        )
    ).scalar_one_or_none()
    if rule is None or not rule.inbound_secret_ciphertext:
        raise AuthenticationError("Invalid automation webhook")
    secret = get_cipher(settings).decrypt(rule.inbound_secret_ciphertext).reveal()
    if not verify_automation_webhook(
        secret=secret,
        timestamp=timestamp,
        signature=signature,
        body=body,
    ):
        raise AuthenticationError("Invalid automation webhook")
    try:
        context = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthenticationError("Invalid automation webhook") from exc
    if not isinstance(context, dict):
        raise AuthenticationError("Invalid automation webhook")
    return await queue_rule_event(
        session,
        organization_id=rule.organization_id,
        trigger="webhook.received",
        event_key=f"webhook:{clean_event_id}",
        context=context,
        rule_id=rule.id,
    )


async def _execute_platform_action(
    session: AsyncSession,
    *,
    principal: Principal,
    rule: AutomationRule,
    execution: AutomationExecution,
    action: dict[str, Any],
    finding: CanonicalFinding | None,
    settings: Settings,
    redis: Any | None,
) -> dict[str, Any] | None:
    """Execute cross-entity actions through existing tenant-scoped service layers."""
    kind = str(action.get("type") or "")
    raw_context = execution.result.get("context", {}) if isinstance(execution.result, dict) else {}
    context = raw_context if isinstance(raw_context, dict) else {}
    if kind == "send_webhook":
        await dispatch(
            session,
            principal,
            event=NotificationEvent.AUTOMATION_NOTIFICATION,
            content=NotificationContent(
                subject=f"Automation webhook: {rule.name}",
                body="An automation rule emitted a signed outbound webhook event.",
                link=(f"/findings/{finding.id}" if finding is not None else "/automation-rules"),
            ),
            settings=settings,
            redis=redis,
            resource_type=("canonical_finding" if finding is not None else "automation_rule"),
            resource_id=str(finding.id if finding is not None else rule.id),
            channels=(NotificationChannel.WEBHOOK,),
        )
        return {"type": kind, "outcome": "dispatched"}
    if kind == "add_asset_tag":
        from app.services import asset as asset_service

        raw_asset_id = finding.asset_id if finding is not None else context.get("asset_id")
        if raw_asset_id is None:
            raise ValueError("add_asset_tag requires finding or asset context")
        tag = await asset_service.tag_asset(
            session,
            principal,
            uuid.UUID(str(raw_asset_id)),
            AssetTagIn(key=str(action["key"]), value=action.get("value")),
        )
        return {"type": kind, "asset_id": str(raw_asset_id), "tag_id": str(tag.id)}
    if kind == "set_finding_field":
        if finding is None:
            raise ValueError("set_finding_field requires finding context")
        field = str(action["field"])
        value = action.get("value")
        changes: dict[str, Any] = {"expected_version": finding.status_version}
        if field == "due_in_days":
            changes["due_at"] = utcnow() + dt.timedelta(days=int(value))
        else:
            changes[field] = value
        updated = await canonical_work_service.update_work(
            session, principal, finding.id, CanonicalWorkIn(**changes)
        )
        return {"type": kind, "field": field, "status_version": updated.status_version}
    if kind == "generate_report":
        assessment_id = uuid.UUID(str(action["assessment_id"]))
        assessment = (
            await session.execute(
                tenant_select(Assessment, principal.organization_id).where(
                    Assessment.id == assessment_id
                )
            )
        ).scalar_one_or_none()
        if assessment is None:
            raise ResourceNotFoundError("Assessment not found for automated report")
        requested_title = str(action.get("title") or f"Security assessment {assessment.reference}")
        report = Report(
            id=uuid.uuid4(),
            organization_id=principal.organization_id,
            assessment_id=assessment.id,
            requested_by_id=rule.created_by_id,
            title=f"Automation · {requested_title}"[:300],
            format=str(action.get("format", "pdf")),
            audience=str(action.get("audience", "executive")),
            status="pending",
        )
        session.add(report)
        return {"type": kind, "report_id": str(report.id), "outcome": "queued"}
    if kind == "run_agent":
        session_id = uuid.UUID(str(action["session_id"]))
        conversation = (
            await session.execute(
                tenant_select(AgentSession, principal.organization_id).where(
                    AgentSession.id == session_id,
                    AgentSession.is_archived.is_(False),
                )
            )
        ).scalar_one_or_none()
        if conversation is None:
            raise ResourceNotFoundError("Agent session not found for automation")
        run_id = uuid.uuid4()
        run = AgentRun(
            id=run_id,
            organization_id=principal.organization_id,
            session_id=conversation.id,
            triggered_by_id=rule.created_by_id or conversation.user_id,
            thread_id=str(run_id),
            graph="multi_agent",
            objective=str(action["objective"]),
            status=AgentRunStatus.QUEUED.value,
        )
        session.add(run)
        staged = stage_run_dispatch(
            session,
            organization_id=principal.organization_id,
            run_id=run_id,
            action=RunAction.SUPERVISE,
            principal=principal,
        )
        staged.run = run
        return {"type": kind, "run_id": str(run_id), "outcome": "queued"}
    return None


def _settle_execution_failure(execution: AutomationExecution, exc: Exception) -> tuple[str, bool]:
    trace = dict(execution.result) if isinstance(execution.result, dict) else {}
    execution.attempts += 1
    retryable = isinstance(exc, CynuxError) and exc.retryable
    error_code = exc.code if isinstance(exc, CynuxError) else "unexpected_error"
    if retryable and execution.attempts < _MAX_AUTOMATION_ATTEMPTS:
        delay_seconds = min(
            _AUTOMATION_RETRY_MAX_SECONDS,
            _AUTOMATION_RETRY_BASE_SECONDS * (2 ** (execution.attempts - 1)),
        )
        execution.next_retry_at = utcnow() + dt.timedelta(seconds=delay_seconds)
        execution.result = {
            **trace,
            "error_code": error_code,
            "retry_scheduled": True,
            "next_retry_at": execution.next_retry_at.isoformat(),
        }
        return error_code, True
    execution.status = "failed"
    execution.next_retry_at = None
    execution.result = {**trace, "error_code": error_code, "attempts": execution.attempts}
    return error_code, False


def _execution_trace(execution: AutomationExecution) -> dict[str, Any]:
    trace = dict(execution.result) if isinstance(execution.result, dict) else {}
    for key in ("actions", "attempts", "error_code", "next_retry_at", "reason", "retry_scheduled"):
        trace.pop(key, None)
    return trace


async def execute_pending_automations(
    session: AsyncSession,
    *,
    settings: Settings,
    redis: Any | None,
    limit: int = 20,
) -> int:
    """Execute queued rule actions with row locks and provider-level idempotency."""
    pending = (
        (
            await session.execute(
                select(AutomationExecution)
                .where(
                    AutomationExecution.status == "pending",
                    or_(
                        AutomationExecution.next_retry_at.is_(None),
                        AutomationExecution.next_retry_at <= utcnow(),
                    ),
                )
                .order_by(AutomationExecution.created_at, AutomationExecution.id)
                .limit(max(1, min(limit, 100)))
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    for execution in pending:
        rule = (
            (
                await session.execute(
                    tenant_select(AutomationRule, execution.organization_id).where(
                        AutomationRule.id == execution.rule_id
                    )
                )
            )
            .scalars()
            .one_or_none()
        )
        if rule is None or not rule.is_enabled:
            execution.status = "skipped"
            execution.result = {"reason": "rule_unavailable"}
            continue
        if execution.canonical_finding_id is None:
            if execution.dry_run or rule.dry_run:
                execution.status = "dry_run"
                execution.result = {
                    **_execution_trace(execution),
                    "actions": rule.actions,
                    "reason": "dry_run",
                }
                continue
            principal = Principal.for_system(organization_id=execution.organization_id)
            outcomes: list[dict[str, Any]] = []
            try:
                for action in rule.actions:
                    if action.get("type") == "notify":
                        await dispatch(
                            session,
                            principal,
                            event=NotificationEvent.AUTOMATION_NOTIFICATION,
                            content=NotificationContent(
                                subject=f"Automation: {rule.name}",
                                body="A durable automation event requires your attention.",
                                link="/automation-rules",
                            ),
                            settings=settings,
                            redis=redis,
                            resource_type="automation_rule",
                            resource_id=str(rule.id),
                            channels=_notification_channels(action),
                        )
                        outcomes.append({"type": "notify"})
                        continue
                    outcome = await _execute_platform_action(
                        session,
                        principal=principal,
                        rule=rule,
                        execution=execution,
                        action=action,
                        finding=None,
                        settings=settings,
                        redis=redis,
                    )
                    if outcome is None:
                        raise ValueError("automation action requires finding context")
                    outcomes.append(outcome)
                execution.status = "executed"
                execution.result = {**_execution_trace(execution), "actions": outcomes}
                await audit_service.record(
                    session,
                    action=audit_service.AuditAction.AUTOMATION_EXECUTION,
                    principal=principal,
                    resource_type="automation_execution",
                    resource_id=execution.id,
                    detail={"rule_id": str(rule.id), "action_count": len(outcomes)},
                )
            except Exception as exc:
                error_code, retry_scheduled = _settle_execution_failure(execution, exc)
                await audit_service.record(
                    session,
                    action=audit_service.AuditAction.AUTOMATION_EXECUTION,
                    principal=principal,
                    resource_type="automation_execution",
                    resource_id=execution.id,
                    outcome=AuditOutcome.FAILURE,
                    detail={
                        "rule_id": str(rule.id),
                        "error_code": error_code,
                        "attempt": execution.attempts,
                        "retry_scheduled": retry_scheduled,
                    },
                )
            continue
        finding = (
            (
                await session.execute(
                    tenant_select(CanonicalFinding, execution.organization_id).where(
                        CanonicalFinding.id == execution.canonical_finding_id
                    )
                )
            )
            .scalars()
            .one_or_none()
        )
        if finding is None:
            execution.status = "skipped"
            execution.result = {"reason": "rule_or_finding_unavailable"}
            continue
        if execution.dry_run or rule.dry_run:
            execution.status = "dry_run"
            execution.result = {
                **_execution_trace(execution),
                "actions": rule.actions,
                "reason": "dry_run",
            }
            continue
        principal = Principal.for_system(organization_id=execution.organization_id)
        outcomes: list[dict[str, Any]] = []
        try:
            for action in rule.actions:
                if action.get("type") == "create_ticket":
                    ticket = await _create_canonical_ticket(
                        session,
                        principal,
                        finding.id,
                        settings=settings,
                        redis=redis,
                        provider=str(action["provider"]),
                    )
                    outcomes.append(
                        {
                            "type": "create_ticket",
                            "provider": str(action["provider"]),
                            "ticket_key": ticket.external_key,
                        }
                    )
                elif action.get("type") == "request_retest":
                    request = await remediation_governance.request_retest(
                        session,
                        principal,
                        finding.id,
                        note="Requested by automation rule.",
                    )
                    outcomes.append({"type": "request_retest", "request_id": str(request.id)})
                elif action.get("type") == "schedule_retest":
                    outcomes.append(
                        await schedule_ticket_close_retest(
                            session,
                            principal=principal,
                            finding=finding,
                            authorization_reference=str(action["authorization_reference"]),
                            settings=settings,
                        )
                    )
                elif action.get("type") == "notify":
                    await dispatch(
                        session,
                        principal,
                        event=NotificationEvent.AUTOMATION_NOTIFICATION,
                        content=NotificationContent(
                            subject=f"Automation: {finding.title}",
                            body="An automation rule matched this finding. Review its remediation status and evidence.",
                            link=f"/findings/{finding.id}",
                        ),
                        settings=settings,
                        redis=redis,
                        resource_type="canonical_finding",
                        resource_id=str(finding.id),
                        severity=Severity.parse(finding.severity),
                        channels=_notification_channels(action),
                    )
                    outcomes.append({"type": "notify"})
                elif action.get("type") == "assign_owner":
                    assignee_user_id = uuid.UUID(str(action["assignee_user_id"]))
                    finding = await canonical_work_service.update_work(
                        session,
                        principal,
                        finding.id,
                        CanonicalWorkIn(
                            expected_version=finding.status_version,
                            assignee_user_id=assignee_user_id,
                        ),
                    )
                    outcomes.append(
                        {"type": "assign_owner", "assignee_user_id": str(assignee_user_id)}
                    )
                elif action.get("type") == "assign_codeowner":
                    assignee_user_id = await _codeowner_assignee(
                        session,
                        organization_id=execution.organization_id,
                        finding=finding,
                    )
                    if assignee_user_id is None:
                        outcomes.append(
                            {"type": "assign_codeowner", "outcome": "no_matching_member"}
                        )
                    else:
                        finding = await canonical_work_service.update_work(
                            session,
                            principal,
                            finding.id,
                            CanonicalWorkIn(
                                expected_version=finding.status_version,
                                assignee_user_id=assignee_user_id,
                            ),
                        )
                        outcomes.append(
                            {
                                "type": "assign_codeowner",
                                "assignee_user_id": str(assignee_user_id),
                            }
                        )
                elif action.get("type") == "set_remediation_group":
                    finding = await canonical_work_service.update_work(
                        session,
                        principal,
                        finding.id,
                        CanonicalWorkIn(
                            expected_version=finding.status_version,
                            remediation_group=str(action["remediation_group"]),
                        ),
                    )
                    outcomes.append(
                        {
                            "type": "set_remediation_group",
                            "remediation_group": str(finding.remediation_group or ""),
                        }
                    )
                elif action.get("type") == "refresh_intelligence":
                    # The intelligence worker owns feed access, caching, provenance and
                    # re-scoring.  Marking this row stale is a bounded, tenant-scoped
                    # handoff to that worker rather than embedding a network request in
                    # a no-code rule.
                    if finding.cve_ids:
                        finding.intel_refreshed_at = None
                        outcomes.append(
                            {
                                "type": "refresh_intelligence",
                                "outcome": "queued",
                                "cve_count": str(len(finding.cve_ids)),
                            }
                        )
                    else:
                        outcomes.append(
                            {"type": "refresh_intelligence", "outcome": "skipped_no_cves"}
                        )
                else:
                    outcome = await _execute_platform_action(
                        session,
                        principal=principal,
                        rule=rule,
                        execution=execution,
                        action=action,
                        finding=finding,
                        settings=settings,
                        redis=redis,
                    )
                    if outcome is None:
                        raise ValueError("automation action is not implemented")
                    outcomes.append(outcome)
            execution.status = "executed"
            execution.next_retry_at = None
            execution.result = {**_execution_trace(execution), "actions": outcomes}
            await audit_service.record(
                session,
                action=audit_service.AuditAction.AUTOMATION_EXECUTION,
                principal=principal,
                resource_type="automation_execution",
                resource_id=execution.id,
                detail={"rule_id": str(rule.id), "action_count": len(outcomes)},
            )
        except Exception as exc:
            error_code, retry_scheduled = _settle_execution_failure(execution, exc)
            await audit_service.record(
                session,
                action=audit_service.AuditAction.AUTOMATION_EXECUTION,
                principal=principal,
                resource_type="automation_execution",
                resource_id=execution.id,
                outcome=AuditOutcome.FAILURE,
                detail={
                    "rule_id": str(rule.id),
                    "error_code": error_code,
                    "attempt": execution.attempts,
                    "retry_scheduled": retry_scheduled,
                },
            )
    return len(pending)


async def _create_canonical_ticket(
    session: AsyncSession,
    principal: Principal,
    finding_id: uuid.UUID | None,
    *,
    settings: Settings,
    redis: Any | None,
    provider: str = "jira",
) -> Any:
    """Delay ticket-service import to keep canonical ingestion and automation acyclic."""
    from app.services import ticket as ticket_service

    return await ticket_service.create_canonical_ticket(
        session,
        principal,
        finding_id,
        settings=settings,
        redis=redis,
        by_agent=True,
        provider=provider,
    )


async def execute_declarative_action(
    session: AsyncSession,
    principal: Principal,
    *,
    finding_id: uuid.UUID,
    action: dict[str, Any],
    settings: Settings,
    redis: Any | None,
    idempotency_key: str,
) -> dict[str, Any]:
    """Execute one allow-listed workflow action through the production service layer."""
    kind = str(action.get("type") or "")
    finding = (
        await session.execute(
            tenant_select(CanonicalFinding, principal.organization_id).where(
                CanonicalFinding.id == finding_id
            )
        )
    ).scalar_one_or_none() if finding_id is not None else None
    if kind == "notify" and finding is None:
        await dispatch(
            session,
            principal,
            event=NotificationEvent.AUTOMATION_NOTIFICATION,
            content=NotificationContent(
                subject="Scheduled workflow notification",
                body="A scheduled durable workflow requires your attention.",
                link="/workflows",
            ),
            settings=settings,
            redis=redis,
            resource_type="workflow_step",
            resource_id=idempotency_key,
            channels=_notification_channels(action),
        )
        return {"type": kind}
    if finding is None:
        from app.core.errors import ResourceNotFoundError

        raise ResourceNotFoundError("canonical finding not found")
    if kind == "create_ticket":
        provider = str(action.get("provider") or "")
        if provider not in _TICKET_PROVIDERS:
            raise ValueError("unsupported ticket provider")
        ticket = await _create_canonical_ticket(
            session, principal, finding.id, settings=settings, redis=redis, provider=provider
        )
        return {"type": kind, "provider": provider, "ticket_key": ticket.external_key}
    if kind == "request_retest":
        request = await remediation_governance.request_retest(
            session, principal, finding.id, note="Requested by durable workflow."
        )
        return {"type": kind, "request_id": str(request.id)}
    if kind == "schedule_retest":
        reference = str(action.get("authorization_reference") or "").strip()
        if not reference:
            raise ValueError("schedule_retest requires authorization_reference")
        return await schedule_ticket_close_retest(
            session,
            principal=principal,
            finding=finding,
            authorization_reference=reference,
            settings=settings,
        )
    if kind == "notify":
        await dispatch(
            session,
            principal,
            event=NotificationEvent.AUTOMATION_NOTIFICATION,
            content=NotificationContent(
                subject=f"Workflow: {finding.title}",
                body="A durable remediation workflow requires your attention.",
                link=f"/findings/{finding.id}",
            ),
            settings=settings,
            redis=redis,
            resource_type="workflow_step",
            resource_id=idempotency_key,
            severity=Severity.parse(finding.severity),
            channels=_notification_channels(action),
        )
        return {"type": kind}
    if kind == "assign_owner":
        assignee_user_id = uuid.UUID(str(action.get("assignee_user_id")))
        finding = await canonical_work_service.update_work(
            session,
            principal,
            finding.id,
            CanonicalWorkIn(
                expected_version=finding.status_version, assignee_user_id=assignee_user_id
            ),
        )
        return {"type": kind, "assignee_user_id": str(assignee_user_id)}
    if kind == "assign_codeowner":
        assignee_user_id = await _codeowner_assignee(
            session, organization_id=principal.organization_id, finding=finding
        )
        if assignee_user_id is None:
            return {"type": kind, "outcome": "no_matching_member"}
        await canonical_work_service.update_work(
            session,
            principal,
            finding.id,
            CanonicalWorkIn(
                expected_version=finding.status_version, assignee_user_id=assignee_user_id
            ),
        )
        return {"type": kind, "assignee_user_id": str(assignee_user_id)}
    if kind == "set_remediation_group":
        group = str(action.get("remediation_group") or "").strip()
        if not group:
            raise ValueError("set_remediation_group requires remediation_group")
        finding = await canonical_work_service.update_work(
            session,
            principal,
            finding.id,
            CanonicalWorkIn(expected_version=finding.status_version, remediation_group=group),
        )
        return {"type": kind, "remediation_group": str(finding.remediation_group or "")}
    if kind == "refresh_intelligence":
        if finding.cve_ids:
            finding.intel_refreshed_at = None
            return {"type": kind, "outcome": "queued", "cve_count": len(finding.cve_ids)}
        return {"type": kind, "outcome": "skipped_no_cves"}
    raise ValueError("automation action is not implemented")


__all__ = [
    "automation_catalog",
    "automation_webhook_signature",
    "conditions_match",
    "create_rule",
    "delete_rule",
    "execute_declarative_action",
    "execute_pending_automations",
    "get_rule",
    "list_executions",
    "list_executions_for_rule",
    "list_executions_paged",
    "list_rules",
    "list_rules_paged",
    "queue_finding_event",
    "queue_inbound_webhook",
    "queue_manual_run",
    "queue_rule_event",
    "rotate_inbound_secret",
    "schedule_ticket_close_retest",
    "update_rule",
    "validate_rule_definition",
    "verify_automation_webhook",
]
