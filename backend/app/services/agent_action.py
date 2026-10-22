"""Guardrails for individual, user-approved agent actions.

This module is intentionally small: it defines what may enter the action queue before a
provider client or scanner ever sees it.  Credentials are resolved only from tenant-scoped
integration settings at execution time; an action payload can never carry a secret.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

import structlog
from sqlalchemy import exists, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.core.config import Settings
from app.core.errors import (
    ConflictError,
    CynuxError,
    InvalidConfigurationError,
    PermissionDeniedError,
)
from app.core.logging_conf import redact_text
from app.db.base import utcnow
from app.db.enums import AuditOutcome, MessageRole, Permission, Role
from app.db.models.agent import AgentAction, AgentMessage, AgentSession
from app.db.models.assessment import Assessment
from app.db.models.identity import Membership, Organization, User
from app.db.repository import TenantRepository, tenant_select
from app.schemas.assessment import AssessmentCreateIn, AuthorizationIn
from app.schemas.canonical import (
    BulkCanonicalWorkIn,
    CanonicalWorkIn,
    RetestRequestIn,
    RiskAcceptanceIn,
)
from app.schemas.external_alert import ExternalAlertSourceActionIn
from app.services import assessment as assessment_service
from app.services import audit as audit_service
from app.services import canonical_work as canonical_work_service
from app.services import control_plane as control_plane_service
from app.services import external_alert as external_alert_service
from app.services import remediation_governance as remediation_governance_service
from app.services import ticket as ticket_service
from app.services.context import ACTOR_AGENT, Principal
from app.worker.dispatch import stage_assessment_run

log = structlog.get_logger(__name__)


def format_action_receipt(action: AgentAction) -> str:
    """State the persisted outcome without turning a queued run into a completed scan."""
    if action.status not in {"executed", "failed"}:
        raise ValueError("Action has no terminal outcome")
    label = redact_text(str(action.label or action.action))[:300]
    summary = redact_text(str(action.result_summary or "No result details were recorded."))[:500]
    if action.status == "failed":
        return f"Action failed: {label}. {summary}"
    if action.action == "start_assessment":
        run = f" Worker run: {action.run_id}." if action.run_id else ""
        return f"Assessment queued: {label}. {summary}.{run} Track the run for scan results."
    return f"Action completed: {label}. {summary}"


async def append_action_receipt(
    session: AsyncSession, action: AgentAction,
) -> AgentMessage | None:
    """Append one deterministic transcript receipt for a terminal tenant action."""
    if action.status not in {"executed", "failed"}:
        return None
    session_id = (
        await session.execute(
            select(AgentSession.id).where(
                AgentSession.organization_id == action.organization_id,
                AgentSession.id == action.session_id,
            ).limit(1)
        )
    ).scalar_one_or_none()
    if session_id is None:
        raise PermissionDeniedError("Agent action session is outside its organization.")
    existing = (
        await session.execute(
            select(AgentMessage).where(
                AgentMessage.organization_id == action.organization_id,
                AgentMessage.session_id == action.session_id,
                AgentMessage.source_action_id == action.id,
            ).limit(1)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    seq = int((await session.execute(
        select(func.coalesce(func.max(AgentMessage.seq), -1) + 1).where(
            AgentMessage.organization_id == action.organization_id,
            AgentMessage.session_id == action.session_id,
        )
    )).scalar_one())
    message = AgentMessage(
        id=uuid.uuid4(), organization_id=action.organization_id,
        session_id=action.session_id, source_action_id=action.id,
        seq=seq, role=MessageRole.ASSISTANT.value,
        content=format_action_receipt(action),
        model="deterministic", provider="cynux",
    )
    session.add(message)
    await session.flush()
    await session.execute(
        update(AgentSession)
        .where(
            AgentSession.organization_id == action.organization_id,
            AgentSession.id == action.session_id,
        )
        .values(
            message_count=AgentSession.message_count + 1,
            last_activity_at=utcnow(),
        )
    )
    return message


async def complete_assessment_action_receipt(
    session: AsyncSession, assessment: Assessment, run_id: uuid.UUID,
) -> bool:
    """Replace the queued receipt with persisted scan results in the same tenant."""
    action = (
        await session.execute(
            select(AgentAction).where(
                AgentAction.organization_id == assessment.organization_id,
                AgentAction.run_id == run_id,
                AgentAction.action == "start_assessment",
                AgentAction.status == "executed",
            ).limit(1)
        )
    ).scalar_one_or_none()
    if action is None:
        return False
    receipt = await append_action_receipt(session, action)
    if receipt is None:
        return False
    total = max(0, int(assessment.findings_total or 0))
    critical = max(0, int(assessment.findings_critical or 0))
    high = max(0, int(assessment.findings_high or 0))
    assets = max(0, int(assessment.assets_discovered or 0))
    receipt.content = (
        f"Assessment completed: {assessment.id}. {total} findings "
        f"({critical} critical, {high} high) across {assets} discovered assets."
        + (
            " Some scanner coverage was degraded; review the report."
            if assessment.degradations else " Report ready."
        )
    )
    return True


async def settle_assessment_action_receipt(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    run_id: uuid.UUID,
    outcome: str,
) -> bool:
    """Show failed or cancelled run state without claiming that its scan completed."""
    if outcome not in {"failed", "cancelled"}:
        raise ValueError("Only failed or cancelled assessment outcomes are supported")
    action = (
        await session.execute(
            select(AgentAction).where(
                AgentAction.organization_id == organization_id,
                AgentAction.run_id == run_id,
                AgentAction.action == "start_assessment",
                AgentAction.status == "executed",
            ).limit(1)
        )
    ).scalar_one_or_none()
    if action is None:
        return False
    receipt = await append_action_receipt(session, action)
    if receipt is None:
        return False
    receipt.content = (
        "Assessment failed. No completed scan result is available; review run details."
        if outcome == "failed"
        else "Assessment cancelled. No completed scan result is available."
    )
    return True

# Each action is deliberate and narrow.  Adding an entry is a security review point.
_ACTION_PERMISSIONS: dict[str, Permission] = {
    "sync_github_alerts": Permission.INTEGRATION_MANAGE,
    "sync_gitlab_alerts": Permission.INTEGRATION_MANAGE,
    "sync_wazuh_alerts": Permission.INTEGRATION_MANAGE,
    "sync_sonarqube_alerts": Permission.INTEGRATION_MANAGE,
    "sync_snyk_issues": Permission.INTEGRATION_MANAGE,
    "sync_tenable_vulnerabilities": Permission.INTEGRATION_MANAGE,
    "sync_qualys_host_detections": Permission.INTEGRATION_MANAGE,
    "sync_rapid7_vulnerabilities": Permission.INTEGRATION_MANAGE,
    "sync_wiz_issues": Permission.INTEGRATION_MANAGE,
    "sync_prisma_cloud_alerts": Permission.INTEGRATION_MANAGE,
    "sync_crowdstrike_vulnerabilities": Permission.INTEGRATION_MANAGE,
    "sync_aws_security_hub_findings": Permission.INTEGRATION_MANAGE,
    "sync_aws_inspector_findings": Permission.INTEGRATION_MANAGE,
    "sync_hackerone_reports": Permission.INTEGRATION_MANAGE,
    "sync_bugcrowd_submissions": Permission.INTEGRATION_MANAGE,
    "sync_checkmarx_results": Permission.INTEGRATION_MANAGE,
    "sync_fortify_issues": Permission.INTEGRATION_MANAGE,
    "sync_azure_defender_alerts": Permission.INTEGRATION_MANAGE,
    "sync_gcp_scc_findings": Permission.INTEGRATION_MANAGE,
    "sync_burp_dast_findings": Permission.INTEGRATION_MANAGE,
    "update_github_alert": Permission.INTEGRATION_MANAGE,
    "create_jira_ticket": Permission.TICKET_CREATE,
    "create_ticket": Permission.TICKET_CREATE,
    "refresh_ticket_status": Permission.FINDING_READ,
    "update_canonical_work": Permission.FINDING_REMEDIATE,
    "bulk_update_canonical_work": Permission.FINDING_REMEDIATE,
    "request_retest": Permission.FINDING_VALIDATE,
    "request_remediation_group_retests": Permission.FINDING_VALIDATE,
    "request_risk_acceptance": Permission.FINDING_REMEDIATE,
    "start_assessment": Permission.ASSESSMENT_CREATE,
    "run_native_ai_posture": Permission.INTEGRATION_MANAGE,
}

# Monitored autonomy is intentionally narrow. These operations synchronize a tenant's
# existing integrations or refresh an already-linked ticket; they cannot create a scan,
# alter a finding, open a ticket, or change a provider-side alert state.
MONITORED_AUTONOMY_ACTIONS: frozenset[str] = frozenset(
    {
        "sync_github_alerts",
        "sync_gitlab_alerts",
        "sync_wazuh_alerts",
        "sync_sonarqube_alerts",
        "sync_snyk_issues",
        "sync_tenable_vulnerabilities",
        "sync_qualys_host_detections",
        "sync_rapid7_vulnerabilities",
        "sync_wiz_issues",
        "sync_prisma_cloud_alerts",
        "sync_crowdstrike_vulnerabilities",
        "sync_aws_security_hub_findings",
        "sync_aws_inspector_findings",
        "sync_hackerone_reports",
        "sync_bugcrowd_submissions",
        "sync_checkmarx_results",
        "sync_fortify_issues",
        "sync_azure_defender_alerts",
        "sync_gcp_scc_findings",
        "sync_burp_dast_findings",
        "refresh_ticket_status",
        "run_native_ai_posture",
    }
)
_ALLOWED_PAYLOAD_KEYS: dict[str, frozenset[str]] = {
    "sync_github_alerts": frozenset(),
    "sync_gitlab_alerts": frozenset(),
    "sync_wazuh_alerts": frozenset(),
    "sync_sonarqube_alerts": frozenset(),
    "sync_snyk_issues": frozenset(),
    "sync_tenable_vulnerabilities": frozenset(),
    "sync_qualys_host_detections": frozenset(),
    "sync_rapid7_vulnerabilities": frozenset(),
    "sync_wiz_issues": frozenset(),
    "sync_prisma_cloud_alerts": frozenset(),
    "sync_crowdstrike_vulnerabilities": frozenset(),
    "sync_aws_security_hub_findings": frozenset(),
    "sync_aws_inspector_findings": frozenset(),
    "sync_hackerone_reports": frozenset(),
    "sync_bugcrowd_submissions": frozenset(),
    "sync_checkmarx_results": frozenset(),
    "sync_fortify_issues": frozenset(),
    "sync_azure_defender_alerts": frozenset(),
    "sync_gcp_scc_findings": frozenset(),
    "sync_burp_dast_findings": frozenset(),
    "update_github_alert": frozenset({"alert_id", "decision", "reason", "comment"}),
    "create_jira_ticket": frozenset(
        {"finding_id", "canonical_finding_id", "project_key", "issue_type", "assignee"}
    ),
    "create_ticket": frozenset(
        {"finding_id", "canonical_finding_id", "provider", "project_key", "issue_type", "assignee"}
    ),
    "refresh_ticket_status": frozenset({"ticket_id"}),
    "update_canonical_work": frozenset(
        {
            "finding_id",
            "expected_version",
            "assignee_user_id",
            "due_at",
            "remediation_plan",
            "remediation_group",
        }
    ),
    "bulk_update_canonical_work": frozenset({"items"}),
    "request_retest": frozenset({"finding_id", "note"}),
    "request_remediation_group_retests": frozenset({"remediation_group", "note"}),
    "request_risk_acceptance": frozenset({"finding_id", "rationale", "expires_at"}),
    "start_assessment": frozenset({"target", "authorization_reference"}),
    "run_native_ai_posture": frozenset(),
}
_SECRET_KEY_PARTS = frozenset({"token", "secret", "password", "credential", "api_key"})


def action_payload_digest(
    action: str, payload: Mapping[str, Any], *, depends_on_action_id: uuid.UUID | None = None
) -> str:
    """A stable hash binding consent to both the operation and exact payload."""
    envelope: dict[str, Any] = {"action": action, "payload": dict(payload)}
    if depends_on_action_id is not None:
        envelope["depends_on_action_id"] = str(depends_on_action_id)
    encoded = json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def validate_action_payload(action: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    """Reject unsupported actions, secret fields, and payloads beyond the action contract."""
    allowed = _ALLOWED_PAYLOAD_KEYS.get(action)
    if allowed is None:
        raise ValueError(f"Unsupported agent action: {action}")
    normalized = dict(payload)
    forbidden = [
        key for key in normalized if any(part in key.lower() for part in _SECRET_KEY_PARTS)
    ]
    if forbidden:
        raise ValueError("Action payloads must not contain credentials or secrets")
    unexpected = sorted(set(normalized) - allowed)
    if unexpected:
        raise ValueError(f"Unsupported payload fields for {action}: {', '.join(unexpected)}")
    if action == "start_assessment":
        target = normalized.get("target")
        reference = normalized.get("authorization_reference")
        if (
            not isinstance(target, str)
            or not target.strip()
            or len(target) > 2048
            or any(ord(ch) < 32 for ch in target)
        ):
            raise ValueError("A single valid assessment target is required")
        if target.lower().startswith(("http://", "https://")):
            parsed = urlsplit(target)
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError(
                    "Assessment targets must not contain credentials or URL parameters"
                )
        if (
            not isinstance(reference, str)
            or not reference.strip()
            or len(reference) > 1024
            or any(ord(ch) < 32 for ch in reference)
        ):
            raise ValueError("An authorization evidence reference is required")
        normalized = {"target": target.strip(), "authorization_reference": reference.strip()}
    if action == "update_github_alert":
        try:
            alert_id = normalized.get("alert_id")
            if not isinstance(alert_id, str):
                raise ValueError("A valid alert_id is required")
            normalized["alert_id"] = str(uuid.UUID(alert_id))
            source_action = ExternalAlertSourceActionIn.model_validate(
                {key: value for key, value in normalized.items() if key != "alert_id"}
            )
            normalized = {
                "alert_id": normalized["alert_id"],
                **source_action.model_dump(exclude_none=True),
            }
        except ValueError as exc:
            raise ValueError("A valid alert_id, decision and rationale are required") from exc
    if action in {"create_jira_ticket", "create_ticket"}:
        target_keys = {key for key in ("finding_id", "canonical_finding_id") if key in normalized}
        if len(target_keys) != 1:
            raise ValueError("Exactly one valid finding_id or canonical_finding_id is required")
        target_key = target_keys.pop()
        finding_id = normalized.get(target_key)
        try:
            if not isinstance(finding_id, str):
                raise ValueError
            normalized[target_key] = str(uuid.UUID(finding_id))
        except ValueError as exc:
            raise ValueError(f"A valid {target_key} is required") from exc
        for field, limit in (("project_key", 40), ("issue_type", 60), ("assignee", 200)):
            value = normalized.get(field)
            if value is None:
                continue
            if (
                not isinstance(value, str)
                or not value.strip()
                or len(value) > limit
                or any(ord(ch) < 32 for ch in value)
            ):
                raise ValueError(f"Invalid {field}")
            normalized[field] = value.strip()
        if "project_key" in normalized and not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_]{0,39}", normalized["project_key"]
        ):
            raise ValueError("Invalid project_key")
        if action == "create_ticket":
            provider = normalized.get("provider")
            if provider not in ticket_service.SUPPORTED_PROVIDERS:
                raise ValueError("Unsupported ticket provider")
    if action == "refresh_ticket_status":
        ticket_id = normalized.get("ticket_id")
        try:
            if not isinstance(ticket_id, str):
                raise ValueError
            normalized = {"ticket_id": str(uuid.UUID(ticket_id))}
        except ValueError as exc:
            raise ValueError("A valid ticket_id is required") from exc
    if action == "update_canonical_work":
        finding_id = normalized.get("finding_id")
        if not isinstance(finding_id, str):
            raise ValueError("A valid finding_id is required")
        try:
            normalized["finding_id"] = str(uuid.UUID(finding_id))
            work = CanonicalWorkIn.model_validate(
                {key: value for key, value in normalized.items() if key != "finding_id"}
            )
        except ValueError as exc:
            raise ValueError("A valid versioned remediation change is required") from exc
        normalized = {
            "finding_id": normalized["finding_id"],
            **work.model_dump(mode="json", exclude_unset=True),
        }
    if action == "bulk_update_canonical_work":
        try:
            bulk = BulkCanonicalWorkIn.model_validate(normalized)
        except ValueError as exc:
            raise ValueError("A valid bounded bulk remediation change is required") from exc
        normalized = bulk.model_dump(mode="json", exclude_unset=True)
    if action == "request_retest":
        finding_id = normalized.get("finding_id")
        try:
            if not isinstance(finding_id, str):
                raise ValueError
            normalized["finding_id"] = str(uuid.UUID(finding_id))
            request = RetestRequestIn.model_validate(
                {key: value for key, value in normalized.items() if key != "finding_id"}
            )
        except ValueError as exc:
            raise ValueError("A valid finding_id and retest note are required") from exc
        normalized = {
            "finding_id": normalized["finding_id"],
            **request.model_dump(exclude_none=True),
        }
    if action == "request_remediation_group_retests":
        group = normalized.get("remediation_group")
        if (
            not isinstance(group, str)
            or not group.strip()
            or len(group.strip()) > 160
            or len(group.strip().lower()) > 160
            or any(ord(ch) < 32 for ch in group)
        ):
            raise ValueError("A valid remediation_group is required")
        try:
            request = RetestRequestIn.model_validate(
                {key: value for key, value in normalized.items() if key != "remediation_group"}
            )
        except ValueError as exc:
            raise ValueError("A valid remediation group retest note is required") from exc
        normalized = {
            "remediation_group": group.strip(),
            **request.model_dump(exclude_none=True),
        }
    if action == "request_risk_acceptance":
        finding_id = normalized.get("finding_id")
        try:
            if not isinstance(finding_id, str):
                raise ValueError
            normalized["finding_id"] = str(uuid.UUID(finding_id))
            request = RiskAcceptanceIn.model_validate(
                {key: value for key, value in normalized.items() if key != "finding_id"}
            )
        except ValueError as exc:
            raise ValueError("A valid risk acceptance request is required") from exc
        normalized = {
            "finding_id": normalized["finding_id"],
            **request.model_dump(mode="json"),
        }
    return normalized


def require_action_permission(principal: Principal, action: str) -> None:
    """Authorize the proposed action with the same permission its executor requires."""
    permission = action_permission(action)
    principal.require(permission)
    if action == "update_github_alert":
        principal.require(Permission.FINDING_VALIDATE)


def action_permission(action: str) -> Permission:
    """Return the executor's permission without exposing the mutable registry mapping."""
    permission = _ACTION_PERMISSIONS.get(action)
    if permission is None:
        raise ValueError(f"Unsupported agent action: {action}")
    return permission


def registered_action_names() -> tuple[str, ...]:
    """Return the stable action surface consumed by the typed tool adapter."""
    return tuple(_ACTION_PERMISSIONS)


def new_agent_action(
    *,
    organization_id: uuid.UUID,
    session_id: uuid.UUID,
    requested_by_user_id: uuid.UUID | None,
    action: str,
    label: str,
    rationale: str | None,
    payload: Mapping[str, Any],
    depends_on_action_id: uuid.UUID | None = None,
) -> AgentAction:
    """Construct a pending action whose approval can only cover this exact payload."""
    validated = validate_action_payload(action, payload)
    return AgentAction(
        id=uuid.uuid4(),
        organization_id=organization_id,
        session_id=session_id,
        requested_by_user_id=requested_by_user_id,
        depends_on_action_id=depends_on_action_id,
        action=action,
        label=label.strip()[:300] or action.replace("_", " ").title(),
        rationale=rationale.strip()[:2000] if rationale and rationale.strip() else None,
        payload=validated,
        payload_digest=action_payload_digest(
            action, validated, depends_on_action_id=depends_on_action_id
        ),
        status="pending",
        execution_evidence={},
    )


async def action_dependency_state(session: AsyncSession, action: AgentAction) -> str:
    """Only an executed action in the same tenant and conversation unlocks a dependent step."""
    if action.depends_on_action_id is None:
        return "ready"
    dependency = (
        await session.execute(
            select(AgentAction).where(
                AgentAction.id == action.depends_on_action_id,
                AgentAction.organization_id == action.organization_id,
                AgentAction.session_id == action.session_id,
            )
        )
    ).scalar_one_or_none()
    if dependency is None or (
        action.action not in {"create_jira_ticket", "create_ticket"}
        or dependency.action != "update_canonical_work"
        or action.payload.get("canonical_finding_id") != dependency.payload.get("finding_id")
    ):
        return "failed"
    if dependency.status == "executed":
        return "ready"
    if dependency.status in {"pending", "approved"}:
        return "waiting"
    return "failed"


async def propose_action(
    session: AsyncSession,
    principal: Principal,
    *,
    session_id: uuid.UUID,
    action: str,
    label: str,
    rationale: str | None,
    payload: Mapping[str, Any],
) -> AgentAction:
    """Persist one separately approved action after tenant and permission checks."""
    principal.require(Permission.AGENT_CHAT)
    require_action_permission(principal, action)
    await TenantRepository(session, AgentSession, principal.organization_id).get_or_404(session_id)
    try:
        proposed = new_agent_action(
            organization_id=principal.organization_id,
            session_id=session_id,
            requested_by_user_id=principal.user_id,
            action=action,
            label=label,
            rationale=rationale,
            payload=payload,
        )
    except ValueError as exc:
        raise InvalidConfigurationError(str(exc), user_message=str(exc)) from exc
    session.add(proposed)
    await session.flush()
    await audit_service.record(
        session,
        action=audit_service.AuditAction.AGENT_ACTION_PROPOSED,
        principal=principal,
        resource_type="agent_action",
        resource_id=proposed.id,
        detail={"action": action, "payload_digest": proposed.payload_digest},
    )
    return proposed


async def execute_approved_action(
    session: AsyncSession,
    principal: Principal,
    proposed: AgentAction,
    *,
    settings: Settings,
    redis: Any | None,
) -> AgentAction:
    """Execute one locked, tenant-scoped approval through existing provider services."""
    require_action_permission(principal, proposed.action)
    if proposed.organization_id != principal.organization_id:
        raise ConflictError("agent action organization mismatch")
    if (
        proposed.status != "approved"
        or proposed.approved_by_user_id is None
        or proposed.resolved_at is None
    ):
        raise ConflictError(
            "agent action is not approved", user_message="Approve this action before running it."
        )
    if proposed.payload_digest != action_payload_digest(
        proposed.action, proposed.payload, depends_on_action_id=proposed.depends_on_action_id
    ):
        raise ConflictError(
            "agent action payload changed",
            user_message="This action request changed. Create a new request.",
        )
    try:
        payload = validate_action_payload(proposed.action, proposed.payload)
    except ValueError as exc:
        raise ConflictError(
            "agent action payload invalid", user_message="This action request is no longer valid."
        ) from exc

    if proposed.action == "sync_github_alerts":
        result = await external_alert_service.sync_github_alerts(
            session, principal, settings=settings, redis=redis
        )
        summary = f"{result.total} alerts synced"
        evidence = {
            "outcome": "synced", "source": "github", "record_count": int(result.total),
            "missing_source_records": int(getattr(result, "missing_source_records", 0)),
        }
    elif proposed.action == "sync_gitlab_alerts":
        result = await external_alert_service.sync_gitlab_alerts(
            session, principal, settings=settings, redis=redis
        )
        summary = f"{result.total} alerts synced"
        evidence = {
            "outcome": "synced", "source": "gitlab", "record_count": int(result.total),
            "missing_source_records": int(result.missing_source_records),
        }
    elif proposed.action == "sync_wazuh_alerts":
        result = await external_alert_service.sync_wazuh_alerts(
            session, principal, settings=settings, redis=redis
        )
        summary = f"{result.total} alerts synced"
        evidence = {"outcome": "synced", "source": "wazuh", "record_count": int(result.total)}
    elif proposed.action == "sync_sonarqube_alerts":
        result = await external_alert_service.sync_sonarqube_alerts(
            session, principal, settings=settings, redis=redis
        )
        summary = f"{result.total} alerts synced"
        evidence = {"outcome": "synced", "source": "sonarqube", "record_count": int(result.total)}
    elif proposed.action == "sync_snyk_issues":
        result = await external_alert_service.sync_snyk_issues(
            session, principal, settings=settings, redis=redis
        )
        summary = f"{result.total} issues synced"
        evidence = {"outcome": "synced", "source": "snyk", "record_count": int(result.total)}
    elif proposed.action == "sync_tenable_vulnerabilities":
        result = await external_alert_service.sync_tenable_vulnerabilities(
            session, principal, settings=settings, redis=redis
        )
        summary = f"{result.total} vulnerabilities synced"
        evidence = {"outcome": "synced", "source": "tenable", "record_count": int(result.total)}
    elif proposed.action == "sync_qualys_host_detections":
        result = await external_alert_service.sync_qualys_host_detections(
            session, principal, settings=settings, redis=redis
        )
        summary = f"{result.total} host detections synced"
        evidence = {"outcome": "synced", "source": "qualys", "record_count": int(result.total)}
    elif proposed.action == "sync_rapid7_vulnerabilities":
        result = await external_alert_service.sync_rapid7_vulnerabilities(
            session, principal, settings=settings, redis=redis
        )
        summary = f"{result.total} vulnerabilities synced"
        evidence = {
            "outcome": "synced",
            "source": "rapid7",
            "record_count": int(result.total),
            "absence_candidates": int(result.absence_candidates),
        }
    elif proposed.action == "sync_wiz_issues":
        result = await external_alert_service.sync_wiz_issues(
            session, principal, settings=settings, redis=redis
        )
        summary = f"{result.total} Wiz Issues synced"
        evidence = {
            "outcome": "synced",
            "source": "wiz",
            "record_count": int(result.total),
            "absence_candidates": int(result.absence_candidates),
            "missing_source_records": int(result.missing_source_records),
        }
    elif proposed.action == "sync_prisma_cloud_alerts":
        result = await external_alert_service.sync_prisma_cloud_alerts(
            session, principal, settings=settings, redis=redis
        )
        summary = f"{result.total} Prisma Cloud alerts synced"
        evidence = {
            "outcome": "synced",
            "source": "prisma_cloud",
            "record_count": int(result.total),
            "absence_candidates": int(result.absence_candidates),
        }
    elif proposed.action == "sync_crowdstrike_vulnerabilities":
        result = await external_alert_service.sync_crowdstrike_vulnerabilities(
            session, principal, settings=settings, redis=redis
        )
        summary = f"{result.total} CrowdStrike vulnerabilities synced"
        evidence = {
            "outcome": "synced",
            "source": "crowdstrike",
            "record_count": int(result.total),
            "absence_candidates": int(result.absence_candidates),
        }
    elif proposed.action == "sync_aws_security_hub_findings":
        result = await external_alert_service.sync_aws_security_hub_findings(
            session, principal, settings=settings, redis=redis
        )
        summary = f"{result.total} AWS Security Hub findings synced"
        evidence = {
            "outcome": "synced",
            "source": "aws_security_hub",
            "record_count": int(result.total),
            "absence_candidates": int(result.absence_candidates),
        }
    elif proposed.action == "sync_aws_inspector_findings":
        result = await external_alert_service.sync_aws_inspector_findings(
            session, principal, settings=settings, redis=redis
        )
        summary = f"{result.total} Amazon Inspector findings synced"
        evidence = {
            "outcome": "synced",
            "source": "aws_inspector",
            "record_count": int(result.total),
            "absence_candidates": int(result.absence_candidates),
        }
    elif proposed.action == "sync_hackerone_reports":
        result = await external_alert_service.sync_hackerone_reports(
            session, principal, settings=settings, redis=redis
        )
        summary = f"{result.total} HackerOne reports synced"
        evidence = {
            "outcome": "synced",
            "source": "hackerone",
            "record_count": int(result.total),
            "absence_candidates": int(result.absence_candidates),
        }
    elif proposed.action == "sync_bugcrowd_submissions":
        result = await external_alert_service.sync_bugcrowd_submissions(session, principal, settings=settings, redis=redis)
        summary = f"{result.total} Bugcrowd submissions synced"
        evidence = {"outcome": "synced", "source": "bugcrowd", "record_count": int(result.total), "absence_candidates": int(result.absence_candidates)}
    elif proposed.action == "sync_checkmarx_results":
        result = await external_alert_service.sync_checkmarx_results(session, principal, settings=settings, redis=redis)
        summary = f"{result.total} Checkmarx results synced"
        evidence = {"outcome": "synced", "source": "checkmarx", "record_count": int(result.total), "absence_candidates": int(result.absence_candidates)}
    elif proposed.action == "sync_fortify_issues":
        result = await external_alert_service.sync_fortify_issues(session, principal, settings=settings, redis=redis)
        summary = f"{result.total} Fortify SSC issues synced"
        evidence = {"outcome": "synced", "source": "fortify", "record_count": int(result.total), "absence_candidates": int(result.absence_candidates)}
    elif proposed.action == "sync_azure_defender_alerts":
        result = await external_alert_service.sync_azure_defender_alerts(
            session, principal, settings=settings, redis=redis
        )
        summary = f"{result.total} Microsoft Defender for Cloud alerts synced"
        evidence = {
            "outcome": "synced",
            "source": "azure_defender",
            "record_count": int(result.total),
            "absence_candidates": int(result.absence_candidates),
        }
    elif proposed.action == "sync_gcp_scc_findings":
        result = await external_alert_service.sync_gcp_scc_findings(
            session, principal, settings=settings, redis=redis
        )
        summary = f"{result.total} Google Security Command Center findings synced"
        evidence = {
            "outcome": "synced",
            "source": "gcp_scc",
            "record_count": int(result.total),
            "absence_candidates": int(result.absence_candidates),
        }
    elif proposed.action == "sync_burp_dast_findings":
        result = await external_alert_service.sync_burp_dast_findings(
            session, principal, settings=settings, redis=redis
        )
        summary = f"{result.total} Burp Suite DAST findings synced"
        evidence = {
            "outcome": "synced",
            "source": "burp_dast",
            "record_count": int(result.total),
            "absence_candidates": int(result.absence_candidates),
        }
    elif proposed.action == "update_github_alert":
        alert = await external_alert_service.set_github_alert_state(
            session,
            principal,
            uuid.UUID(payload["alert_id"]),
            decision=payload["decision"],
            reason=payload.get("reason"),
            comment=payload.get("comment"),
            settings=settings,
            redis=redis,
        )
        summary = f"GitHub alert {alert.status}"
        evidence = {
            "outcome": "updated",
            "resource": {"type": "github_alert", "id": payload["alert_id"]},
            "status": str(alert.status),
        }
    elif proposed.action in {"create_jira_ticket", "create_ticket"}:
        ticket_target = payload.get("canonical_finding_id") or payload["finding_id"]
        provider = payload.get("provider", "jira")
        if "canonical_finding_id" in payload:
            ticket = await ticket_service.create_canonical_ticket(
                session,
                principal,
                uuid.UUID(ticket_target),
                settings=settings,
                redis=redis,
                project_key=payload.get("project_key"),
                issue_type=payload.get("issue_type"),
                assignee=payload.get("assignee"),
                by_agent=True,
                provider=provider,
            )
        else:
            ticket = await ticket_service.create_ticket(
                session,
                principal,
                uuid.UUID(ticket_target),
                settings=settings,
                redis=redis,
                project_key=payload.get("project_key"),
                issue_type=payload.get("issue_type"),
                assignee=payload.get("assignee"),
                by_agent=True,
                provider=provider,
            )
        summary = f"{provider.replace('_', ' ').title()} ticket {ticket.external_key} linked"
        evidence = {
            "outcome": "created",
            "resource": {"type": f"{provider}_ticket", "id": str(ticket.external_key)},
            "ticket_link_id": str(getattr(ticket, "id", "")),
            "ticket_url": getattr(ticket, "url", None),
        }
        evidence["canonical_finding_id" if "canonical_finding_id" in payload else "finding_id"] = str(
            ticket_target
        )
    elif proposed.action == "refresh_ticket_status":
        ticket = await ticket_service.refresh_ticket_status(
            session,
            principal,
            uuid.UUID(payload["ticket_id"]),
            settings=settings,
            redis=redis,
        )
        summary = (
            f"{ticket.provider.replace('_', ' ').title()} ticket {ticket.external_key} "
            f"status refreshed to {ticket.external_status or 'unknown'}"
        )
        evidence = {
            "outcome": "refreshed",
            "resource": {"type": f"{ticket.provider}_ticket", "id": str(ticket.external_key)},
            "ticket_link_id": str(ticket.id),
            "external_key": ticket.external_key,
            "external_status": ticket.external_status,
            "ticket_url": ticket.url,
        }
    elif proposed.action == "update_canonical_work":
        finding = await canonical_work_service.update_work(
            session,
            principal,
            uuid.UUID(payload["finding_id"]),
            CanonicalWorkIn.model_validate(
                {key: value for key, value in payload.items() if key != "finding_id"}
            ),
        )
        summary = f"Remediation work updated to version {finding.status_version}"
        evidence = {
            "outcome": "updated",
            "resource": {"type": "canonical_finding", "id": payload["finding_id"]},
            "status_version": int(finding.status_version),
        }
    elif proposed.action == "bulk_update_canonical_work":
        findings = await canonical_work_service.bulk_update_work(
            session,
            principal,
            BulkCanonicalWorkIn.model_validate(payload),
        )
        summary = f"Remediation work updated for {len(findings)} findings"
        evidence = {
            "outcome": "updated",
            "resource": {"type": "canonical_finding_batch", "count": len(findings)},
            "findings": [
                {"id": str(finding.id), "status_version": int(finding.status_version)}
                for finding in findings
            ],
        }
    elif proposed.action == "request_retest":
        request = await remediation_governance_service.request_retest(
            session,
            principal,
            uuid.UUID(payload["finding_id"]),
            note=payload.get("note"),
        )
        summary = f"Retest request {request.id} created"
        evidence = {
            "outcome": "created",
            "resource": {"type": "retest_request", "id": str(request.id)},
            "canonical_finding_id": payload["finding_id"],
        }
    elif proposed.action == "request_remediation_group_retests":
        requests = await remediation_governance_service.request_remediation_group_retests(
            session,
            principal,
            remediation_group=payload["remediation_group"],
            note=payload.get("note"),
        )
        summary = (
            f"Verification requested for {len(requests)} findings in remediation group "
            f"{payload['remediation_group']}"
        )
        evidence = {
            "outcome": "created",
            "resource": {
                "type": "remediation_group_retest_batch",
                "id": payload["remediation_group"],
                "count": len(requests),
            },
            "retest_request_ids": [str(request.id) for request in requests],
        }
    elif proposed.action == "request_risk_acceptance":
        request = RiskAcceptanceIn.model_validate(
            {key: value for key, value in payload.items() if key != "finding_id"}
        )
        acceptance = await remediation_governance_service.request_risk_acceptance(
            session,
            principal,
            uuid.UUID(payload["finding_id"]),
            rationale=request.rationale,
            expires_at=request.expires_at,
        )
        summary = f"Risk acceptance request {acceptance.id} created"
        evidence = {
            "outcome": "created",
            "resource": {"type": "risk_acceptance", "id": str(acceptance.id)},
            "canonical_finding_id": payload["finding_id"],
        }
    elif proposed.action == "run_native_ai_posture":
        result = await control_plane_service.run_native_ai_posture_assessment(
            session, principal
        )
        summary = (
            f"Native AI posture assessed {result['assessed_resources']} resources; "
            f"{result['at_risk_resources']} require attention"
        )
        evidence = {
            "outcome": "assessed",
            "resource": {
                "type": "native_ai_posture_assessment",
                "id": str(result["policy_id"]),
            },
            "assessed_resources": result["assessed_resources"],
            "compliant_resources": result["compliant_resources"],
            "at_risk_resources": result["at_risk_resources"],
            "critical_resources": result["critical_resources"],
            "recommendation_ids": [str(value) for value in result["recommendation_ids"]],
            "external_connector_required": False,
        }
    elif proposed.action == "start_assessment":
        assessment = await assessment_service.create_assessment(
            session,
            principal,
            AssessmentCreateIn(
                targets=[payload["target"]],
                authorization=AuthorizationIn(
                    confirmed=True,
                    attestation_text=(
                        "The approving user confirms authorization to assess the exact target "
                        "in this action and the supplied evidence reference."
                    ),
                    evidence_reference=payload["authorization_reference"],
                ),
            ),
            settings,
        )
        run_id, _dispatch_id = stage_assessment_run(session, principal, assessment)
        proposed.run_id = run_id
        summary = f"Assessment {assessment.id} queued; scanning has not completed"
        evidence = {
            "outcome": "queued",
            "resource": {"type": "assessment", "id": str(assessment.id)},
            "run_id": str(run_id),
            "target": payload["target"],
        }
    else:  # pragma: no cover - the allowlist above rejects this first
        raise ConflictError("unsupported agent action")

    proposed.status = "executed"
    proposed.executed_at = utcnow()
    proposed.result_summary = summary
    proposed.execution_evidence = evidence
    await audit_service.record(
        session,
        action=audit_service.AuditAction.AGENT_ACTION_EXECUTED,
        principal=principal,
        resource_type="agent_action",
        resource_id=proposed.id,
        detail={"action": proposed.action, "payload_digest": proposed.payload_digest},
    )
    return proposed


async def execute_approved_batch(
    session: AsyncSession,
    *,
    settings: Settings,
    redis: Any | None,
    limit: int = 5,
) -> int:
    """Recover approved work when a browser did not finish the execute request.

    The database row is the durable queue. SKIP LOCKED coordinates worker replicas
    and the API's immediate execute route; a crash before commit leaves the row
    approved for another sweep. Provider operations must therefore be idempotent.
    """
    prerequisite = aliased(AgentAction)
    waiting_on_prerequisite = exists(
        select(1).select_from(prerequisite).where(
            prerequisite.id == AgentAction.depends_on_action_id,
            prerequisite.organization_id == AgentAction.organization_id,
            prerequisite.session_id == AgentAction.session_id,
            prerequisite.status.in_(("pending", "approved")),
        )
    )
    rows = (
        (
            await session.execute(
                select(AgentAction)
                .where(
                    AgentAction.status == "approved",
                    or_(AgentAction.depends_on_action_id.is_(None), ~waiting_on_prerequisite),
                )
                .order_by(AgentAction.resolved_at, AgentAction.id)
                .limit(max(1, min(limit, 20)))
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    for action in rows:
        if await action_dependency_state(session, action) == "waiting":
            continue
        membership = None
        if action.approved_by_user_id is not None:
            membership = (
                await session.execute(
                    select(Membership.role)
                    .join(User, User.id == Membership.user_id)
                    .join(Organization, Organization.id == Membership.organization_id)
                    .where(
                        Membership.organization_id == action.organization_id,
                        Membership.user_id == action.approved_by_user_id,
                        Membership.accepted_at.is_not(None),
                        User.is_active.is_(True),
                        Organization.is_active.is_(True),
                    )
                )
            ).one_or_none()
        try:
            role = Role(membership[0]) if membership is not None else None
        except ValueError:
            role = None
        if role is None:
            await _fail_approved_action(
                session, action, "Approver is no longer an active organization member."
            )
            continue
        principal = Principal(
            user_id=action.approved_by_user_id,
            organization_id=action.organization_id,
            role=role,
            actor_type=ACTOR_AGENT,
        )
        try:
            require_action_permission(principal, action.action)
        except PermissionDeniedError:
            await _fail_approved_action(
                session, action, "Approver no longer has permission for this action."
            )
            continue
        await execute_and_settle_action(session, principal, action, settings=settings, redis=redis)
    return len(rows)


async def execute_and_settle_action(
    session: AsyncSession,
    principal: Principal,
    action: AgentAction,
    *,
    settings: Settings,
    redis: Any | None,
) -> AgentAction:
    """Run an approved action and persist a terminal result even on provider failure."""
    require_action_permission(principal, action.action)
    if action.status != "approved":
        raise ConflictError(
            "agent action is not approved", user_message="Approve this action before running it."
        )
    dependency = await action_dependency_state(session, action)
    if dependency == "waiting":
        raise ConflictError(
            "agent action dependency pending",
            user_message="Complete the prerequisite action before running this one.",
        )
    if dependency == "failed":
        await _fail_approved_action(
            session, action, "Prerequisite action was rejected, failed, or is unavailable."
        )
    else:
        try:
            async with session.begin_nested():
                await execute_approved_action(
                    session, principal, action, settings=settings, redis=redis
                )
        except CynuxError as exc:
            await _fail_approved_action(session, action, redact_text(exc.user_message)[:500])
        except Exception as exc:
            # Do not persist exception text: provider responses may echo credentials.
            log.error(
                "agent_action.unexpected_failure",
                action_id=str(action.id),
                action=action.action,
                error_type=type(exc).__name__,
            )
            await _fail_approved_action(
                session,
                action,
                "Action failed unexpectedly; review worker logs and retry with a new approval.",
            )
    for _attempt in range(3):
        try:
            async with session.begin_nested():
                await append_action_receipt(session, action)
            break
        except IntegrityError:
            # A concurrent chat turn may have taken the same sequence number.
            continue
        except Exception as exc:
            # An action that reached a provider must not be replayed because a receipt failed.
            log.warning(
                "agent_action.receipt_failed",
                action_id=str(action.id),
                error_type=type(exc).__name__,
            )
            break
    return action


async def _fail_approved_action(session: AsyncSession, action: AgentAction, reason: str) -> None:
    action.status = "failed"
    action.result_summary = reason
    action.execution_evidence = {
        "outcome": "failed",
        "action": action.action,
        "reason": reason,
    }
    await audit_service.record(
        session,
        action=audit_service.AuditAction.AGENT_ACTION_FAILED,
        resource_type="agent_action",
        resource_id=action.id,
        organization_id=action.organization_id,
        outcome=AuditOutcome.FAILURE,
        reason=reason,
        detail={"action": action.action, "payload_digest": action.payload_digest},
    )


async def resolve_action(
    session: AsyncSession,
    principal: Principal,
    action_id: uuid.UUID,
    *,
    approve: bool,
    note: str | None,
) -> AgentAction:
    """Resolve exactly one pending action; a later executor must recheck its hash."""
    proposed = (
        await session.execute(
            tenant_select(AgentAction, principal.organization_id)
            .where(AgentAction.id == action_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if proposed is None:
        # Preserve the repository convention: do not disclose cross-tenant records.
        return await TenantRepository(session, AgentAction, principal.organization_id).get_or_404(
            action_id
        )
    require_action_permission(principal, proposed.action)
    if proposed.status != "pending":
        raise ConflictError(
            "agent action already resolved",
            user_message="Someone already responded to this action request.",
        )
    if proposed.payload_digest != action_payload_digest(
        proposed.action, proposed.payload, depends_on_action_id=proposed.depends_on_action_id
    ):
        raise ConflictError(
            "agent action payload changed",
            user_message="This action request is no longer valid. Create a new request.",
        )
    proposed.status = "approved" if approve else "rejected"
    proposed.approved_by_user_id = principal.user_id
    proposed.resolved_at = utcnow()
    proposed.resolution_note = note.strip()[:2000] if note and note.strip() else None
    await audit_service.record(
        session,
        action=(
            audit_service.AuditAction.AGENT_ACTION_APPROVED
            if approve
            else audit_service.AuditAction.AGENT_ACTION_REJECTED
        ),
        principal=principal,
        resource_type="agent_action",
        resource_id=proposed.id,
        detail={"action": proposed.action, "payload_digest": proposed.payload_digest},
        reason=proposed.resolution_note,
    )
    return proposed


__all__ = [
    "action_permission",
    "action_payload_digest",
    "execute_and_settle_action",
    "execute_approved_action",
    "execute_approved_batch",
    "new_agent_action",
    "MONITORED_AUTONOMY_ACTIONS",
    "propose_action",
    "registered_action_names",
    "require_action_permission",
    "resolve_action",
    "validate_action_payload",
]
