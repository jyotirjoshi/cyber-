"""Provider-neutral AI policy, tool authorization, and access-graph primitives.

The module deliberately keeps request content transient.  Results and receipts contain
only canonical digests and bounded metadata, making the same code safe for hosted and
tenant BYOK model endpoints.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import uuid
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from app.core.errors import ConflictError, ResourceNotFoundError
from app.db.enums import Permission
from app.db.models.assurance import AIAccessEdge, AIInteractionReceipt, AIToolManifest
from app.db.models.control_plane import SecurityPolicy, SecurityResource
from app.db.repository import tenant_select
from app.services.ai_security import classify_sensitive_data
from app.services.context import Principal

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.core.config import Settings
    from app.schemas.assurance import (
        AIAccessEdgeCreateIn,
        AIRuntimeEvaluateIn,
        AIToolManifestCreateIn,
        OpenAIChatCompletionIn,
    )

SUPPORTED_PROVIDERS = frozenset(
    {"openai", "anthropic", "google", "openrouter", "azure_openai", "ollama", "vllm"}
)


def canonical_digest(value: Any) -> str:
    """SHA-256 of deterministic, UTF-8 JSON."""

    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class RuntimeDecision:
    provider: str
    model: str
    region: str | None
    decision: str
    reason_codes: tuple[str, ...]
    prompt_digest: str
    input_tokens_estimate: int
    requested_output_tokens: int
    estimated_cost_usd: Decimal
    retention_mode: str


@dataclass(frozen=True, slots=True)
class InteractionReceipt:
    request_key: str
    provider: str
    model: str
    region: str | None
    decision: str
    reason_codes: tuple[str, ...]
    prompt_digest: str
    output_digest: str
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: Decimal
    latency_ms: int
    retention_mode: str
    occurred_at: dt.datetime


@dataclass(frozen=True, slots=True)
class ToolManifest:
    server_key: str
    tool_name: str
    version: str
    argument_schema: dict[str, Any]
    permissions: tuple[str, ...]
    schema_digest: str


@dataclass(frozen=True, slots=True)
class ToolAuthorization:
    allowed: bool
    manifest_digest: str
    argument_digest: str
    approval_scope_digest: str
    authorized_at: dt.datetime


def _bounded_decimal(value: str | int | float | Decimal, *, label: str) -> Decimal:
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{label} must be a decimal") from exc
    if not result.is_finite() or result < 0:
        raise ValueError(f"{label} must be finite and non-negative")
    return result


def evaluate_runtime_request(
    *,
    provider: str,
    model: str,
    region: str | None,
    content: str,
    requested_output_tokens: int,
    estimated_cost_usd: str | int | float | Decimal,
    policy: Mapping[str, Any],
    direction: str = "prompt",
) -> RuntimeDecision:
    """Apply pre-flight controls without retaining request content."""

    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError("unsupported AI provider")
    if direction not in {"prompt", "output"}:
        raise ValueError("direction must be prompt or output")
    if not model or len(model) > 512:
        raise ValueError("model must be a bounded identifier")
    if not 1 <= requested_output_tokens <= 1_000_000:
        raise ValueError("requested output tokens are out of range")
    prompt_digest = canonical_digest({"content": content})
    raw_input_tokens = max(1, (len(content) + 3) // 4)
    max_prompt_chars = int(policy.get("max_prompt_chars", 1_000_000))
    if len(content) > max_prompt_chars:
        content = content[:max_prompt_chars]
        truncated = True
    else:
        truncated = False

    cost = _bounded_decimal(estimated_cost_usd, label="estimated cost")
    input_tokens = raw_input_tokens
    reasons: list[str] = []
    blocking_reasons: list[str] = []
    allowed_providers = set(policy.get("allowed_providers") or SUPPORTED_PROVIDERS)
    allowed_models = set(policy.get("allowed_models") or [model])
    allowed_regions = set(policy.get("allowed_regions") or ([region] if region else []))
    if provider not in allowed_providers:
        blocking_reasons.append("provider_not_allowed")
    if truncated:
        blocking_reasons.append("prompt_size_exceeded")
    if model not in allowed_models:
        blocking_reasons.append("model_not_allowed")
    if allowed_regions and region not in allowed_regions:
        blocking_reasons.append("region_not_allowed")
    if input_tokens > int(policy.get("max_input_tokens", 1_000_000)):
        blocking_reasons.append("input_budget_exceeded")
    if requested_output_tokens > int(policy.get("max_output_tokens", 1_000_000)):
        blocking_reasons.append("output_budget_exceeded")
    if cost > _bounded_decimal(policy.get("max_cost_usd", "1000000"), label="cost budget"):
        blocking_reasons.append("cost_budget_exceeded")
    reasons.extend(blocking_reasons)
    classification = classify_sensitive_data(content)
    reasons.extend(classification.labels)
    lowered = content.lower()
    injection = direction == "prompt" and any(
        phrase in lowered
        for phrase in (
            "ignore previous instructions",
            "ignore all previous instructions",
            "reveal the system prompt",
            "bypass guardrail",
            "bypass approval",
        )
    )
    if injection:
        reasons.append("prompt_injection")
    urls = re.findall(r"(?i)\b(?:https?://|javascript:|data:)[^\s<>()]+", content)
    allowed_domains = {str(item).lower().rstrip(".") for item in policy.get("allowed_link_domains", [])}
    blocked_domains = {str(item).lower().rstrip(".") for item in policy.get("blocked_link_domains", [])}
    unapproved_link = False
    for url in urls:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        explicitly_blocked = any(host == item or host.endswith(f".{item}") for item in blocked_domains)
        outside_allowlist = bool(allowed_domains) and not any(
            host == item or host.endswith(f".{item}") for item in allowed_domains
        )
        unsafe_scheme = parsed.scheme.lower() not in {"http", "https"}
        if explicitly_blocked or outside_allowlist or unsafe_scheme:
            unapproved_link = True
            break
    if unapproved_link:
        reasons.append("unapproved_link")
        if policy.get("block_unapproved_links", True):
            blocking_reasons.append("unapproved_link")
    if direction == "output" and classification.labels and policy.get("block_sensitive_output", False):
        reasons.append("sensitive_output")
        blocking_reasons.append("sensitive_output")
    decision = (
        "block"
        if blocking_reasons or (injection and policy.get("block_prompt_injection", True))
        else "allow"
    )
    if decision == "allow" and classification.labels:
        decision = "redact" if policy.get("redact_sensitive_data", True) else "allow"
    retention = str(policy.get("retention_mode", "digest_only"))
    if retention not in {"none", "digest_only", "metadata"}:
        raise ValueError("invalid retention mode")
    return RuntimeDecision(
        provider=provider,
        model=model,
        region=region,
        decision=decision,
        reason_codes=tuple(dict.fromkeys(reasons)),
        prompt_digest=prompt_digest,
        input_tokens_estimate=input_tokens,
        requested_output_tokens=requested_output_tokens,
        estimated_cost_usd=cost,
        retention_mode=retention,
    )


def build_interaction_receipt(
    *,
    request_key: str,
    result: RuntimeDecision,
    output: str,
    input_tokens: int,
    output_tokens: int,
    latency_ms: int,
    occurred_at: dt.datetime | None = None,
) -> InteractionReceipt:
    """Build a digest-only post-flight receipt."""

    if min(input_tokens, output_tokens, latency_ms) < 0:
        raise ValueError("usage and latency values must be non-negative")
    return InteractionReceipt(
        request_key=request_key,
        provider=result.provider,
        model=result.model,
        region=result.region,
        decision=result.decision,
        reason_codes=result.reason_codes,
        prompt_digest=result.prompt_digest,
        output_digest=canonical_digest({"output": output}),
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        estimated_cost_usd=result.estimated_cost_usd,
        latency_ms=latency_ms,
        retention_mode=result.retention_mode,
        occurred_at=occurred_at or dt.datetime.now(dt.UTC),
    )


def build_tool_manifest(
    *,
    server_key: str,
    tool_name: str,
    version: str,
    argument_schema: dict[str, Any],
    permissions: Iterable[str],
) -> ToolManifest:
    if argument_schema.get("type") != "object":
        raise ValueError("tool argument schema must have an object root")
    if argument_schema.get("additionalProperties") is not False:
        raise ValueError("tool argument schema must reject additional properties")
    material = {
        "server_key": server_key,
        "tool_name": tool_name,
        "version": version,
        "argument_schema": argument_schema,
        "permissions": sorted(set(permissions)),
    }
    return ToolManifest(
        server_key=server_key,
        tool_name=tool_name,
        version=version,
        argument_schema=argument_schema,
        permissions=tuple(material["permissions"]),
        schema_digest=canonical_digest(material),
    )


def _validate_schema(value: Any, schema: Mapping[str, Any], path: str = "arguments") -> None:
    expected = schema.get("type")
    type_map = {
        "object": dict,
        "array": list,
        "string": str,
        "integer": int,
        "number": (int, float, Decimal),
        "boolean": bool,
        "null": type(None),
    }
    if expected in type_map and not isinstance(value, type_map[expected]):
        raise ConflictError(f"{path} must be {expected}")
    if "enum" in schema and value not in schema["enum"]:
        raise ConflictError(f"{path} is not an allowed value")
    if expected == "object":
        properties = schema.get("properties") or {}
        required = set(schema.get("required") or [])
        missing = required - set(value)
        if missing:
            raise ConflictError(f"{path} is missing required properties: {', '.join(sorted(missing))}")
        extra = set(value) - set(properties)
        if extra and schema.get("additionalProperties") is False:
            raise ConflictError(f"{path} contains additional properties: {', '.join(sorted(extra))}")
        for key, child in value.items():
            if key in properties:
                _validate_schema(child, properties[key], f"{path}.{key}")
    elif expected == "array":
        minimum = int(schema.get("minItems", 0))
        maximum = int(schema.get("maxItems", 10_000))
        if not minimum <= len(value) <= maximum:
            raise ConflictError(f"{path} array length is outside policy")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, child in enumerate(value):
                _validate_schema(child, item_schema, f"{path}[{index}]")
    elif expected == "string":
        if len(value) < int(schema.get("minLength", 0)):
            raise ConflictError(f"{path} is shorter than allowed")
        if len(value) > int(schema.get("maxLength", 100_000)):
            raise ConflictError(f"{path} is longer than allowed")
        if schema.get("pattern") and re.search(str(schema["pattern"]), value) is None:
            raise ConflictError(f"{path} does not match the required pattern")


def authorize_tool_call(
    *,
    manifest: ToolManifest,
    arguments: dict[str, Any],
    granted_permissions: set[str],
    expected_manifest_digest: str,
    approval_scope_digest: str,
    delegation_expires_at: dt.datetime | None = None,
    now: dt.datetime | None = None,
    revoked: bool = False,
) -> ToolAuthorization:
    """Authorize one exact tool call; changing any argument invalidates approval."""

    current_time = now or dt.datetime.now(dt.UTC)
    if revoked:
        raise ConflictError("Tool authorization was revoked")
    if expected_manifest_digest != manifest.schema_digest:
        raise ConflictError("Tool manifest changed after approval")
    if delegation_expires_at and current_time >= delegation_expires_at:
        raise ConflictError("Tool delegation expired")
    missing = set(manifest.permissions) - granted_permissions
    if missing:
        raise ConflictError(f"Missing tool permissions: {', '.join(sorted(missing))}")
    _validate_schema(arguments, manifest.argument_schema)
    expected_scope = canonical_digest(
        {
            "manifest_digest": manifest.schema_digest,
            "arguments": arguments,
            "action": "execute",
        }
    )
    if approval_scope_digest != expected_scope:
        raise ConflictError("Tool approval does not match the exact action scope")
    return ToolAuthorization(
        allowed=True,
        manifest_digest=manifest.schema_digest,
        argument_digest=canonical_digest(arguments),
        approval_scope_digest=approval_scope_digest,
        authorized_at=current_time,
    )


def access_reachability(
    edges: Iterable[Mapping[str, Any]], source: str, *, max_depth: int = 8
) -> dict[str, int]:
    """Return minimum hop distance to every reachable AI/data resource."""

    if not 1 <= max_depth <= 32:
        raise ValueError("max_depth must be between 1 and 32")
    graph: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        if edge.get("approved", True):
            graph[str(edge["source"])].add(str(edge["target"]))
    distances: dict[str, int] = {source: 0}
    pending = deque([source])
    while pending:
        node = pending.popleft()
        depth = distances[node]
        if depth >= max_depth:
            continue
        for target in sorted(graph[node]):
            if target not in distances:
                distances[target] = depth + 1
                pending.append(target)
    distances.pop(source, None)
    return distances


def access_paths(
    edges: Iterable[Mapping[str, Any]],
    source: str,
    target: str,
    *,
    max_depth: int = 8,
    max_paths: int = 100,
) -> list[list[str]]:
    """Enumerate bounded simple paths for explainable blast-radius answers."""

    graph: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        if edge.get("approved", True):
            graph[str(edge["source"])].add(str(edge["target"]))
    results: list[list[str]] = []
    pending: deque[list[str]] = deque([[source]])
    while pending and len(results) < max_paths:
        path = pending.popleft()
        if len(path) - 1 >= max_depth:
            continue
        for child in sorted(graph[path[-1]]):
            if child in path:
                continue
            candidate = [*path, child]
            if child == target:
                results.append(candidate)
            else:
                pending.append(candidate)
    return results


async def evaluate_and_record(
    session: AsyncSession, principal: Principal, payload: AIRuntimeEvaluateIn
) -> tuple[RuntimeDecision, AIInteractionReceipt]:
    """Evaluate a transient request and persist only its policy receipt."""

    principal.require(Permission.ORG_READ)
    decision = evaluate_runtime_request(
        provider=payload.provider,
        model=payload.model,
        region=payload.region,
        content=payload.content,
        requested_output_tokens=payload.requested_output_tokens,
        estimated_cost_usd=payload.estimated_cost_usd,
        policy=payload.policy,
        direction=payload.direction,
    )
    existing = await session.scalar(
        tenant_select(AIInteractionReceipt, principal.organization_id).where(
            AIInteractionReceipt.request_key == payload.request_key
        )
    )
    if existing is not None:
        if existing.prompt_digest != decision.prompt_digest:
            raise ConflictError("AI request key was replayed with different content")
        return decision, existing
    row = AIInteractionReceipt(
        organization_id=principal.organization_id,
        request_key=payload.request_key,
        application_key=payload.application_key,
        agent_key=payload.agent_key,
        model_key=payload.model,
        provider=payload.provider,
        region=payload.region,
        decision=decision.decision,
        prompt_digest=decision.prompt_digest,
        output_digest=None,
        tool_keys=[],
        reason_codes=list(decision.reason_codes),
        input_tokens=decision.input_tokens_estimate,
        output_tokens=0,
        cost_usd=decision.estimated_cost_usd,
        latency_ms=None,
        retention_mode=decision.retention_mode,
        occurred_at=dt.datetime.now(dt.UTC),
    )
    session.add(row)
    await session.flush()
    return decision, row


async def proxy_chat_completion(
    session: AsyncSession,
    principal: Principal,
    payload: OpenAIChatCompletionIn,
    *,
    settings: Settings,
) -> dict[str, Any]:
    """Run one non-streaming OpenAI-compatible completion through tenant policy and BYOK."""

    from app.db.enums import IntegrationKind
    from app.llm.base import LLMMessage
    from app.llm.gateway import LLMGateway
    from app.services.integration import resolve_settings

    principal.require(Permission.AGENT_CHAT)
    request_key = payload.request_key or f"chat-{uuid.uuid4()}"
    existing = await session.scalar(
        tenant_select(AIInteractionReceipt, principal.organization_id).where(
            AIInteractionReceipt.request_key == request_key
        )
    )
    if existing is not None:
        raise ConflictError(
            "This request key was already consumed; raw model output is intentionally not retained"
        )
    policy_row = await session.scalar(
        tenant_select(SecurityPolicy, principal.organization_id)
        .where(
            SecurityPolicy.kind.in_(["ai_gateway", "ai_guard"]),
            SecurityPolicy.status == "active",
        )
        .order_by(SecurityPolicy.updated_at.desc())
        .limit(1)
    )
    policy: dict[str, Any] = dict(policy_row.rules) if policy_row else {}
    scoped = await resolve_settings(
        session, principal, IntegrationKind.LLM, settings=settings, require=True
    )
    provider = payload.provider or (str(scoped.llm.provider) if scoped.llm.provider else "")
    if not provider:
        raise ConflictError("No tenant AI provider is configured")
    content = "\n".join(f"{message.role}:{message.content}" for message in payload.messages)
    input_estimate = max(1, (len(content) + 3) // 4)
    prices = policy.get("cost_estimate") if isinstance(policy.get("cost_estimate"), dict) else {}
    input_price = _bounded_decimal(prices.get("input_usd_per_million", 0), label="input price")
    output_price = _bounded_decimal(prices.get("output_usd_per_million", 0), label="output price")
    estimated_cost = (
        Decimal(input_estimate) * input_price + Decimal(payload.max_tokens) * output_price
    ) / Decimal(1_000_000)
    preflight = evaluate_runtime_request(
        provider=provider,
        model=payload.model,
        region=payload.region,
        content=content,
        requested_output_tokens=payload.max_tokens,
        estimated_cost_usd=estimated_cost,
        policy=policy,
        direction="prompt",
    )
    if preflight.decision == "block":
        row = AIInteractionReceipt(
            organization_id=principal.organization_id,
            request_key=request_key,
            application_key=payload.application_key,
            agent_key=payload.agent_key,
            model_key=payload.model,
            provider=provider,
            region=payload.region,
            decision="block",
            prompt_digest=preflight.prompt_digest,
            output_digest=None,
            tool_keys=[],
            reason_codes=list(preflight.reason_codes),
            input_tokens=preflight.input_tokens_estimate,
            output_tokens=0,
            cost_usd=Decimal("0"),
            latency_ms=0,
            retention_mode=preflight.retention_mode,
            occurred_at=dt.datetime.now(dt.UTC),
        )
        session.add(row)
        await session.flush()
        # A policy denial is itself security evidence. Persist the digest-only
        # receipt before raising so the request transaction cannot roll it back.
        await session.commit()
        raise ConflictError("AI request was blocked by tenant policy")
    messages = [
        LLMMessage(
            role=message.role,
            content=(
                classify_sensitive_data(message.content).redacted_content
                if preflight.decision == "redact"
                else message.content
            ),
        )
        for message in payload.messages
    ]
    gateway = LLMGateway(scoped)
    try:
        response = await gateway.complete_custom(
            provider=provider,
            model=payload.model,
            messages=messages,
            max_output_tokens=payload.max_tokens,
            temperature=payload.temperature,
        )
    finally:
        await gateway.aclose()
    postflight = evaluate_runtime_request(
        provider=provider,
        model=payload.model,
        region=payload.region,
        content=response.text,
        requested_output_tokens=max(1, response.usage.output_tokens),
        estimated_cost_usd=estimated_cost,
        policy=policy,
        direction="output",
    )
    safe_output = (
        classify_sensitive_data(response.text).redacted_content
        if postflight.decision == "redact"
        else response.text
    )
    actual_cost = (
        Decimal(response.usage.input_tokens) * input_price
        + Decimal(response.usage.output_tokens) * output_price
    ) / Decimal(1_000_000)
    receipt = build_interaction_receipt(
        request_key=request_key,
        result=postflight,
        output=response.text,
        input_tokens=response.usage.input_tokens,
        output_tokens=response.usage.output_tokens,
        latency_ms=response.latency_ms,
    )
    row = AIInteractionReceipt(
        organization_id=principal.organization_id,
        request_key=request_key,
        application_key=payload.application_key,
        agent_key=payload.agent_key,
        model_key=payload.model,
        provider=provider,
        region=payload.region,
        decision=postflight.decision,
        prompt_digest=preflight.prompt_digest,
        output_digest=receipt.output_digest,
        tool_keys=[],
        reason_codes=list(dict.fromkeys([*preflight.reason_codes, *postflight.reason_codes])),
        input_tokens=response.usage.input_tokens,
        output_tokens=response.usage.output_tokens,
        cost_usd=actual_cost,
        latency_ms=response.latency_ms,
        retention_mode=postflight.retention_mode,
        occurred_at=receipt.occurred_at,
    )
    session.add(row)
    await session.flush()
    if postflight.decision == "block":
        # Do not lose the output-inspection decision when the response body is
        # intentionally withheld from the caller.
        await session.commit()
        raise ConflictError("AI output was blocked by tenant policy")
    return {
        "id": request_key,
        "object": "chat.completion",
        "created": int(receipt.occurred_at.timestamp()),
        "model": response.model or payload.model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": safe_output},
                "finish_reason": response.stop_reason or "stop",
            }
        ],
        "usage": {
            "prompt_tokens": response.usage.input_tokens,
            "completion_tokens": response.usage.output_tokens,
            "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
        },
        "policy_receipt": {
            "decision": postflight.decision,
            "reason_codes": row.reason_codes,
            "prompt_digest": row.prompt_digest,
            "output_digest": row.output_digest,
            "retention_mode": row.retention_mode,
        },
    }


async def register_tool_manifest(
    session: AsyncSession, principal: Principal, payload: AIToolManifestCreateIn
) -> AIToolManifest:
    principal.require(Permission.INTEGRATION_MANAGE)
    built = build_tool_manifest(
        server_key=payload.server_key,
        tool_name=payload.tool_name,
        version=payload.version,
        argument_schema=payload.argument_schema,
        permissions=payload.permissions,
    )
    exact = await session.scalar(
        tenant_select(AIToolManifest, principal.organization_id).where(
            AIToolManifest.server_key == payload.server_key,
            AIToolManifest.tool_name == payload.tool_name,
            AIToolManifest.version == payload.version,
        )
    )
    if exact is not None:
        if exact.schema_digest != built.schema_digest:
            raise ConflictError("An immutable tool manifest version cannot be overwritten")
        return exact
    previous = await session.scalar(
        tenant_select(AIToolManifest, principal.organization_id)
        .where(
            AIToolManifest.server_key == payload.server_key,
            AIToolManifest.tool_name == payload.tool_name,
        )
        .order_by(AIToolManifest.observed_at.desc())
        .limit(1)
    )
    if previous is not None and previous.schema_digest != built.schema_digest:
        previous.approved = False
        previous.status = "changed"
    row = AIToolManifest(
        organization_id=principal.organization_id,
        server_key=payload.server_key,
        tool_name=payload.tool_name,
        version=payload.version,
        schema_digest=built.schema_digest,
        argument_schema=payload.argument_schema,
        result_schema=payload.result_schema,
        permissions=list(built.permissions),
        owner_team=payload.owner_team,
        approved=False,
        status="pending_review",
        observed_at=dt.datetime.now(dt.UTC),
    )
    session.add(row)
    await session.flush()
    return row


async def decide_tool_manifest(
    session: AsyncSession,
    principal: Principal,
    manifest_id: uuid.UUID,
    *,
    approved: bool,
    expected_schema_digest: str,
) -> AIToolManifest:
    principal.require(Permission.INTEGRATION_MANAGE)
    row = await session.scalar(
        tenant_select(AIToolManifest, principal.organization_id)
        .where(AIToolManifest.id == manifest_id)
        .with_for_update()
    )
    if row is None:
        raise ResourceNotFoundError("AI tool manifest not found")
    if row.schema_digest != expected_schema_digest:
        raise ConflictError("Tool manifest changed after review")
    row.approved = approved
    row.status = "approved" if approved else "revoked"
    row.approved_at = dt.datetime.now(dt.UTC) if approved else None
    await session.flush()
    return row


async def authorize_persisted_tool_call(
    session: AsyncSession,
    principal: Principal,
    manifest_id: uuid.UUID,
    *,
    arguments: dict[str, Any],
    expected_manifest_digest: str,
    approval_scope_digest: str,
    delegation_expires_at: dt.datetime | None,
) -> ToolAuthorization:
    principal.require(Permission.INTEGRATION_MANAGE)
    row = await session.scalar(
        tenant_select(AIToolManifest, principal.organization_id).where(
            AIToolManifest.id == manifest_id
        )
    )
    if row is None:
        raise ResourceNotFoundError("AI tool manifest not found")
    manifest = ToolManifest(
        server_key=row.server_key,
        tool_name=row.tool_name,
        version=row.version,
        argument_schema=row.argument_schema,
        permissions=tuple(row.permissions),
        schema_digest=row.schema_digest,
    )
    return authorize_tool_call(
        manifest=manifest,
        arguments=arguments,
        granted_permissions=set(row.permissions),
        expected_manifest_digest=expected_manifest_digest,
        approval_scope_digest=approval_scope_digest,
        delegation_expires_at=delegation_expires_at,
        revoked=not row.approved or row.status != "approved",
    )


async def upsert_access_edge(
    session: AsyncSession, principal: Principal, payload: AIAccessEdgeCreateIn
) -> AIAccessEdge:
    principal.require(Permission.INTEGRATION_MANAGE)
    resources = await session.scalars(
        tenant_select(SecurityResource, principal.organization_id).where(
            SecurityResource.id.in_([payload.source_resource_id, payload.target_resource_id])
        )
    )
    if len(list(resources.all())) != 2:
        raise ResourceNotFoundError("AI access graph resource not found")
    row = await session.scalar(
        tenant_select(AIAccessEdge, principal.organization_id).where(
            AIAccessEdge.source_resource_id == payload.source_resource_id,
            AIAccessEdge.target_resource_id == payload.target_resource_id,
            AIAccessEdge.relation == payload.relation,
        )
    )
    now = dt.datetime.now(dt.UTC)
    if row is None:
        row = AIAccessEdge(
            organization_id=principal.organization_id,
            source_resource_id=payload.source_resource_id,
            target_resource_id=payload.target_resource_id,
            relation=payload.relation,
            privileges=payload.privileges,
            approved=payload.approved,
            source_kind=payload.source_kind,
            provenance=payload.provenance,
            first_seen_at=now,
            last_seen_at=now,
        )
        session.add(row)
    else:
        row.privileges = payload.privileges
        row.approved = payload.approved
        row.provenance = payload.provenance
        row.last_seen_at = now
    await session.flush()
    return row


async def query_access_graph(
    session: AsyncSession,
    principal: Principal,
    *,
    source_resource_id: uuid.UUID,
    target_resource_id: uuid.UUID | None,
    max_depth: int,
) -> dict[str, Any]:
    principal.require(Permission.ORG_READ)
    rows = await session.scalars(
        tenant_select(AIAccessEdge, principal.organization_id).where(AIAccessEdge.approved.is_(True))
    )
    edges = [
        {
            "source": str(row.source_resource_id),
            "target": str(row.target_resource_id),
            "approved": row.approved,
        }
        for row in rows.all()
    ]
    source = str(source_resource_id)
    reachable = access_reachability(edges, source, max_depth=max_depth)
    paths = (
        access_paths(edges, source, str(target_resource_id), max_depth=max_depth)
        if target_resource_id
        else []
    )
    return {"source_resource_id": source_resource_id, "reachable": reachable, "paths": paths}


__all__ = [
    "InteractionReceipt",
    "RuntimeDecision",
    "SUPPORTED_PROVIDERS",
    "ToolAuthorization",
    "ToolManifest",
    "access_paths",
    "access_reachability",
    "authorize_tool_call",
    "authorize_persisted_tool_call",
    "build_interaction_receipt",
    "build_tool_manifest",
    "canonical_digest",
    "evaluate_runtime_request",
    "evaluate_and_record",
    "proxy_chat_completion",
    "decide_tool_manifest",
    "query_access_graph",
    "register_tool_manifest",
    "upsert_access_edge",
]
