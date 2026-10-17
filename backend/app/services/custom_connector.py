"""Validation and bounded execution primitives for declarative HTTP connectors."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import ipaddress
import json
import re
import socket
from collections.abc import Mapping
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.core.errors import ConflictError, CynuxError, InvalidConfigurationError
from app.db.base import utcnow
from app.db.enums import Permission
from app.db.models.custom_connector import CustomConnector, CustomConnectorRun
from app.db.models.integration import Integration
from app.integrations.http import ResilientClient, build_client
from app.schemas.custom_connector import CustomConnectorIn
from app.services.context import Principal

_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,500}$")
_JSON_PATH = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,9}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_OPEN_STATES = frozenset({"new", "active", "open", "reopened", "unresolved"})
_FIXED_STATES = frozenset({"fixed", "resolved", "mitigated", "closed"})
_MAX_RECORDS_PER_RUN = 50_000


class ConnectorPageClient(Protocol):
    async def get_json(
        self, path: str, *, params: dict[str, Any] | None = None, **kwargs: object
    ) -> Any: ...


class RuntimeConnectorClient:
    """JSON page client that permits only bounded same-origin redirects."""

    def __init__(self, client: ResilientClient, *, base_url: str) -> None:
        self._client = client
        self._base_url = base_url

    async def get_json(
        self, path: str, *, params: dict[str, Any] | None = None, **_: object
    ) -> Any:
        request_target = path
        request_params = params
        for _redirect in range(4):
            response = await self._client.request("GET", request_target, params=request_params)
            if 300 <= response.status_code < 400:
                location = response.headers.get("location")
                target = urljoin(str(response.url), location or "")
                if not location or not safe_response_origin(self._base_url, target):
                    raise InvalidConfigurationError(
                        "custom connector redirect left its configured HTTPS origin"
                    )
                request_target, request_params = target, None
                continue
            if len(response.content) > 5 * 1024 * 1024:
                raise InvalidConfigurationError(
                    "custom connector response exceeded the 5 MiB safety limit"
                )
            try:
                return response.json()
            except ValueError as exc:
                raise InvalidConfigurationError(
                    "custom connector returned invalid JSON"
                ) from exc
        raise InvalidConfigurationError("custom connector exceeded the redirect limit")

    async def aclose(self) -> None:
        await self._client.aclose()


def validate_definition(payload: CustomConnectorIn) -> dict[str, Any]:
    parsed = urlsplit(payload.base_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise InvalidConfigurationError("custom connector base URL must be a fixed HTTPS origin")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise InvalidConfigurationError("custom connector destination must be public")
    routes: list[dict[str, Any]] = []
    for route in payload.routes:
        if not isinstance(route, dict) or set(route).difference({"name", "method", "path", "records_path"}):
            raise InvalidConfigurationError("custom connector route contains unsupported fields")
        method, path = route.get("method", "GET"), route.get("path")
        if method != "GET" or not isinstance(path, str) or not _PATH.fullmatch(path) or ".." in path:
            raise InvalidConfigurationError("custom connectors allow bounded relative GET routes only")
        records_path = route.get("records_path", "items")
        if not isinstance(records_path, str) or not _JSON_PATH.fullmatch(records_path):
            raise InvalidConfigurationError("invalid connector records path")
        routes.append({"name": str(route.get("name") or path)[:160], "method": "GET", "path": path, "records_path": records_path})
    for output, source in payload.field_mapping.items():
        if not _JSON_PATH.fullmatch(output) or not _JSON_PATH.fullmatch(source):
            raise InvalidConfigurationError("connector mappings must use bounded JSON field paths")
    pagination = dict(payload.pagination)
    if set(pagination).difference({"type", "cursor_path", "query_parameter", "max_pages", "page_size"}):
        raise InvalidConfigurationError("unsupported connector pagination configuration")
    if pagination:
        if pagination.get("type") not in {"cursor", "page"}:
            raise InvalidConfigurationError("pagination type must be cursor or page")
        pagination["max_pages"] = max(1, min(int(pagination.get("max_pages", 20)), 100))
        pagination["page_size"] = max(1, min(int(pagination.get("page_size", 100)), 500))
    return {"base_url": payload.base_url.rstrip("/"), "routes": routes, "pagination": pagination, "field_mapping": dict(payload.field_mapping)}


async def create_connector(session: AsyncSession, principal: Principal, payload: CustomConnectorIn) -> CustomConnector:
    principal.require(Permission.INTEGRATION_MANAGE)
    definition = validate_definition(payload)
    row = CustomConnector(organization_id=principal.organization_id, created_by_id=principal.user_id, name=payload.name.strip(), output_type=payload.output_type, credential_integration_id=payload.credential_integration_id, rate_limit_per_minute=payload.rate_limit_per_minute, is_enabled=True, **definition)
    session.add(row)
    await session.flush()
    return row


def _definition_digest(connector: CustomConnector) -> str:
    document = {
        "base_url": connector.base_url,
        "routes": connector.routes,
        "pagination": connector.pagination,
        "field_mapping": connector.field_mapping,
        "output_type": connector.output_type,
        "credential_integration_id": (
            str(connector.credential_integration_id)
            if connector.credential_integration_id is not None
            else None
        ),
    }
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


async def reserve_connector_run(
    session: AsyncSession,
    principal: Principal,
    connector: CustomConnector,
    *,
    idempotency_key: str,
) -> tuple[CustomConnectorRun, bool]:
    """Reserve a durable run or replay the matching reservation."""
    principal.require(Permission.INTEGRATION_MANAGE)
    if connector.organization_id != principal.organization_id:
        raise InvalidConfigurationError("custom connector does not belong to this organization")
    key = idempotency_key.strip()
    if not key or len(key) > 160:
        raise InvalidConfigurationError("invalid custom connector idempotency key")
    digest = _definition_digest(connector)
    existing = await session.scalar(
        select(CustomConnectorRun)
        .where(
            CustomConnectorRun.organization_id == principal.organization_id,
            CustomConnectorRun.connector_id == connector.id,
            CustomConnectorRun.idempotency_key == key,
        )
        .with_for_update()
    )
    if existing is not None:
        if existing.request_digest != digest:
            raise ConflictError(
                "custom connector idempotency key was reused for a changed definition"
            )
        return existing, True
    row = CustomConnectorRun(
        organization_id=principal.organization_id,
        connector_id=connector.id,
        status="pending",
        idempotency_key=key,
        request_digest=digest,
        checkpoint={},
        result={},
        records_read=0,
        records_written=0,
        started_at=utcnow(),
    )
    session.add(row)
    await session.flush()
    return row, False


async def _assert_public_destination(base_url: str) -> None:
    host = urlsplit(base_url).hostname
    if not host:
        raise InvalidConfigurationError("custom connector base URL has no hostname")
    try:
        addresses = await asyncio.get_running_loop().getaddrinfo(
            host, 443, type=socket.SOCK_STREAM
        )
    except OSError as exc:
        raise InvalidConfigurationError(
            "custom connector hostname could not be resolved"
        ) from exc
    if not addresses:
        raise InvalidConfigurationError("custom connector hostname did not resolve")
    for item in addresses:
        address = ipaddress.ip_address(item[4][0])
        if not address.is_global or address in ipaddress.ip_network("169.254.169.254/32"):
            raise InvalidConfigurationError(
                "custom connector hostname resolved to a non-public address"
            )


async def _credential_headers(
    session: AsyncSession, connector: CustomConnector, *, settings: Settings
) -> dict[str, str]:
    headers = {"Accept": "application/json"}
    if connector.credential_integration_id is None:
        return headers
    integration = await session.scalar(
        select(Integration)
        .options(selectinload(Integration.credentials))
        .where(
            Integration.id == connector.credential_integration_id,
            Integration.organization_id == connector.organization_id,
            Integration.is_enabled.is_(True),
        )
    )
    if integration is None:
        raise InvalidConfigurationError("custom connector credential integration is unavailable")
    from app.services.integration import credentials_for

    credentials = credentials_for(integration, settings=settings)
    if token := credentials.get("api_token") or credentials.get("automation_token"):
        headers["Authorization"] = f"Bearer {token.reveal()}"
    elif key := credentials.get("api_key"):
        headers["X-API-Key"] = key.reveal()
    elif (username := credentials.get("username")) and (password := credentials.get("password")):
        value = base64.b64encode(
            f"{username.reveal()}:{password.reveal()}".encode()
        ).decode("ascii")
        headers["Authorization"] = f"Basic {value}"
    return headers


async def _runtime_client(
    session: AsyncSession,
    connector: CustomConnector,
    *,
    settings: Settings,
    redis: Any | None,
) -> RuntimeConnectorClient:
    await _assert_public_destination(connector.base_url)
    headers = await _credential_headers(session, connector, settings=settings)
    client = build_client(
        provider=f"custom:{connector.id.hex[:24]}",
        base_url=connector.base_url,
        settings=settings,
        redis=redis,
        headers=headers,
        timeout=30.0,
        follow_redirects=False,
    )
    return RuntimeConnectorClient(client, base_url=connector.base_url)


async def _stage_alerts(
    session: AsyncSession,
    *,
    organization_id: Any,
    integration_id: Any | None,
    provider: str,
    alerts: list[Any],
) -> int:
    from app.services.external_alert import _stage_normalized_alerts

    return await _stage_normalized_alerts(
        session,
        organization_id=organization_id,
        integration_id=integration_id,
        provider=provider,
        alerts=alerts,
    )


async def execute_connector(
    session: AsyncSession,
    principal: Principal,
    connector: CustomConnector,
    run: CustomConnectorRun,
    *,
    client: ConnectorPageClient,
) -> CustomConnectorRun:
    """Execute one reserved connector run inside the caller's transaction."""
    principal.require(Permission.INTEGRATION_MANAGE)
    if (
        connector.organization_id != principal.organization_id
        or run.organization_id != principal.organization_id
        or run.connector_id != connector.id
    ):
        raise InvalidConfigurationError("custom connector run scope is invalid")
    if run.status == "completed":
        return run
    if not connector.is_enabled:
        raise InvalidConfigurationError("custom connector is disabled")

    provider = f"custom:{connector.id.hex[:24]}"
    route_results: dict[str, dict[str, int]] = {}
    checkpoints = dict((run.checkpoint or {}).get("routes") or {})
    normalized: list[Any] = []
    total_read = 0
    for route in connector.routes:
        route_name = str(route.get("name") or route["path"])[:160]
        records, route_checkpoint = await collect_records(
            client,
            route,
            connector.pagination,
            checkpoint=dict(checkpoints.get(route_name) or {}),
        )
        total_read += len(records)
        if total_read > _MAX_RECORDS_PER_RUN:
            raise InvalidConfigurationError(
                "custom connector run exceeded the 50000-record safety limit"
            )
        for record in records:
            mapped = map_record(record, connector.field_mapping)
            normalized.append(normalize_record(mapped, raw=record, provider=provider))
        checkpoints[route_name] = route_checkpoint
        route_results[route_name] = {"read": len(records)}

    written = await _stage_alerts(
        session,
        organization_id=principal.organization_id,
        integration_id=connector.credential_integration_id,
        provider=provider,
        alerts=normalized,
    )
    run.status = "completed"
    run.checkpoint = {"routes": checkpoints}
    run.result = {"routes": route_results, "output_type": connector.output_type}
    run.records_read = total_read
    run.records_written = written
    run.error_code = None
    run.completed_at = utcnow()
    return run


async def run_pending_connector_runs(
    session: AsyncSession,
    *,
    settings: Settings,
    redis: Any | None,
    limit: int = 3,
    client_factory: Any | None = None,
) -> int:
    """Claim queued connector runs once across worker replicas and settle each safely."""
    rows = list(
        (
            await session.execute(
                select(CustomConnectorRun, CustomConnector)
                .join(
                    CustomConnector,
                    (CustomConnector.id == CustomConnectorRun.connector_id)
                    & (
                        CustomConnector.organization_id
                        == CustomConnectorRun.organization_id
                    ),
                )
                .where(
                    CustomConnectorRun.status == "pending",
                    CustomConnector.is_enabled.is_(True),
                )
                .order_by(CustomConnectorRun.created_at, CustomConnectorRun.id)
                .limit(max(1, min(limit, 20)))
                .with_for_update(of=CustomConnectorRun, skip_locked=True)
            )
        ).all()
    )
    for run, connector in rows:
        run.status = "running"
        principal = Principal.for_system(organization_id=run.organization_id)
        client: ConnectorPageClient | None = None
        try:
            if client_factory is None:
                client = await _runtime_client(
                    session, connector, settings=settings, redis=redis
                )
            else:
                candidate = client_factory(connector, settings, redis)
                client = await candidate if inspect.isawaitable(candidate) else candidate
            async with session.begin_nested():
                await execute_connector(
                    session, principal, connector, run, client=client
                )
        except Exception as exc:
            run.status = "failed"
            run.error_code = exc.code if isinstance(exc, CynuxError) else type(exc).__name__
            run.result = {
                "error": (
                    exc.user_message
                    if isinstance(exc, CynuxError)
                    else "The custom connector run failed unexpectedly. Review worker logs."
                )
            }
            run.completed_at = utcnow()
        finally:
            close = getattr(client, "aclose", None)
            if close is not None:
                result = close()
                if inspect.isawaitable(result):
                    await result
    return len(rows)


def value_at(document: dict[str, Any], path: str) -> Any:
    value: Any = document
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def map_record(record: dict[str, Any], mapping: dict[str, str]) -> dict[str, Any]:
    return {target: value_at(record, source) for target, source in mapping.items() if value_at(record, source) is not None}


def safe_response_origin(base_url: str, response_url: str) -> bool:
    """Return whether a followed response stayed on the configured HTTPS origin."""
    expected = urlsplit(base_url)
    actual = urlsplit(response_url)
    expected_port = expected.port or (443 if expected.scheme == "https" else None)
    actual_port = actual.port or (443 if actual.scheme == "https" else None)
    return (
        expected.scheme == actual.scheme == "https"
        and expected.hostname is not None
        and actual.hostname is not None
        and expected.hostname.casefold() == actual.hostname.casefold()
        and expected_port == actual_port
        and actual.username is None
        and actual.password is None
    )


def _records_at(document: Any, path: str) -> list[dict[str, Any]]:
    value: Any = document
    for part in path.split("."):
        if not isinstance(value, Mapping):
            raise InvalidConfigurationError("custom connector records path did not resolve")
        value = value.get(part)
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise InvalidConfigurationError("custom connector records path must resolve to objects")
    return list(value)


async def collect_records(
    client: ConnectorPageClient,
    route: dict[str, Any],
    pagination: dict[str, Any],
    *,
    checkpoint: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Collect one bounded route and return a checkpoint safe to persist."""
    max_pages = max(1, min(int(pagination.get("max_pages", 1)), 100))
    page_size = max(1, min(int(pagination.get("page_size", 100)), 500))
    mode = pagination.get("type")
    query_parameter = str(pagination.get("query_parameter") or ("cursor" if mode == "cursor" else "page"))
    cursor_path = str(pagination.get("cursor_path") or "next")
    cursor = checkpoint.get("cursor")
    page = max(1, int(checkpoint.get("page", 1)))
    records: list[dict[str, Any]] = []
    pages = 0
    complete = False

    for _ in range(max_pages):
        params: dict[str, Any] = {"page_size": page_size}
        if mode == "cursor" and cursor not in (None, ""):
            params[query_parameter] = cursor
        elif mode == "page":
            params[query_parameter] = page
        document = await client.get_json(route["path"], params=params)
        batch = _records_at(document, route.get("records_path", "items"))
        records.extend(batch)
        pages += 1

        if mode == "cursor":
            next_cursor = value_at(document, cursor_path) if isinstance(document, dict) else None
            if next_cursor in (None, ""):
                complete = True
                cursor = None
                break
            cursor = str(next_cursor)
        elif mode == "page":
            page += 1
            if len(batch) < page_size:
                complete = True
                break
        else:
            complete = True
            break

    next_checkpoint: dict[str, Any] = {"pages": pages, "complete": complete}
    if not complete and mode == "cursor" and cursor:
        next_checkpoint["cursor"] = cursor
    if not complete and mode == "page":
        next_checkpoint["page"] = page
    return records, next_checkpoint


def normalize_record(
    mapped: dict[str, Any], *, raw: dict[str, Any], provider: str
):
    """Create a source-preserving alert from allowlisted mapped fields only."""
    from app.services.external_alert import NormalizedExternalAlert

    external_id = str(mapped.get("external_id") or "").strip()
    title = str(mapped.get("title") or "").strip()
    if not external_id or not title:
        raise InvalidConfigurationError(
            "custom connector mappings require external_id and title"
        )
    severity = str(mapped.get("severity") or "info").casefold()
    if severity not in _SEVERITIES:
        severity = "info"
    source_state = str(mapped.get("status") or "open").casefold()
    if source_state in _FIXED_STATES:
        status = "fixed"
    elif source_state in _OPEN_STATES:
        status = "open"
    elif source_state in {"dismissed", "false_positive", "not_applicable"}:
        status = "dismissed"
    else:
        status = "open"
    asset_value = str(mapped.get("asset_value") or mapped.get("resource") or "").strip()
    asset_type = str(mapped.get("asset_type") or "unknown").strip().casefold()
    raw_cves = mapped.get("cve_ids") or []
    if isinstance(raw_cves, str):
        raw_cves = [item.strip() for item in raw_cves.split(",")]
    cve_ids = sorted(
        {
            str(item).upper()
            for item in raw_cves
            if isinstance(item, str) and _CVE.fullmatch(item.strip())
        }
    )
    allowed_raw = {key: raw[key] for key in mapped if key in raw}
    evidence = {
        "provider": provider,
        "provider_state": source_state,
        "asset_type": asset_type,
        "asset_value": asset_value[:1000],
    }
    return NormalizedExternalAlert(
        external_id=external_id[:300],
        category=str(mapped.get("category") or "custom")[:80],
        title=title[:1000],
        severity=severity,
        status=status,
        resource=asset_value[:1000] or None,
        source_url=(str(mapped["source_url"])[:2000] if mapped.get("source_url") else None),
        cve_ids=cve_ids,
        evidence=evidence,
        raw_payload=allowed_raw,
    )


__all__ = [
    "collect_records",
    "create_connector",
    "execute_connector",
    "map_record",
    "normalize_record",
    "reserve_connector_run",
    "run_pending_connector_runs",
    "safe_response_origin",
    "validate_definition",
    "value_at",
]
