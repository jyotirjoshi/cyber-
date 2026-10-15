"""Validation and bounded execution primitives for declarative HTTP connectors."""
from __future__ import annotations
import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import InvalidConfigurationError
from app.db.enums import Permission
from app.db.models.custom_connector import CustomConnector
from app.schemas.custom_connector import CustomConnectorIn
from app.services.context import Principal

_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,500}$")
_JSON_PATH = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,9}$")


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


def value_at(document: dict[str, Any], path: str) -> Any:
    value: Any = document
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def map_record(record: dict[str, Any], mapping: dict[str, str]) -> dict[str, Any]:
    return {target: value_at(record, source) for target, source in mapping.items() if value_at(record, source) is not None}


__all__ = ["create_connector", "map_record", "validate_definition", "value_at"]
