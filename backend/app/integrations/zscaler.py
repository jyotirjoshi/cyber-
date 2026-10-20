"""Zscaler OneAPI inventory and narrowly scoped policy enforcement."""

from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING, Any

from app.core.config import Settings
from app.core.errors import (
    IntegrationError,
    IntegrationNotConfiguredError,
    InvalidConfigurationError,
)
from app.integrations.circuit import BreakerConfig
from app.integrations.control_enforcement import EnforcementCommand
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis

PROVIDER = "Zscaler"
_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_ACTION_PATHS: dict[str, tuple[str, str]] = {
    "zpa.update_application_access": ("PATCH", "/zpa/mgmtconfig/v1/admin/customers/{customer}/application/{target}"),
    "zpa.update_segment_group": ("PATCH", "/zpa/mgmtconfig/v1/admin/customers/{customer}/segmentGroup/{target}"),
    "zpa.update_server_group": ("PATCH", "/zpa/mgmtconfig/v1/admin/customers/{customer}/serverGroup/{target}"),
    "zpa.update_connector_group": ("PATCH", "/zpa/mgmtconfig/v1/admin/customers/{customer}/appConnectorGroup/{target}"),
    "zia.update_url_filter_rule": ("PUT", "/zia/api/v1/urlFilteringRules/{target}"),
    "zia.update_firewall_rule": ("PUT", "/zia/api/v1/firewallFilteringRules/{target}"),
}


def inventory_endpoints(customer_id: str) -> tuple[tuple[str, str, str], ...]:
    """The bounded inventory surfaces reconciled into CAASM."""

    if not _SAFE_ID.fullmatch(customer_id):
        raise InvalidConfigurationError(
            "invalid Zscaler customer identifier",
            user_message="The Zscaler customer identifier is not valid.",
        )
    prefix = f"/zpa/mgmtconfig/v1/admin/customers/{customer_id}"
    return (
        ("zpa", "private_application", f"{prefix}/application"),
        ("zpa", "segment_group", f"{prefix}/segmentGroup"),
        ("zpa", "server_group", f"{prefix}/serverGroup"),
        ("zpa", "connector_group", f"{prefix}/appConnectorGroup"),
        ("zia", "url_filter_rule", "/zia/api/v1/urlFilteringRules"),
        ("zia", "firewall_rule", "/zia/api/v1/firewallFilteringRules"),
    )


def build_action_path(action: str, target_external_id: str, customer_id: str) -> tuple[str, str]:
    spec = _ACTION_PATHS.get(action)
    if spec is None:
        raise InvalidConfigurationError(
            f"unsupported Zscaler enforcement action: {action}",
            user_message="That Zscaler policy action is not supported.",
        )
    if not _SAFE_ID.fullmatch(target_external_id) or not _SAFE_ID.fullmatch(customer_id):
        raise InvalidConfigurationError(
            "invalid Zscaler resource identifier",
            user_message="The Zscaler resource identifier is not valid.",
        )
    method, template = spec
    return method, template.format(customer=customer_id, target=target_external_id)


def normalize_inventory_item(
    *, provider_domain: str, resource_kind: str, item: dict[str, Any]
) -> dict[str, Any]:
    external_id = str(item.get("id") or item.get("externalId") or item.get("name") or "").strip()
    if not external_id:
        raise IntegrationError("Zscaler inventory item has no stable identifier", provider=PROVIDER)
    return {
        "resource_key": f"zscaler:{provider_domain}:{resource_kind}:{external_id}",
        "kind": "saas_application" if resource_kind == "cloud_application" else "asset",
        "name": str(item.get("name") or external_id),
        "provider": "zscaler",
        "external_id": external_id,
        "approved": item.get("enabled") if isinstance(item.get("enabled"), bool) else None,
        "attributes": {
            "provider_domain": provider_domain,
            "resource_kind": resource_kind,
            "description": item.get("description"),
            "status": item.get("status"),
        },
        "provenance": {"source": f"zscaler_{provider_domain}"},
    }


class ZscalerClient:
    provider = "zscaler"

    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.zscaler
        self._redis = redis
        self._client: ResilientClient | None = None
        self._access_token: str | None = None

    @property
    def configured(self) -> bool:
        return self._cfg.configured

    def _require(self) -> ResilientClient:
        if not self.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint="Configure base URL, customer ID, OAuth client ID, and client secret.",
            )
        if self._client is None:
            self._client = build_client(
                provider=PROVIDER,
                base_url=self._cfg.base_url or "",
                settings=self.settings,
                redis=self._redis,
                timeout=float(self._cfg.timeout_seconds),
                verify=self._cfg.verify_tls,
                retry=RetryPolicy(max_attempts=3, backoff_base=0.5),
                breaker_config=BreakerConfig(failure_threshold=4, cooldown_seconds=180),
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        self._access_token = None

    async def _token(self) -> str:
        if self._access_token:
            return self._access_token
        payload = await self._require().post_json(
            "/oauth2/v1/token",
            data={
                "grant_type": "client_credentials",
                "client_id": reveal(self._cfg.client_id),
                "client_secret": reveal(self._cfg.client_secret),
                "audience": self._cfg.audience,
            },
            idempotency_key="zscaler-oauth-token",
        )
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise IntegrationError("Zscaler authentication returned no token", provider=PROVIDER)
        self._access_token = token
        return token

    async def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {await self._token()}", "Content-Type": "application/json"}

    async def ping(self) -> bool:
        await self._require().get_json(
            f"/zpa/mgmtconfig/v1/admin/customers/{self._cfg.customer_id}/application",
            params={"pagesize": 1},
            headers=await self._headers(),
        )
        return True

    async def list_inventory(self, *, limit: int = 500) -> list[dict[str, Any]]:
        bounded = min(max(limit, 1), 1000)
        headers = await self._headers()
        endpoints = inventory_endpoints(self._cfg.customer_id or "")
        normalized: list[dict[str, Any]] = []
        for domain, kind, path in endpoints:
            payload = await self._require().get_json(
                path, params={"pageSize": bounded}, headers=headers
            )
            items = payload if isinstance(payload, list) else payload.get("list", []) if isinstance(payload, dict) else []
            for item in items[:bounded]:
                if isinstance(item, dict):
                    normalized.append(
                        normalize_inventory_item(
                            provider_domain=domain, resource_kind=kind, item=item
                        )
                    )
        return normalized

    async def preview(self, command: EnforcementCommand) -> dict[str, Any]:
        method, path = build_action_path(
            command.action, command.target_external_id, self._cfg.customer_id or ""
        )
        return {
            "status": "previewed",
            "method": method,
            "target_path": path,
            "desired_state": command.desired_state,
        }

    async def snapshot(self, command: EnforcementCommand) -> dict[str, Any]:
        _method, path = build_action_path(
            command.action, command.target_external_id, self._cfg.customer_id or ""
        )
        payload = await self._require().get_json(path, headers=await self._headers())
        return payload if isinstance(payload, dict) else {"value": payload}

    async def confirm(self, command: EnforcementCommand) -> dict[str, Any]:
        state = await self.snapshot(command)
        matches = all(state.get(key) == value for key, value in command.desired_state.items())
        digest = hashlib.sha256(
            json.dumps(state, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()
        return {"matches": matches, "state_digest": digest}

    async def apply(self, command: EnforcementCommand) -> dict[str, Any]:
        method, path = build_action_path(
            command.action, command.target_external_id, self._cfg.customer_id or ""
        )
        client = self._require()
        if method == "PATCH":
            payload = await client.patch_json(
                path,
                json=command.desired_state,
                headers=await self._headers(),
                idempotency_key=command.idempotency_key,
            )
        else:
            payload = await client.put_json(
                path,
                json=command.desired_state,
                headers=await self._headers(),
                idempotency_key=command.idempotency_key,
            )
        response = payload if isinstance(payload, dict) else {}
        return {
            "status": "applied",
            "request_id": response.get("requestId") or response.get("id"),
            "provider_status": response.get("status"),
            "target_external_id": command.target_external_id,
        }


__all__ = [
    "PROVIDER",
    "ZscalerClient",
    "build_action_path",
    "inventory_endpoints",
    "normalize_inventory_item",
]
