from __future__ import annotations

from typing import Any

import pytest


class FakeAdapter:
    provider = "fake"

    def __init__(self) -> None:
        self.preview_calls = 0
        self.apply_calls = 0

    async def preview(self, command: Any) -> dict[str, Any]:
        self.preview_calls += 1
        return {"status": "previewed", "authorization": "Bearer do-not-leak"}

    async def apply(self, command: Any) -> dict[str, Any]:
        self.apply_calls += 1
        return {"status": "applied", "request_id": "req-1", "api_token": "secret"}


@pytest.mark.asyncio
async def test_dry_run_never_invokes_provider_write_and_redacts_receipt() -> None:
    from app.integrations.control_enforcement import EnforcementCommand, execute_enforcement

    adapter = FakeAdapter()
    receipt = await execute_enforcement(
        adapter,
        EnforcementCommand(
            action="zpa.update_application_access",
            target_external_id="app-1",
            desired_state={"segment_group": "employees"},
            idempotency_key="idem-1",
            dry_run=True,
        ),
    )

    assert adapter.preview_calls == 1
    assert adapter.apply_calls == 0
    assert receipt.status == "previewed"
    assert receipt.provider_receipt["authorization"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_applied_receipt_replay_does_not_repeat_provider_write() -> None:
    from app.integrations.control_enforcement import (
        EnforcementCommand,
        EnforcementReceipt,
        execute_enforcement,
    )

    adapter = FakeAdapter()
    command = EnforcementCommand(
        action="zpa.update_application_access",
        target_external_id="app-1",
        desired_state={"enabled": False},
        idempotency_key="idem-2",
        dry_run=False,
    )
    prior = EnforcementReceipt(
        provider="fake",
        action=command.action,
        idempotency_key=command.idempotency_key,
        status="applied",
        provider_receipt={"request_id": "prior"},
    )
    receipt = await execute_enforcement(adapter, command, existing_receipt=prior)

    assert receipt is prior
    assert adapter.apply_calls == 0


def test_zscaler_rejects_arbitrary_paths_and_unsupported_actions() -> None:
    from app.core.errors import InvalidConfigurationError
    from app.integrations.zscaler import build_action_path

    with pytest.raises(InvalidConfigurationError):
        build_action_path("custom.http", "https://attacker.example/path", "customer-1")
    with pytest.raises(InvalidConfigurationError):
        build_action_path("zpa.update_application_access", "../admin", "customer-1")


def test_zscaler_inventory_normalization_has_stable_resource_keys() -> None:
    from app.integrations.zscaler import normalize_inventory_item

    item = normalize_inventory_item(
        provider_domain="zpa",
        resource_kind="private_application",
        item={"id": "app-123", "name": "Payroll", "enabled": True},
    )
    assert item["resource_key"] == "zscaler:zpa:private_application:app-123"
    assert item["name"] == "Payroll"
    assert item["approved"] is True


def test_zscaler_is_a_first_class_configurable_integration() -> None:
    from app.db.enums import IntegrationKind
    from app.services.integration import _DEFAULT_NAMES, _SPECS

    assert IntegrationKind.ZSCALER in _SPECS
    assert _SPECS[IntegrationKind.ZSCALER].required == ("client_id", "client_secret")
    assert _DEFAULT_NAMES[IntegrationKind.ZSCALER] == "Zscaler Zero Trust Exchange"
