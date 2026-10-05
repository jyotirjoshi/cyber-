"""Business context on persistent assets must survive API projection."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from app.core.errors import UserError
from app.db.enums import Role
from app.db.models.asset import Asset
from app.schemas.asset import AssetContextIn, AssetOut
from app.services.asset import _score, set_asset_context
from app.services.context import Principal


def test_asset_persists_and_projects_owner_environment_and_groups() -> None:
    asset = Asset(
        id=uuid.uuid4(), organization_id=uuid.uuid4(), name="api.example",
        asset_type="domain", status="active", criticality="high",
        criticality_source="operator_tag", risk_score=0.0,
        internet_exposed=True, technology=[], evidence={}, seen_in_assessments=[],
        selected_for_scanning=False,
        owner_team="platform", environment="production", groups=["payments", "pci"],
    )
    payload = AssetOut.model_validate({
        **asset.as_dict(), "tags": [], "created_at": "2026-10-02T00:00:00Z",
    })
    assert payload.owner_team == "platform"
    assert payload.environment == "production"
    assert payload.groups == ["payments", "pci"]


def test_context_rejects_invalid_environment_and_duplicate_groups() -> None:
    with pytest.raises(ValidationError):
        AssetContextIn(environment="prod")
    with pytest.raises(ValidationError):
        AssetContextIn(groups=["payments", "payments"])


def test_context_rejects_empty_update_and_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        AssetContextIn()
    with pytest.raises(ValidationError):
        AssetContextIn(unrecognized=True)


def test_context_normalizes_team_and_group_names() -> None:
    payload = AssetContextIn(owner_team=" Platform ", groups=[" PCI ", "payments"])
    assert payload.owner_team == "Platform"
    assert payload.groups == ["PCI", "payments"]


@pytest.mark.asyncio
async def test_context_update_is_tenant_scoped_and_audited() -> None:
    org_id = uuid.uuid4()
    asset = Asset(
        id=uuid.uuid4(), organization_id=org_id, name="api.example", asset_type="domain",
        environment="unknown", groups=[],
    )
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    session = AsyncMock()
    with patch("app.services.asset.TenantRepository") as repo_type, patch(
        "app.services.asset.audit_service.record", new_callable=AsyncMock
    ) as audit:
        repo_type.return_value.get_or_404 = AsyncMock(return_value=asset)
        result = await set_asset_context(
            session, principal, asset.id,
            AssetContextIn(owner_team="Platform", environment="production", groups=["pci"]),
        )
    assert result is asset
    assert (asset.owner_team, asset.environment, asset.groups) == ("Platform", "production", ["pci"])
    repo_type.return_value.get_or_404.assert_awaited_once_with(asset.id)
    audit.assert_awaited_once()


def test_curated_production_environment_overrides_nonprod_name_heuristic() -> None:
    asset = Asset(
        name="dev-api.example", asset_type="domain", status="active", criticality="high",
        criticality_source="operator_tag", internet_exposed=False, technology=[],
        environment="production",
    )
    settings = SimpleNamespace(agent=SimpleNamespace(criticality_keywords=[]))
    production_score, reasons = _score(asset, settings)
    asset.environment = "unknown"
    unknown_score, _ = _score(asset, settings)
    assert production_score > unknown_score
    assert "Looks non-production, ranked lower" not in reasons


@pytest.mark.asyncio
async def test_context_rejects_owner_outside_organization() -> None:
    org_id = uuid.uuid4()
    asset = Asset(id=uuid.uuid4(), organization_id=org_id, name="api.example", asset_type="domain")
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    session = AsyncMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    session.execute.return_value = result
    with patch("app.services.asset.TenantRepository") as repo_type, patch(
        "app.services.asset.audit_service.record", new_callable=AsyncMock
    ) as audit:
        repo_type.return_value.get_or_404 = AsyncMock(return_value=asset)
        with pytest.raises(UserError):
            await set_asset_context(
                session, principal, asset.id, AssetContextIn(owner_user_id=uuid.uuid4())
            )
    assert asset.owner_user_id is None
    audit.assert_not_awaited()
