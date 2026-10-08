"""Large recon batches must use bounded tenant-filtered inventory queries."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.db.models.asset import Asset
from app.scanners.recon_assets import DiscoveredAsset
from app.services.asset import _load_by_keys, upsert_assets


@pytest.mark.asyncio
async def test_bulk_inventory_lookup_chunks_large_name_sets() -> None:
    organization_id = uuid.uuid4()
    keys = {(f"host-{index}.example.com", None, None) for index in range(2_101)}
    calls = []

    class Session:
        async def execute(self, stmt):
            assert "assets.organization_id" in str(stmt)
            names = next(
                value for value in stmt.compile().params.values() if isinstance(value, list)
            )
            calls.append(names)
            assert len(names) <= 1_000
            rows = [SimpleNamespace(name=name, port=None, protocol=None) for name in names]
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))

    found = await _load_by_keys(Session(), organization_id, keys)
    assert len(found) == len(keys)
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_inventory_lookup_reuses_prior_repository_integration_asset() -> None:
    organization_id = uuid.uuid4()
    key = ("https://github.com/acme/api", None, None)
    synthetic = Asset(
        id=uuid.uuid4(),
        organization_id=organization_id,
        name="repo:acme/api",
        asset_type="repo",
    )

    class Session:
        async def execute(self, statement):
            names = next(
                value for value in statement.compile().params.values() if isinstance(value, list)
            )
            rows = [synthetic] if synthetic.name in names else []
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))

    found = await _load_by_keys(Session(), organization_id, {key})
    assert found[key] is synthetic


@pytest.mark.asyncio
async def test_inventory_lookup_reuses_enterprise_repository_alias_when_type_is_known() -> None:
    organization_id = uuid.uuid4()
    key = ("https://git.company.example/acme/api", None, None)
    synthetic = Asset(
        id=uuid.uuid4(),
        organization_id=organization_id,
        name="repo:git.company.example/acme/api",
        asset_type="repo",
    )

    class Session:
        async def execute(self, statement):
            names = next(
                value for value in statement.compile().params.values() if isinstance(value, list)
            )
            rows = [synthetic] if synthetic.name in names else []
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))

    found = await _load_by_keys(
        Session(),
        organization_id,
        {key},
        asset_types={key: "repository"},
    )
    assert found[key] is synthetic


@pytest.mark.asyncio
async def test_recon_adopts_synthetic_asset_id_and_restores_scannable_name() -> None:
    from app.db.models.asset import AssetChange

    organization_id = uuid.uuid4()
    assessment = SimpleNamespace(id=uuid.uuid4(), organization_id=organization_id)
    synthetic = Asset(
        id=uuid.uuid4(),
        organization_id=organization_id,
        name="repo:acme/api",
        asset_type="repo",
        technology=[],
        evidence={},
        seen_in_assessments=[],
        internet_exposed=False,
    )
    session = AsyncMock()
    session.add = MagicMock()
    result = MagicMock()
    result.scalar_one.return_value = SimpleNamespace(entitlements={}, risk_policy_version=0)
    session.execute.return_value = result
    with patch(
        "app.services.asset._load_by_keys",
        new_callable=AsyncMock,
        return_value={
            ("https://github.com/acme/api", None, None): synthetic,
        },
    ), patch(
        "app.services.asset._count_organization_assets", new_callable=AsyncMock, return_value=1
    ), patch("app.services.asset._count_assets", new_callable=AsyncMock, return_value=1), patch(
        "app.services.asset.assert_asset_capacity"
    ):
        touched = await upsert_assets(
            session,
            assessment,
            [
                DiscoveredAsset(
                    name="https://github.com/acme/api",
                    asset_type="repository",
                    internet_exposed=False,
                )
            ],
        )
    assert touched == [synthetic]
    assert synthetic.name == "https://github.com/acme/api"
    assert synthetic.asset_type == "repository"
    assert str(assessment.id) in synthetic.seen_in_assessments
    events = [
        call.args[0] for call in session.add.call_args_list if isinstance(call.args[0], AssetChange)
    ]
    assert len(events) == 1
    assert events[0].changes["name"] == {
        "old": "repo:acme/api",
        "new": "https://github.com/acme/api",
    }


@pytest.mark.asyncio
async def test_rediscovery_does_not_reactivate_operator_excluded_asset() -> None:
    organization_id = uuid.uuid4()
    assessment = SimpleNamespace(id=uuid.uuid4(), organization_id=organization_id)
    excluded = Asset(
        id=uuid.uuid4(),
        organization_id=organization_id,
        name="api.example.com",
        asset_type="subdomain",
        status="out_of_scope",
        technology=[],
        evidence={},
        seen_in_assessments=[],
        internet_exposed=False,
        selected_for_scanning=False,
    )
    session = AsyncMock()
    session.add = MagicMock()
    result = MagicMock()
    result.scalar_one.return_value = SimpleNamespace(entitlements={}, risk_policy_version=0)
    session.execute.return_value = result
    with patch(
        "app.services.asset._load_by_keys",
        new_callable=AsyncMock,
        return_value={
            ("api.example.com", None, None): excluded,
        },
    ), patch(
        "app.services.asset._count_organization_assets", new_callable=AsyncMock, return_value=1
    ), patch("app.services.asset._count_assets", new_callable=AsyncMock, return_value=1), patch(
        "app.services.asset.assert_asset_capacity"
    ):
        await upsert_assets(
            session,
            assessment,
            [
                DiscoveredAsset(
                    name="api.example.com",
                    asset_type="subdomain",
                    status="active",
                )
            ],
        )
    assert excluded.status == "out_of_scope"
    assert excluded.selected_for_scanning is False


@pytest.mark.asyncio
async def test_recon_records_one_tenant_scoped_drift_event_and_ignores_repeat() -> None:
    from app.db.models.asset import AssetChange

    organization_id = uuid.uuid4()
    assessment = SimpleNamespace(id=uuid.uuid4(), organization_id=organization_id)
    existing = Asset(
        id=uuid.uuid4(),
        organization_id=organization_id,
        name="api.example.com",
        asset_type="subdomain",
        status="active",
        ip_address="192.0.2.10",
        technology=["nginx"],
        evidence={},
        seen_in_assessments=[],
        internet_exposed=False,
    )
    session = AsyncMock()
    session.add = MagicMock()
    result = MagicMock()
    result.scalar_one.return_value = SimpleNamespace(entitlements={}, risk_policy_version=0)
    session.execute.return_value = result
    with patch(
        "app.services.asset._load_by_keys",
        new_callable=AsyncMock,
        return_value={
            ("api.example.com", None, None): existing,
        },
    ), patch(
        "app.services.asset._count_organization_assets", new_callable=AsyncMock, return_value=1
    ), patch("app.services.asset._count_assets", new_callable=AsyncMock, return_value=1), patch(
        "app.services.asset.assert_asset_capacity"
    ):
        record = DiscoveredAsset(
            name="api.example.com",
            asset_type="subdomain",
            ip_address="192.0.2.20",
            technology=("nginx", "OpenResty"),
            internet_exposed=True,
        )
        await upsert_assets(session, assessment, [record])
        await upsert_assets(session, assessment, [record])
    events = [
        call.args[0] for call in session.add.call_args_list if isinstance(call.args[0], AssetChange)
    ]
    assert len(events) == 1
    assert events[0].organization_id == organization_id
    assert events[0].assessment_id == assessment.id
    assert events[0].asset_id == existing.id
    assert events[0].change_type == "changed"
    assert events[0].changes == {
        "ip_address": {"old": "192.0.2.10", "new": "192.0.2.20"},
        "internet_exposed": {"old": False, "new": True},
        "technology": {"old": ["nginx"], "new": ["nginx", "OpenResty"]},
    }


@pytest.mark.asyncio
async def test_recon_records_first_discovery_event_without_claiming_live_exposure() -> None:
    from app.db.models.asset import AssetChange

    organization_id = uuid.uuid4()
    assessment = SimpleNamespace(id=uuid.uuid4(), organization_id=organization_id)
    session = AsyncMock()
    session.add = MagicMock()
    result = MagicMock()
    result.scalar_one.return_value = SimpleNamespace(entitlements={}, risk_policy_version=0)
    session.execute.return_value = result
    with patch("app.services.asset._load_by_keys", new_callable=AsyncMock, return_value={}), patch(
        "app.services.asset._count_organization_assets", new_callable=AsyncMock, return_value=0
    ), patch("app.services.asset._count_assets", new_callable=AsyncMock, return_value=1), patch(
        "app.services.asset.assert_asset_capacity"
    ):
        await upsert_assets(
            session,
            assessment,
            [
                DiscoveredAsset(
                    name="new.example.com",
                    asset_type="subdomain",
                    internet_exposed=False,
                )
            ],
        )
    events = [
        call.args[0] for call in session.add.call_args_list if isinstance(call.args[0], AssetChange)
    ]
    assert len(events) == 1
    assert events[0].change_type == "discovered"
    assert events[0].changes == {}
    assert events[0].organization_id == organization_id
