"""Discovery events and notifications must stay inside the assessment tenant."""

import uuid
from contextlib import asynccontextmanager
from importlib import import_module
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.dialects import postgresql

from app.db.enums import Role
from app.db.models.asset import Asset, AssetChange
from app.services.context import Principal


@pytest.mark.asyncio
async def test_new_asset_alert_excludes_seeds_and_foreign_rows(monkeypatch) -> None:
    from app.services import asset_change

    org_id, foreign_org_id, assessment_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    discovered = Asset(id=uuid.uuid4(), organization_id=org_id, name="new.example.com")
    seed = Asset(id=uuid.uuid4(), organization_id=org_id, name="example.com")
    foreign = Asset(id=uuid.uuid4(), organization_id=foreign_org_id, name="foreign.example.com")
    rows = [
        (
            AssetChange(
                organization_id=org_id,
                assessment_id=assessment_id,
                asset_id=discovered.id,
                change_type="discovered",
            ),
            discovered,
        ),
        (
            AssetChange(
                organization_id=org_id,
                assessment_id=assessment_id,
                asset_id=seed.id,
                change_type="discovered",
            ),
            seed,
        ),
        (
            AssetChange(
                organization_id=foreign_org_id,
                assessment_id=assessment_id,
                asset_id=foreign.id,
                change_type="discovered",
            ),
            foreign,
        ),
        (
            AssetChange(
                organization_id=org_id,
                assessment_id=assessment_id,
                asset_id=uuid.uuid4(),
                change_type="discovered",
            ),
            Asset(id=uuid.uuid4(), organization_id=org_id, name="wrong-join.example.com"),
        ),
        (
            AssetChange(
                organization_id=org_id,
                assessment_id=assessment_id,
                asset_id=uuid.uuid4(),
                change_type="changed",
            ),
            Asset(id=uuid.uuid4(), organization_id=org_id, name="changed.example.com"),
        ),
    ]
    statements = []

    class Session:
        async def execute(self, statement):
            statements.append(statement)
            return SimpleNamespace(all=lambda: rows)

    staged = []

    async def dispatch(session, actor, **kwargs):
        staged.append((actor, kwargs))
        return []

    monkeypatch.setattr(asset_change.notification_service, "dispatch", dispatch)
    count = await asset_change.stage_new_asset_alert(
        Session(),
        principal,
        assessment_id=assessment_id,
        seed_names={"example.com"},
        settings=SimpleNamespace(public_base_url="https://app.test"),
    )
    assert count == 1
    assert len(staged) == 1
    assert staged[0][0] is principal
    assert "new.example.com" in staged[0][1]["content"].body
    assert "foreign.example.com" not in staged[0][1]["content"].body
    assert "example.com," not in staged[0][1]["content"].body
    assert staged[0][1]["resource_id"] == str(assessment_id)
    compiled = statements[0].compile(dialect=postgresql.dialect())
    assert org_id in compiled.params.values()
    assert assessment_id in compiled.params.values()


@pytest.mark.asyncio
async def test_asset_change_feed_is_tenant_filtered_and_bounded() -> None:
    from app.services.asset_change import list_asset_changes

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    statements = []

    class Session:
        async def execute(self, statement):
            statements.append(statement)
            if len(statements) == 1:
                return SimpleNamespace(scalar_one=lambda: 0)
            return SimpleNamespace(all=lambda: [])

    page = await list_asset_changes(Session(), principal, limit=25, offset=0)
    assert page.total == 0
    assert page.items == []
    for statement in statements:
        assert org_id in statement.compile(dialect=postgresql.dialect()).params.values()


@pytest.mark.asyncio
async def test_asset_changes_route_passes_principal_and_precedes_dynamic_asset_route(
    monkeypatch,
) -> None:
    from app.api.v1 import assets
    from app.schemas.asset_change import AssetChangePageOut

    principal = Principal(
        user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.SECURITY_ENGINEER
    )
    session = object()
    calls = []

    async def list_changes(db, actor, *, limit, offset):
        calls.append((db, actor, limit, offset))
        return AssetChangePageOut(items=[], total=0, limit=limit, offset=offset)

    monkeypatch.setattr(assets.asset_change_service, "list_asset_changes", list_changes)
    result = await assets.list_asset_changes(principal, session, 25, 0)
    assert result.total == 0
    assert calls == [(session, principal, 25, 0)]
    paths = [route.path for route in assets.router.routes]
    assert paths.index("/assets/changes") < paths.index("/assets/{asset_id}")


@pytest.mark.asyncio
async def test_recon_stages_discovery_alert_after_inventory_merge(monkeypatch) -> None:
    from app.scanners.recon_assets import DiscoveredAsset

    recon = import_module("app.agent.nodes.recon")
    principal = Principal(
        user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.SECURITY_ENGINEER
    )
    assessment = SimpleNamespace(
        id=uuid.uuid4(), organization_id=principal.organization_id, assets_discovered=0
    )
    session = object()
    settings = SimpleNamespace(public_base_url="https://app.test")

    @asynccontextmanager
    async def session_scope(_settings):
        yield session

    async def upsert(_session, target, records):
        assert records[0].name == "example.com"
        assert records[1].name == "new.example.com"
        target.assets_discovered = 2
        return []

    stage = AsyncMock(return_value=1)
    monkeypatch.setattr(recon, "session_scope", session_scope)
    monkeypatch.setattr(recon, "load_assessment", AsyncMock(return_value=assessment))
    monkeypatch.setattr(recon, "upsert_assets", upsert)
    monkeypatch.setattr(recon, "transition", AsyncMock())
    monkeypatch.setattr(recon.asset_change_service, "stage_new_asset_alert", stage)

    result = await recon._record_inventory(
        SimpleNamespace(settings=settings),
        {
            "principal": principal.to_dict(),
            "organization_id": str(principal.organization_id),
            "assessment_id": str(assessment.id),
        },
        seeds=[DiscoveredAsset(name="example.com", asset_type="domain")],
        recon_assets=[DiscoveredAsset(name="new.example.com", asset_type="subdomain")],
        degradation=None,
    )
    assert result == 2
    stage.assert_awaited_once_with(
        session,
        principal,
        assessment_id=assessment.id,
        seed_names={"example.com"},
        settings=settings,
    )
