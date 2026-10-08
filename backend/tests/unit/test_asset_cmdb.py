"""CMDB business context attaches only to matching tenant inventory assets."""

import io
import uuid
from types import SimpleNamespace

import pytest
from fastapi import UploadFile
from sqlalchemy.dialects import postgresql

from app.db.enums import Role
from app.db.models.asset import Asset, AssetTag
from app.services.context import Principal


def test_cmdb_csv_normalizes_tier_and_rejects_unbounded_input() -> None:
    from app.services.asset_cmdb import parse_cmdb_csv

    rows = parse_cmdb_csv(
        b"asset_type,asset_value,tier,owner_team,environment\n"
        b"domain,API.Example.COM.,tier1, Platform ,production\n"
    )
    assert len(rows) == 1
    assert rows[0].asset_type == "domain"
    assert rows[0].asset_value == "api.example.com"
    assert rows[0].criticality == "high"
    assert rows[0].owner_team == "Platform"
    assert rows[0].environment == "production"

    with pytest.raises(ValueError, match="unknown column"):
        parse_cmdb_csv(b"asset_type,asset_value,secret\ndomain,api.example.com,key\n")
    with pytest.raises(ValueError, match="duplicate"):
        parse_cmdb_csv(
            b"asset_type,asset_value,tier\n"
            b"domain,api.example.com,tier1\n"
            b"domain,API.EXAMPLE.COM,tier2\n"
        )


def test_cmdb_csv_rejects_secret_bearing_or_oversized_identities() -> None:
    from app.services.asset_cmdb import parse_cmdb_csv

    with pytest.raises(ValueError, match="identity"):
        parse_cmdb_csv(
            b"asset_type,asset_value,tier\n" b"url,https://user:secret@example.com/api,tier1\n"
        )
    with pytest.raises(ValueError, match="identity"):
        parse_cmdb_csv(b"asset_type,asset_value,tier\n" + b"domain," + b"a" * 3000 + b",tier1\n")


@pytest.mark.asyncio
async def test_cmdb_dry_run_matches_tenant_asset_without_mutating_it(monkeypatch) -> None:
    from app.services.asset_cmdb import apply_cmdb_csv, parse_cmdb_csv

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    asset = Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="api.example.com",
        asset_type="domain",
        criticality="unknown",
        criticality_source="default",
        environment="unknown",
        groups=[],
        owner_team=None,
    )
    statements = []

    class _Session:
        async def execute(self, statement):
            statements.append(statement)
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [asset]))

    rows = parse_cmdb_csv(
        b"asset_type,asset_value,tier,owner_team,environment\n"
        b"domain,api.example.com,tier0,Platform,production\n"
    )
    result = await apply_cmdb_csv(_Session(), principal, rows, dry_run=True)
    assert result == {"matched": 1, "updated": 1, "unmatched": []}
    assert asset.criticality == "unknown"
    assert asset.owner_team is None
    query = statements[0].compile(dialect=postgresql.dialect())
    assert org_id in query.params.values()


@pytest.mark.asyncio
async def test_cmdb_import_preserves_operator_override_and_skips_foreign_asset(monkeypatch) -> None:
    from app.services.asset_cmdb import apply_cmdb_csv, parse_cmdb_csv

    org_id = uuid.uuid4()
    other_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    own = Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="api.example.com",
        asset_type="domain",
        criticality="critical",
        criticality_source="operator_tag",
        criticality_rationale="Operator override",
        environment="unknown",
        groups=[],
        owner_team=None,
    )
    foreign = Asset(
        id=uuid.uuid4(),
        organization_id=other_id,
        name="foreign.example.com",
        asset_type="domain",
        criticality="unknown",
        criticality_source="default",
        environment="unknown",
        groups=[],
        owner_team=None,
    )

    class _Session:
        async def execute(self, statement):
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [own, foreign]))

    async def audit(*args, **kwargs):
        return None

    monkeypatch.setattr("app.services.audit.record", audit)
    rows = parse_cmdb_csv(
        b"asset_type,asset_value,tier,owner_team,environment\n"
        b"domain,api.example.com,tier3,Platform,production\n"
        b"domain,foreign.example.com,tier0,Other,production\n"
    )
    result = await apply_cmdb_csv(_Session(), principal, rows, dry_run=False)
    assert result == {
        "matched": 1,
        "updated": 1,
        "unmatched": ["domain:foreign.example.com"],
    }
    assert own.criticality == "critical"
    assert own.criticality_rationale == "Operator override"
    assert own.owner_team == "Platform"
    assert own.environment == "production"
    assert foreign.criticality == "unknown"
    assert foreign.owner_team is None


@pytest.mark.asyncio
async def test_cmdb_tier_survives_inference_and_invalidates_risk_policy(monkeypatch) -> None:
    from app.services.asset import infer_criticality
    from app.services.asset_cmdb import apply_cmdb_csv, parse_cmdb_csv

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    asset = Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="api.example.com",
        asset_type="domain",
        criticality="unknown",
        criticality_source="default",
        environment="unknown",
        groups=[],
        owner_team=None,
    )
    statements = []

    class _Session:
        async def execute(self, statement):
            statements.append(statement)
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [asset]))

    async def audit(*args, **kwargs):
        return None

    monkeypatch.setattr("app.services.audit.record", audit)
    rows = parse_cmdb_csv(b"asset_type,asset_value,tier\ndomain,api.example.com,tier1\n")
    result = await apply_cmdb_csv(_Session(), principal, rows, dry_run=False)
    assert result["updated"] == 1
    assert asset.criticality == "high"
    assert asset.criticality_source == "cmdb"
    assert "CMDB" in asset.criticality_rationale
    assert len(statements) == 2
    policy_update = statements[1].compile(dialect=postgresql.dialect())
    assert org_id in policy_update.params.values()
    level, source, _ = await infer_criticality(
        asset, SimpleNamespace(agent=SimpleNamespace(criticality_keywords=[]))
    )
    assert level.value == "high"
    assert source.value == "cmdb"


@pytest.mark.asyncio
async def test_operator_tag_outranks_cmdb_tier_during_scoring() -> None:
    from app.services.asset import infer_criticality

    asset = Asset(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        name="api.example.com",
        asset_type="domain",
        criticality="low",
        criticality_source="cmdb",
        environment="production",
        groups=[],
    )
    asset.tags = [
        AssetTag(
            id=uuid.uuid4(),
            organization_id=asset.organization_id,
            asset_id=asset.id,
            key="criticality",
            value="critical",
            is_operator_applied=True,
        )
    ]
    level, source, _ = await infer_criticality(
        asset, SimpleNamespace(agent=SimpleNamespace(criticality_keywords=[]))
    )
    assert level.value == "critical"
    assert source.value == "operator_tag"


@pytest.mark.asyncio
async def test_cmdb_environment_change_invalidates_scoring_policy(monkeypatch) -> None:
    from app.services.asset_cmdb import apply_cmdb_csv, parse_cmdb_csv

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    asset = Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="dev-api.example.com",
        asset_type="domain",
        criticality="high",
        criticality_source="operator_tag",
        environment="unknown",
        groups=[],
        owner_team=None,
    )
    statements = []

    class _Session:
        async def execute(self, statement):
            statements.append(statement)
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [asset]))

    async def audit(*args, **kwargs):
        return None

    monkeypatch.setattr("app.services.audit.record", audit)
    await apply_cmdb_csv(
        _Session(),
        principal,
        parse_cmdb_csv(
            b"asset_type,asset_value,environment\n" b"domain,dev-api.example.com,production\n"
        ),
        dry_run=False,
    )
    assert asset.environment == "production"
    assert len(statements) == 2
    assert org_id in statements[1].compile(dialect=postgresql.dialect()).params.values()


@pytest.mark.asyncio
async def test_cmdb_api_import_is_tenant_scoped_and_commits_one_update(monkeypatch) -> None:
    from app.api.v1.assets import import_cmdb_assets

    org_id, foreign_org_id = uuid.uuid4(), uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    own = Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="api.example.com",
        asset_type="domain",
        criticality="unknown",
        criticality_source="default",
        environment="unknown",
        groups=[],
        owner_team=None,
    )
    foreign = Asset(
        id=uuid.uuid4(),
        organization_id=foreign_org_id,
        name="foreign.example.com",
        asset_type="domain",
        criticality="unknown",
        criticality_source="default",
        environment="unknown",
        groups=[],
        owner_team=None,
    )
    statements = []

    class _Session:
        committed = False

        async def execute(self, statement):
            statements.append(statement)
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [own, foreign]))

        async def commit(self):
            self.committed = True

    async def audit(*args, **kwargs):
        return None

    monkeypatch.setattr("app.services.audit.record", audit)
    session = _Session()
    file = UploadFile(
        file=io.BytesIO(
            b"asset_type,asset_value,owner_team\n"
            b"domain,api.example.com,Platform\n"
            b"domain,foreign.example.com,Other\n"
        ),
        filename="cmdb.csv",
    )
    result = await import_cmdb_assets(
        file=file, dry_run=False, principal=principal, session=session
    )
    assert result.matched == 1
    assert result.updated == 1
    assert result.unmatched == ["domain:foreign.example.com"]
    assert own.owner_team == "Platform"
    assert foreign.owner_team is None
    assert session.committed
    query = statements[0].compile(dialect=postgresql.dialect())
    assert org_id in query.params.values()
