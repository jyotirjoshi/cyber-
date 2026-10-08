"""Tenant-owned structured business fields remain separate from scanner evidence."""

import uuid
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql

from app.db.enums import Role
from app.db.models.asset import Asset
from app.db.models.canonical import CanonicalFinding
from app.schemas.asset import AssetContextIn
from app.schemas.canonical import CanonicalWorkIn
from app.services.context import Principal


def test_asset_and_finding_custom_fields_accept_bounded_scalar_values() -> None:
    fields = {"service_tier": "gold", "regulated": True, "cost_center": 42}
    assert AssetContextIn(custom_fields=fields).custom_fields == fields
    assert CanonicalWorkIn(expected_version=0, custom_fields=fields).custom_fields == fields


@pytest.mark.parametrize(
    "fields",
    [
        {"api_key": "must-not-store"},
        {"owner": {"nested": "object"}},
        {"a": "x" * 201},
        {"notes": "sk-abcdefghijklmnopqrstuvwxyz123456"},
        {f"field_{i}": i for i in range(21)},
    ],
)
def test_custom_fields_reject_secrets_nested_data_and_unbounded_values(fields) -> None:
    with pytest.raises(ValidationError):
        AssetContextIn(custom_fields=fields)
    with pytest.raises(ValidationError):
        CanonicalWorkIn(expected_version=0, custom_fields=fields)


@pytest.mark.asyncio
async def test_finding_custom_fields_update_is_tenant_scoped_and_versioned(monkeypatch) -> None:
    from app.services.canonical_work import update_work

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    finding = CanonicalFinding(
        id=uuid.uuid4(),
        organization_id=org_id,
        asset_id=uuid.uuid4(),
        status="open",
        status_version=3,
        custom_fields={},
    )
    statements = []
    added = []

    class _Session:
        async def execute(self, statement):
            statements.append(statement)
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [finding]))

        def add(self, row):
            added.append(row)

    async def audit(*args, **kwargs):
        return None

    monkeypatch.setattr("app.services.canonical_work.audit_service.record", audit)
    result = await update_work(
        _Session(),
        principal,
        finding.id,
        CanonicalWorkIn(expected_version=3, custom_fields={"service_tier": "gold"}),
    )
    assert result.custom_fields == {"service_tier": "gold"}
    assert result.status_version == 4
    assert len(added) == 1
    query = statements[0].compile(dialect=postgresql.dialect())
    assert org_id in query.params.values()
    assert finding.id in query.params.values()


@pytest.mark.asyncio
async def test_asset_custom_fields_update_does_not_replace_scanner_evidence(monkeypatch) -> None:
    from app.services.asset import set_asset_context

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    asset = Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="api.example.com",
        asset_type="domain",
        evidence={"technology": "nmap"},
        custom_fields={},
    )

    class _Repo:
        async def get_or_404(self, asset_id):
            assert asset_id == asset.id
            return asset

    audit_calls = []

    async def audit(*args, **kwargs):
        audit_calls.append(kwargs)
        return None

    monkeypatch.setattr(
        "app.services.asset.TenantRepository", lambda session, model, tenant: _Repo()
    )
    monkeypatch.setattr("app.services.asset.audit_service.record", audit)
    result = await set_asset_context(
        object(),
        principal,
        asset.id,
        AssetContextIn(custom_fields={"service_tier": "gold"}),
    )
    assert result.custom_fields == {"service_tier": "gold"}
    assert result.evidence == {"technology": "nmap"}
    assert "gold" not in str(audit_calls)
