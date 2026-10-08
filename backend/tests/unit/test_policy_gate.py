"""CI gates fail closed without coverage and never read another tenant's findings."""

from __future__ import annotations

import datetime as dt
import uuid
from types import SimpleNamespace

import pytest
from fastapi import FastAPI

from app.core.errors import TenantIsolationError
from app.db.enums import Role
from app.db.models.asset import Asset
from app.services.context import Principal


def test_policy_gate_is_exposed_as_an_authenticated_asset_api() -> None:
    from app.api.v1.assets import router

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    path = app.openapi()["paths"]["/api/v1/assets/{asset_id}/policy-gate"]
    assert "get" in path
    assert path["get"]["security"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("counts", "scan_age_days", "decision", "allowed"),
    [
        ({"critical": 1}, None, "block", False),
        ({"high": 2}, 1, "warn", True),
        ({}, 1, "pass", True),
        ({}, None, "unknown", False),
        ({"high": 1}, 10, "unknown", False),
    ],
)
async def test_gate_uses_open_canonical_severity_and_recent_imported_scan(
    counts,
    scan_age_days,
    decision,
    allowed,
) -> None:
    from app.services.policy_gate import evaluate_asset_gate

    organization_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    principal = Principal(
        user_id=uuid.uuid4(),
        organization_id=organization_id,
        role=Role.DEVELOPER,
    )
    asset = Asset(
        id=asset_id,
        organization_id=organization_id,
        name="https://github.com/acme/api",
        asset_type="repository",
        status="active",
    )
    now = dt.datetime(2026, 10, 6, tzinfo=dt.UTC)
    scan_at = now - dt.timedelta(days=scan_age_days) if scan_age_days is not None else None

    class _Rows:
        def __init__(self, *, item=None, rows=None):
            self.item = item
            self.rows = rows or []

        def scalar_one_or_none(self):
            return self.item

        def scalar_one(self):
            return self.item

        def all(self):
            return self.rows

        def scalars(self):
            return SimpleNamespace(all=lambda: self.rows)

    class _Session:
        async def execute(self, statement):
            sql = str(statement)
            assert "organization_id" in sql
            if "FROM assets" in sql and "assets.id =" in sql:
                return _Rows(item=asset)
            if "FROM assets" in sql:
                return _Rows(rows=[])
            if "FROM canonical_findings" in sql:
                assert "status" in sql and "asset_id" in sql
                return _Rows(rows=list(counts.items()))
            if "FROM scanner_jobs" in sql:
                assert "imported_at" in sql and "targets" in sql
                return _Rows(item=scan_at)
            raise AssertionError(f"unexpected query: {sql}")

    result = await evaluate_asset_gate(_Session(), principal, asset_id, now=now)
    assert result.decision == decision
    assert result.allow_deploy is allowed
    assert result.counts["critical"] == counts.get("critical", 0)
    assert result.counts["high"] == counts.get("high", 0)


@pytest.mark.asyncio
async def test_gate_does_not_evaluate_a_foreign_asset() -> None:
    from app.services.policy_gate import evaluate_asset_gate

    principal = Principal(
        user_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        role=Role.DEVELOPER,
    )
    foreign = Asset(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        name="https://github.com/other/api",
        asset_type="repository",
    )

    class _Session:
        async def execute(self, statement):
            assert "FROM assets" in str(statement)
            assert "organization_id" in str(statement)
            return SimpleNamespace(scalar_one_or_none=lambda: None)

    with pytest.raises(TenantIsolationError):
        await evaluate_asset_gate(_Session(), principal, foreign.id)


@pytest.mark.asyncio
async def test_gate_counts_critical_finding_on_legacy_source_alias() -> None:
    from app.services.policy_gate import evaluate_asset_gate

    organization_id = uuid.uuid4()
    principal = Principal(
        user_id=uuid.uuid4(),
        organization_id=organization_id,
        role=Role.DEVELOPER,
    )
    scanned = Asset(
        id=uuid.uuid4(),
        organization_id=organization_id,
        name="https://github.com/acme/api",
        asset_type="repository",
        status="active",
    )
    legacy = Asset(
        id=uuid.uuid4(),
        organization_id=organization_id,
        name="repo:acme/api",
        asset_type="repo",
        status="active",
    )
    now = dt.datetime(2026, 10, 6, tzinfo=dt.UTC)
    queries = []

    class _Rows:
        def __init__(self, *, item=None, rows=None):
            self.item = item
            self.rows = rows or []

        def scalar_one_or_none(self):
            return self.item

        def scalar_one(self):
            return self.item

        def all(self):
            return self.rows

        def scalars(self):
            return SimpleNamespace(all=lambda: self.rows)

    class _Session:
        async def execute(self, statement):
            sql = str(statement)
            assert "organization_id" in sql
            queries.append(statement)
            if "FROM assets" in sql and "assets.id =" in sql:
                return _Rows(item=scanned)
            if "FROM assets" in sql:
                return _Rows(rows=[legacy])
            if "FROM canonical_findings" in sql:
                params = statement.compile().params
                selected_ids = next(
                    value
                    for value in params.values()
                    if isinstance(value, list) and scanned.id in value
                )
                return _Rows(rows=[("critical", 1)] if legacy.id in selected_ids else [])
            if "FROM scanner_jobs" in sql:
                return _Rows(item=now - dt.timedelta(hours=1))
            raise AssertionError(sql)

    result = await evaluate_asset_gate(_Session(), principal, scanned.id, now=now)
    assert result.decision == "block"
    assert result.allow_deploy is False


@pytest.mark.asyncio
async def test_gate_does_not_treat_inventory_only_scans_as_vulnerability_coverage() -> None:
    from app.services.policy_gate import evaluate_asset_gate

    organization_id = uuid.uuid4()
    asset = Asset(
        id=uuid.uuid4(),
        organization_id=organization_id,
        name="https://github.com/acme/api",
        asset_type="repository",
        status="active",
    )
    principal = Principal(
        user_id=uuid.uuid4(),
        organization_id=organization_id,
        role=Role.DEVELOPER,
    )
    now = dt.datetime(2026, 10, 6, tzinfo=dt.UTC)

    class _Rows:
        def __init__(self, *, item=None, rows=None):
            self.item = item
            self.rows = rows or []

        def scalar_one_or_none(self):
            return self.item

        def scalar_one(self):
            return self.item

        def all(self):
            return self.rows

        def scalars(self):
            return SimpleNamespace(all=lambda: self.rows)

    class _Session:
        async def execute(self, statement):
            sql = str(statement)
            if "FROM assets" in sql and "assets.id =" in sql:
                return _Rows(item=asset)
            if "FROM assets" in sql or "FROM canonical_findings" in sql:
                return _Rows(rows=[])
            if "FROM scanner_jobs" in sql:
                params = statement.compile().params.values()
                scanner_sets = [
                    value
                    for value in params
                    if isinstance(value, list | tuple)
                    and any(name in value for name in ("reconftw", "nuclei", "trivy_repo"))
                ]
                if "scanner_jobs.scanner" not in sql or not scanner_sets:
                    return _Rows(item=now)
                assert "reconftw" not in scanner_sets[0]
                assert "nmap" not in scanner_sets[0]
                return _Rows(item=None)
            raise AssertionError(sql)

    result = await evaluate_asset_gate(_Session(), principal, asset.id, now=now)
    assert result.decision == "unknown"
    assert result.allow_deploy is False
