"""Tenant weight changes must make persisted canonical scores refreshable."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.db.enums import Criticality, CriticalitySource, Role
from app.db.models.asset import Asset
from app.db.models.canonical import CanonicalFinding, FindingObservation
from app.db.models.identity import Organization
from app.scanners.recon_assets import DiscoveredAsset
from app.schemas.asset import AssetCriticalityIn
from app.schemas.organization import OrganizationUpdateIn
from app.services.asset import score_and_select, set_criticality, upsert_assets
from app.services.canonical_risk_refresh import refresh_stale_risk_batch
from app.services.context import Principal
from app.services.organization import update_organization


@pytest.mark.asyncio
async def test_weight_change_increments_tenant_risk_policy_version() -> None:
    organization = Organization(
        id=uuid.uuid4(),
        name="Acme",
        slug="acme",
        is_active=True,
        max_concurrent_scanner_jobs=4,
        policy={},
        entitlements={},
        risk_policy_version=0,
    )
    principal = Principal(
        user_id=uuid.uuid4(),
        organization_id=organization.id,
        role=Role.OWNER,
    )
    session = AsyncMock()
    session.get.return_value = organization
    with patch("app.services.organization.audit.record", new_callable=AsyncMock):
        await update_organization(
            session,
            principal,
            OrganizationUpdateIn(
                policy={
                    "risk_weights": {
                        "severity": 30,
                        "exploitation": 35,
                        "exploit_probability": 10,
                        "exposure": 15,
                        "asset_criticality": 5,
                        "ransomware": 5,
                    }
                }
            ),
        )
    assert organization.risk_policy_version == 1


def test_canonical_finding_stores_policy_version_of_its_score() -> None:
    assert not Organization.__table__.c.risk_policy_version.nullable
    assert not CanonicalFinding.__table__.c.risk_policy_version.nullable


@pytest.mark.asyncio
async def test_refresh_recomputes_stale_score_from_current_tenant_weights() -> None:
    import datetime as dt

    org_id = uuid.uuid4()
    asset = Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="api.example",
        asset_type="domain",
        criticality="high",
        internet_exposed=True,
    )
    organization = Organization(
        id=org_id,
        name="Acme",
        slug="acme",
        policy={
            "risk_weights": {
                "severity": 30,
                "exploitation": 35,
                "exploit_probability": 10,
                "exposure": 15,
                "asset_criticality": 5,
                "ransomware": 5,
            }
        },
        risk_policy_version=1,
    )
    now = dt.datetime.now(dt.UTC)
    finding = CanonicalFinding(
        id=uuid.uuid4(),
        organization_id=org_id,
        asset_id=asset.id,
        fingerprint="a" * 64,
        title="Risk",
        severity="high",
        status="open",
        cve_ids=["CVE-2024-12345"],
        first_seen_at=now,
        last_seen_at=now,
        risk_score=46.5,
        risk_factors={},
        risk_policy_version=0,
    )
    observation = FindingObservation(
        id=uuid.uuid4(),
        organization_id=org_id,
        canonical_finding_id=finding.id,
        provider="github",
        external_id="7",
        cve_id="CVE-2024-12345",
        source_status="open",
        title="Risk",
        severity="high",
        first_seen_at=now,
        last_seen_at=now,
        evidence={"in_kev": True, "epss_score": 0.5, "ransomware_use": True},
    )
    rows = MagicMock()
    rows.all.return_value = [(finding, organization, asset)]
    observations = MagicMock()
    observations.scalars.return_value.all.return_value = [observation]
    session = AsyncMock()
    session.execute.side_effect = [rows, observations]

    updated = await refresh_stale_risk_batch(session, limit=10)

    assert updated == 1
    assert finding.risk_score == 83.08
    assert finding.risk_policy_version == 1
    assert finding.risk_factors["inputs"]["in_kev"] is True


@pytest.mark.asyncio
async def test_refresh_joins_assets_and_observations_to_the_finding_tenant() -> None:
    from sqlalchemy.dialects import postgresql

    org_id, finding_id = uuid.uuid4(), uuid.uuid4()
    finding = SimpleNamespace(id=finding_id, organization_id=org_id, severity="high")
    organization = SimpleNamespace(id=org_id, risk_policy_version=1)
    session = AsyncMock()
    rows, observations = MagicMock(), MagicMock()
    rows.all.return_value = [(finding, organization, SimpleNamespace())]
    observations.scalars.return_value.all.return_value = []
    session.execute.side_effect = [rows, observations]
    with patch("app.services.canonical_risk_refresh.score_canonical", return_value=(20, {})), patch(
        "app.services.canonical_risk_refresh.load_policy",
        return_value=SimpleNamespace(risk_weights={}),
    ):
        await refresh_stale_risk_batch(session)

    statements = [
        str(call.args[0].compile(dialect=postgresql.dialect()))
        for call in session.execute.call_args_list
    ]
    assert "assets.organization_id = canonical_findings.organization_id" in statements[0]
    assert (
        "finding_observations.organization_id = canonical_findings.organization_id" in statements[1]
    )


@pytest.mark.asyncio
async def test_curated_asset_criticality_queues_risk_refresh() -> None:
    org_id = uuid.uuid4()
    organization = Organization(
        id=org_id,
        name="Acme",
        slug="acme",
        risk_policy_version=2,
    )
    asset = Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="api.example",
        asset_type="domain",
        criticality="normal",
        criticality_source="default",
    )
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    session = AsyncMock()
    session.get.return_value = organization
    with patch("app.services.asset.TenantRepository") as repo_type, patch(
        "app.services.asset.audit_service.record", new_callable=AsyncMock
    ):
        repo_type.return_value.get_or_404 = AsyncMock(return_value=asset)
        await set_criticality(
            session,
            principal,
            asset.id,
            AssetCriticalityIn(criticality="critical", rationale="Payments"),
        )
    assert organization.risk_policy_version == 3


@pytest.mark.asyncio
async def test_recon_exposure_change_queues_risk_refresh() -> None:
    org_id = uuid.uuid4()
    organization = Organization(id=org_id, name="Acme", slug="acme", risk_policy_version=2)
    assessment = SimpleNamespace(id=uuid.uuid4(), organization_id=org_id)
    asset = Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="api.example",
        asset_type="domain",
        internet_exposed=False,
        technology=[],
        evidence={},
        seen_in_assessments=[],
    )
    session = AsyncMock()
    session.add = MagicMock()
    result = MagicMock()
    result.scalar_one.return_value = organization
    session.execute.return_value = result
    with patch(
        "app.services.asset._load_by_keys",
        new_callable=AsyncMock,
        return_value={
            ("api.example", None, None): asset,
        },
    ), patch(
        "app.services.asset._count_organization_assets", new_callable=AsyncMock, return_value=1
    ), patch("app.services.asset._count_assets", new_callable=AsyncMock, return_value=1), patch(
        "app.services.asset.assert_asset_capacity"
    ):
        await upsert_assets(
            session, assessment, [DiscoveredAsset(name="api.example", asset_type="domain")]
        )
    assert asset.internet_exposed is True
    assert organization.risk_policy_version == 3


@pytest.mark.asyncio
async def test_new_recon_asset_does_not_queue_tenant_wide_risk_refresh() -> None:
    org_id = uuid.uuid4()
    organization = Organization(id=org_id, name="Acme", slug="acme", risk_policy_version=2)
    assessment = SimpleNamespace(id=uuid.uuid4(), organization_id=org_id)
    session = AsyncMock()
    session.add = MagicMock()
    result = MagicMock()
    result.scalar_one.return_value = organization
    session.execute.return_value = result
    with patch("app.services.asset._load_by_keys", new_callable=AsyncMock, return_value={}), patch(
        "app.services.asset._count_organization_assets", new_callable=AsyncMock, return_value=0
    ), patch("app.services.asset._count_assets", new_callable=AsyncMock, return_value=1), patch(
        "app.services.asset.assert_asset_capacity"
    ):
        await upsert_assets(
            session, assessment, [DiscoveredAsset(name="new.example", asset_type="domain")]
        )
    assert organization.risk_policy_version == 2


@pytest.mark.asyncio
async def test_inferred_criticality_change_queues_risk_refresh() -> None:
    org_id = uuid.uuid4()
    organization = Organization(id=org_id, name="Acme", slug="acme", risk_policy_version=4)
    assessment = SimpleNamespace(id=uuid.uuid4(), organization_id=org_id)
    asset = Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="api.example",
        asset_type="domain",
        criticality="unknown",
        criticality_source="default",
        status="active",
        internet_exposed=True,
        technology=[],
        seen_in_assessments=[str(assessment.id)],
        environment="unknown",
        port=None,
    )
    session = AsyncMock()
    result = MagicMock()
    result.scalars.return_value.all.return_value = [asset]
    result.scalar_one.return_value = organization
    session.execute.return_value = result
    session.get.return_value = organization
    with patch(
        "app.services.asset.infer_criticality",
        new_callable=AsyncMock,
        return_value=(
            Criticality.HIGH,
            CriticalitySource.INFERRED_EXPOSURE,
            "Externally reachable",
        ),
    ), patch("app.services.asset.audit_service.record", new_callable=AsyncMock):
        await score_and_select(
            session,
            assessment,
            budget=1,
            settings=SimpleNamespace(
                agent=SimpleNamespace(
                    max_scope_budget=10,
                    criticality_keywords=[],
                )
            ),
        )
    assert asset.criticality == "high"
    assert organization.risk_policy_version == 5
