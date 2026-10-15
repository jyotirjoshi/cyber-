"""Ingestion merges equivalent source records while retaining provenance."""

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql.dml import Insert

from app.core.errors import ConflictError, InvalidConfigurationError
from app.db.enums import Role
from app.db.models.asset import Asset
from app.db.models.audit import AuditEvent
from app.db.models.canonical import (
    AutomationRule,
    CanonicalFinding,
    FindingHistory,
    FindingObservation,
)
from app.db.models.external_alert import ExternalSecurityAlert
from app.db.models.identity import Organization
from app.services.canonical_identity import identity_for_observation
from app.services.canonical_ingest import ingest_external_alerts
from app.services.context import Principal
from app.services.external_alert import stage_github_alerts


class _Rows:
    def __init__(self, rows):
        self.rows = rows

    def scalar_one(self):
        return self.rows[0]

    def scalars(self):
        return self

    def all(self):
        return self.rows


class _Session:
    def __init__(self, organization_id):
        self.organization = Organization(
            id=organization_id, name="Test", slug="test", entitlements={}
        )
        self.added = []
        self.statements = []
        self.inserted_alerts = []
        self.existing_assets = []
        self.existing_findings = []

    def add(self, row):
        self.added.append(row)

    async def flush(self):
        pass

    async def execute(self, statement):
        self.statements.append(statement)
        if isinstance(statement, Insert):
            return _Rows(self.inserted_alerts)
        entity = statement.column_descriptions[0]["entity"]
        if entity is Organization:
            return _Rows([self.organization])
        if entity is Asset:
            return _Rows(
                self.existing_assets + [row for row in self.added if isinstance(row, Asset)]
            )
        if entity is CanonicalFinding:
            return _Rows(
                self.existing_findings
                + [row for row in self.added if isinstance(row, CanonicalFinding)]
            )
        if entity is FindingObservation:
            return _Rows([row for row in self.added if isinstance(row, FindingObservation)])
        if entity is AutomationRule:
            return _Rows([])
        return _Rows([len([row for row in self.added if isinstance(row, Asset)])])


@pytest.mark.asyncio
async def test_two_providers_one_repo_cve_create_one_finding_two_observations(monkeypatch) -> None:
    from app.services import canonical_ingest

    organization_id = uuid.uuid4()
    session = _Session(organization_id)
    session.organization.policy = {"sla_targets_days": {"critical": 2}}
    alerts = [
        SimpleNamespace(
            id=uuid.uuid4(),
            organization_id=organization_id,
            provider="github",
            external_id="dependabot:Acme/Api:7",
            resource="Acme/Api",
            evidence={},
            cve_ids=["CVE-2024-12345"],
            title="Vulnerable library",
            severity="high",
            status="open",
            source_url=None,
        ),
        SimpleNamespace(
            id=uuid.uuid4(),
            organization_id=organization_id,
            provider="gitlab",
            external_id="acme/api:uuid-7",
            resource="acme/api:requirements.txt",
            evidence={"project": "acme/api"},
            cve_ids=["CVE-2024-12345"],
            title="Library vulnerability",
            severity="critical",
            status="open",
            source_url=None,
        ),
    ]

    queued: list[tuple[uuid.UUID, uuid.UUID, str]] = []

    async def fake_queue(_session, *, finding, asset, trigger):
        queued.append((finding.id, asset.id, trigger))
        return 1

    monkeypatch.setattr(canonical_ingest, "queue_finding_event", fake_queue, raising=False)
    await ingest_external_alerts(session, organization_id, alerts)

    assets = [row for row in session.added if isinstance(row, Asset)]
    findings = [row for row in session.added if isinstance(row, CanonicalFinding)]
    observations = [row for row in session.added if isinstance(row, FindingObservation)]
    history = [row for row in session.added if isinstance(row, FindingHistory)]
    assert len(assets) == len(findings) == len(history) == 1
    assert len(observations) == 2
    assert {row.provider for row in observations} == {"github", "gitlab"}
    assert {row.canonical_finding_id for row in observations} == {findings[0].id}
    assert findings[0].severity == "critical"
    assert findings[0].asset_id == assets[0].id
    assert findings[0].risk_score > 0
    assert findings[0].due_at is not None
    assert findings[0].due_at - findings[0].first_seen_at == __import__("datetime").timedelta(days=2)
    assert findings[0].risk_factors["inputs"]["severity_label"] == "critical"
    assert queued == [(findings[0].id, assets[0].id, "finding.created")]
    observation_lookup = next(
        statement
        for statement in session.statements
        if statement.column_descriptions[0]["entity"] is FindingObservation
    )
    lookup_sql = str(observation_lookup.compile(dialect=postgresql.dialect()))
    assert "(finding_observations.provider, finding_observations.external_id) IN" in lookup_sql


@pytest.mark.asyncio
async def test_integration_reuses_scanned_repository_asset_for_same_exposure() -> None:
    organization_id = uuid.uuid4()
    session = _Session(organization_id)
    scanned = Asset(
        id=uuid.uuid4(),
        organization_id=organization_id,
        name="https://github.com/acme/api",
        asset_type="repository",
        criticality="normal",
        internet_exposed=False,
    )
    session.existing_assets = [scanned]
    alert = SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=organization_id,
        provider="github",
        external_id="dependabot:acme/api:7",
        resource="acme/api",
        evidence={},
        cve_ids=["CVE-2024-12345"],
        title="Vulnerable package",
        severity="high",
        status="open",
        source_url=None,
    )
    await ingest_external_alerts(session, organization_id, [alert])
    assert not [row for row in session.added if isinstance(row, Asset)]
    finding = next(row for row in session.added if isinstance(row, CanonicalFinding))
    assert finding.asset_id == scanned.id


@pytest.mark.asyncio
async def test_matching_asset_from_other_tenant_is_never_reused() -> None:
    organization_id = uuid.uuid4()
    session = _Session(organization_id)
    foreign = Asset(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        name="https://github.com/acme/api",
        asset_type="repository",
    )
    session.existing_assets = [foreign]
    alert = SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=organization_id,
        provider="github",
        external_id="dependabot:acme/api:7",
        resource="acme/api",
        evidence={},
        cve_ids=["CVE-2024-12345"],
        title="Vulnerable package",
        severity="high",
        status="open",
        source_url=None,
    )
    await ingest_external_alerts(session, organization_id, [alert])
    created = [row for row in session.added if isinstance(row, Asset)]
    assert len(created) == 1
    assert created[0].organization_id == organization_id
    finding = next(row for row in session.added if isinstance(row, CanonicalFinding))
    assert finding.asset_id == created[0].id


@pytest.mark.asyncio
async def test_external_ingest_rejects_cross_tenant_asset_override() -> None:
    organization_id = uuid.uuid4()
    session = _Session(organization_id)
    foreign = Asset(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        name="https://github.com/acme/api",
        asset_type="repository",
    )
    alert = SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=organization_id,
        provider="github",
        external_id="dependabot:acme/api:7",
        resource="acme/api",
        evidence={},
        cve_ids=["CVE-2024-12345"],
        title="Vulnerable package",
        severity="high",
        status="open",
        source_url=None,
    )
    with pytest.raises(ValueError, match="cross-tenant asset override"):
        await ingest_external_alerts(
            session,
            organization_id,
            [alert],
            asset_overrides={("repo", "acme/api"): foreign},
        )


@pytest.mark.asyncio
async def test_ambiguous_same_named_repositories_do_not_guess_an_asset() -> None:
    organization_id = uuid.uuid4()
    session = _Session(organization_id)
    session.existing_assets = [
        Asset(
            id=uuid.uuid4(),
            organization_id=organization_id,
            name=f"https://{host}/acme/api",
            asset_type="repository",
        )
        for host in ("github.com", "gitlab.com")
    ]
    alert = SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=organization_id,
        provider="github",
        external_id="dependabot:acme/api:7",
        resource="acme/api",
        evidence={},
        cve_ids=["CVE-2024-12345"],
        title="Vulnerable package",
        severity="high",
        status="open",
        source_url=None,
    )
    await ingest_external_alerts(session, organization_id, [alert])
    created = [row for row in session.added if isinstance(row, Asset)]
    assert len(created) == 1
    assert created[0].name == "repo:acme/api"


@pytest.mark.asyncio
async def test_existing_canonical_exposure_moves_from_legacy_alias_to_scanned_asset() -> None:
    organization_id = uuid.uuid4()
    session = _Session(organization_id)
    legacy = Asset(
        id=uuid.uuid4(),
        organization_id=organization_id,
        name="repo:acme/api",
        asset_type="repo",
    )
    scanned = Asset(
        id=uuid.uuid4(),
        organization_id=organization_id,
        name="https://github.com/acme/api",
        asset_type="repository",
        criticality="high",
        internet_exposed=False,
    )
    session.existing_assets = [legacy, scanned]
    exposure = CanonicalFinding(
        id=uuid.uuid4(),
        organization_id=organization_id,
        asset_id=legacy.id,
        fingerprint=identity_for_observation(
            "repo",
            "acme/api",
            ["CVE-2024-12345"],
            "github",
            "previous",
        ),
        title="Vulnerable package",
        severity="high",
        status="open",
        cve_ids=["CVE-2024-12345"],
    )
    session.existing_findings = [exposure]
    alert = SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=organization_id,
        provider="github",
        external_id="dependabot:acme/api:7",
        resource="acme/api",
        evidence={},
        cve_ids=["CVE-2024-12345"],
        title="Vulnerable package",
        severity="high",
        status="open",
        source_url=None,
    )
    await ingest_external_alerts(session, organization_id, [alert])
    assert exposure.asset_id == scanned.id


@pytest.mark.asyncio
async def test_enterprise_git_repository_import_reuses_its_scanned_asset() -> None:
    organization_id = uuid.uuid4()
    session = _Session(organization_id)
    scanned = Asset(
        id=uuid.uuid4(),
        organization_id=organization_id,
        name="https://git.company.example/acme/api",
        asset_type="repository",
    )
    session.existing_assets = [scanned]
    alert = SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=organization_id,
        provider="semgrep",
        external_id="rule:7",
        resource=scanned.name,
        evidence={"asset_type": "repo", "asset_value": scanned.name},
        cve_ids=["CVE-2024-12345"],
        title="Vulnerable package",
        severity="high",
        status="open",
        source_url=None,
    )
    await ingest_external_alerts(session, organization_id, [alert])
    assert not [row for row in session.added if isinstance(row, Asset)]
    finding = next(row for row in session.added if isinstance(row, CanonicalFinding))
    assert finding.asset_id == scanned.id


@pytest.mark.asyncio
async def test_source_asset_reassignment_closes_orphaned_canonical_finding() -> None:
    """A moved source must not leave an unsupported old exposure open."""
    organization_id = uuid.uuid4()
    session = _Session(organization_id)
    source_id = "dependabot:acme/legacy:7"

    def alert(repo: str):
        return SimpleNamespace(
            id=uuid.uuid4(),
            organization_id=organization_id,
            provider="github",
            external_id=source_id,
            resource=repo,
            evidence={"project": repo},
            cve_ids=["CVE-2024-12345"],
            title="Vulnerable library",
            severity="high",
            status="open",
            source_url=None,
        )

    await ingest_external_alerts(session, organization_id, [alert("acme/legacy")])
    old = next(row for row in session.added if isinstance(row, CanonicalFinding))
    await ingest_external_alerts(session, organization_id, [alert("acme/current")])

    findings = [row for row in session.added if isinstance(row, CanonicalFinding)]
    observations = [row for row in session.added if isinstance(row, FindingObservation)]
    assert len(findings) == 2
    assert len(observations) == 1
    assert observations[0].canonical_finding_id != old.id
    assert old.status == "closed"
    assert old.closed_at is not None
    assert any(
        row.canonical_finding_id == old.id and row.new_status == "closed"
        for row in session.added
        if isinstance(row, FindingHistory)
    )


@pytest.mark.asyncio
async def test_source_cve_replacement_supersedes_old_observation() -> None:
    organization_id = uuid.uuid4()
    session = _Session(organization_id)

    def alert(cve: str):
        return SimpleNamespace(
            id=uuid.uuid4(),
            organization_id=organization_id,
            provider="github",
            external_id="dependabot:acme/api:7",
            resource="acme/api",
            evidence={},
            cve_ids=[cve],
            title="Vulnerable library",
            severity="high",
            status="open",
            source_url=None,
        )

    await ingest_external_alerts(session, organization_id, [alert("CVE-2024-11111")])
    old = next(row for row in session.added if isinstance(row, CanonicalFinding))
    await ingest_external_alerts(session, organization_id, [alert("CVE-2024-22222")])

    observations = [row for row in session.added if isinstance(row, FindingObservation)]
    assert len(observations) == 2
    assert (
        next(row for row in observations if row.cve_id == "CVE-2024-11111").source_status
        == "superseded"
    )
    assert old.status == "closed"
    assert next(
        row for row in session.added if isinstance(row, CanonicalFinding) and row.id != old.id
    ).status in {"new", "open"}


@pytest.mark.asyncio
async def test_github_staging_populates_canonical_ledger_in_same_transaction() -> None:
    organization_id = uuid.uuid4()
    session = _Session(organization_id)
    session.inserted_alerts = [
        ExternalSecurityAlert(
            id=uuid.uuid4(),
            organization_id=organization_id,
            provider="github",
            external_id="dependabot:acme/api:7",
            category="dependabot",
            resource="acme/api",
            evidence={},
            cve_ids=["CVE-2024-12345"],
            title="Vulnerable library",
            severity="high",
            status="open",
            source_url=None,
        )
    ]

    result = await stage_github_alerts(
        session,
        organization_id=organization_id,
        integration_id=None,
        feeds=[
            (
                "dependabot",
                [
                    {
                        "number": 7,
                        "repository": {"full_name": "acme/api"},
                        "state": "open",
                        "security_advisory": {
                            "summary": "Vulnerable library",
                            "severity": "high",
                            "identifiers": [{"type": "CVE", "value": "CVE-2024-12345"}],
                        },
                    }
                ],
            )
        ],
    )

    assert result.total == 1
    assert len([row for row in session.added if isinstance(row, CanonicalFinding)]) == 1
    assert len([row for row in session.added if isinstance(row, FindingObservation)]) == 1


@pytest.mark.asyncio
async def test_multi_cve_alert_projects_one_finding_per_cve() -> None:
    organization_id = uuid.uuid4()
    session = _Session(organization_id)
    alert = SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=organization_id,
        provider="github",
        external_id="dependabot:acme/api:8",
        resource="acme/api",
        evidence={},
        cve_ids=["CVE-2024-11111", "CVE-2024-22222"],
        title="Affected dependency",
        severity="high",
        status="open",
        source_url=None,
    )

    await ingest_external_alerts(session, organization_id, [alert])

    findings = [row for row in session.added if isinstance(row, CanonicalFinding)]
    observations = [row for row in session.added if isinstance(row, FindingObservation)]
    assert len(findings) == len(observations) == 2
    assert {tuple(row.cve_ids) for row in findings} == {
        ("CVE-2024-11111",),
        ("CVE-2024-22222",),
    }
    assert {row.cve_id for row in observations} == {"CVE-2024-11111", "CVE-2024-22222"}


@pytest.mark.asyncio
async def test_defectdojo_finding_links_existing_inventory_asset() -> None:
    from app.services.canonical_ingest import ingest_native_findings

    organization_id = uuid.uuid4()
    session = _Session(organization_id)
    asset = Asset(
        id=uuid.uuid4(),
        organization_id=organization_id,
        name="host.example",
        asset_type="domain",
        status="active",
        risk_score=0.0,
        criticality="unknown",
        criticality_source="default",
        evidence={},
        seen_in_assessments=[],
        technology=[],
    )
    session.existing_assets = [asset]
    native = SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=organization_id,
        asset_id=asset.id,
        defectdojo_finding_id=77,
        title="TLS flaw",
        severity="high",
        status="active",
        cve_ids=["CVE-2024-12345"],
        endpoint="https://host.example/",
        cvss_score=9.5,
    )

    await ingest_native_findings(session, organization_id, [native])

    canonical = [row for row in session.added if isinstance(row, CanonicalFinding)]
    observations = [row for row in session.added if isinstance(row, FindingObservation)]
    assert len(canonical) == len(observations) == 1
    assert canonical[0].asset_id == asset.id
    assert observations[0].provider == "defectdojo"
    assert canonical[0].risk_factors["inputs"]["cvss_score"] == 9.5
    assert not [row for row in session.added if isinstance(row, Asset)]


@pytest.mark.asyncio
async def test_defectdojo_finding_without_inventory_match_uses_endpoint_host() -> None:
    from app.services.canonical_ingest import ingest_native_findings

    organization_id = uuid.uuid4()
    session = _Session(organization_id)
    native = SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=organization_id,
        asset_id=None,
        defectdojo_finding_id=78,
        title="TLS flaw",
        severity="high",
        status="active",
        cve_ids=["CVE-2024-12345"],
        endpoint="https://Host.Example:443/login",
    )

    await ingest_native_findings(session, organization_id, [native])

    assets = [row for row in session.added if isinstance(row, Asset)]
    canonical = [row for row in session.added if isinstance(row, CanonicalFinding)]
    assert len(assets) == len(canonical) == 1
    assert assets[0].name == "domain:host.example"
    assert canonical[0].asset_id == assets[0].id


@pytest.mark.asyncio
async def test_two_complete_scoped_absences_close_canonical_finding() -> None:
    from app.services.canonical_ingest import reconcile_absent_observations

    organization_id = uuid.uuid4()
    session = _Session(organization_id)
    finding_id = uuid.uuid4()
    finding = CanonicalFinding(
        id=finding_id,
        organization_id=organization_id,
        asset_id=uuid.uuid4(),
        fingerprint="a" * 64,
        title="SQL injection",
        severity="high",
        status="open",
        cve_ids=[],
        first_seen_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        last_seen_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        absence_count=0,
        status_version=0,
    )
    observation = FindingObservation(
        id=uuid.uuid4(),
        organization_id=organization_id,
        canonical_finding_id=finding_id,
        provider="sonarqube",
        external_id="payments:AZ123",
        cve_id="",
        source_status="open",
        title="SQL injection",
        severity="high",
        evidence={"project": "payments"},
        first_seen_at=finding.first_seen_at,
        last_seen_at=finding.last_seen_at,
        missing_sync_count=0,
    )
    session.add(finding)
    session.add(observation)

    await reconcile_absent_observations(
        session,
        organization_id,
        provider="sonarqube",
        scope_keys=["payments"],
        observed_external_ids=[],
    )
    assert finding.status == "open"
    assert observation.missing_sync_count == 1

    await reconcile_absent_observations(
        session,
        organization_id,
        provider="sonarqube",
        scope_keys=["payments"],
        observed_external_ids=[],
    )
    assert finding.status == "closed"
    assert observation.source_status == "absent"
    assert finding.status_version == 1
    assert [row.new_status for row in session.added if isinstance(row, FindingHistory)] == [
        "closed"
    ]


@pytest.mark.asyncio
async def test_absent_source_no_longer_inflates_surviving_finding_risk() -> None:
    from app.services.canonical_ingest import reconcile_absent_observations

    organization_id = uuid.uuid4()
    asset = Asset(
        id=uuid.uuid4(),
        organization_id=organization_id,
        name="api.example",
        asset_type="domain",
        criticality="unknown",
        internet_exposed=False,
    )
    finding = CanonicalFinding(
        id=uuid.uuid4(),
        organization_id=organization_id,
        asset_id=asset.id,
        fingerprint="c" * 64,
        title="Risk",
        severity="high",
        status="open",
        risk_score=100.0,
        risk_factors={},
        risk_policy_version=0,
    )
    sonar = FindingObservation(
        id=uuid.uuid4(),
        organization_id=organization_id,
        canonical_finding_id=finding.id,
        provider="sonarqube",
        external_id="api:issue",
        cve_id="CVE-2024-12345",
        source_status="open",
        title="Risk",
        severity="high",
        missing_sync_count=1,
        evidence={"project": "api", "epss_score": 0.9, "in_kev": True},
    )
    github = FindingObservation(
        id=uuid.uuid4(),
        organization_id=organization_id,
        canonical_finding_id=finding.id,
        provider="github",
        external_id="repo:issue",
        cve_id="CVE-2024-12345",
        source_status="open",
        title="Risk",
        severity="high",
        missing_sync_count=0,
        evidence={"epss_score": 0.1},
    )
    organization = Organization(
        id=organization_id,
        name="Acme",
        slug="acme",
        policy={},
        risk_policy_version=2,
    )
    session = AsyncMock()
    session.add = MagicMock()
    session.execute.side_effect = [
        _Rows([sonar]),
        _Rows([sonar, github]),
        _Rows([finding]),
        _Rows([asset]),
        _Rows([organization]),
    ]

    changed = await reconcile_absent_observations(
        session,
        organization_id,
        provider="sonarqube",
        scope_keys=["api"],
        observed_external_ids=[],
    )

    assert changed == 1
    assert sonar.source_status == "absent"
    assert finding.status == "open"
    assert finding.risk_factors["inputs"]["epss_score"] == 0.1
    assert finding.risk_factors["inputs"]["in_kev"] is None
    assert finding.risk_score == 34.2
    assert finding.risk_policy_version == 2
    first_query = session.execute.call_args_list[0].args[0]
    sql = str(first_query.compile(dialect=postgresql.dialect()))
    assert "finding_observations.source_status NOT IN" in sql


@pytest.mark.asyncio
async def test_analyst_risk_acceptance_requires_reason_and_records_history() -> None:
    from app.services.canonical_decision import decide_status

    organization_id = uuid.uuid4()
    actor = Principal(
        user_id=uuid.uuid4(), organization_id=organization_id, role=Role.SECURITY_ENGINEER
    )
    session = _Session(organization_id)
    now = __import__("datetime").datetime.now(__import__("datetime").UTC)
    finding = CanonicalFinding(
        id=uuid.uuid4(),
        organization_id=organization_id,
        asset_id=uuid.uuid4(),
        fingerprint="b" * 64,
        title="Risk",
        severity="high",
        status="new",
        cve_ids=[],
        first_seen_at=now,
        last_seen_at=now,
        absence_count=0,
        status_version=0,
    )
    session.add(finding)

    with pytest.raises(InvalidConfigurationError):
        await decide_status(
            session, actor, finding.id, status="accepted_risk", reason="", expected_version=0
        )
    with pytest.raises(ConflictError):
        await decide_status(
            session,
            actor,
            finding.id,
            status="accepted_risk",
            reason="Reviewed by owner",
            expected_version=1,
        )
    assert finding.status == "new"

    await decide_status(
        session,
        actor,
        finding.id,
        status="accepted_risk",
        reason="Reviewed by owner",
        expected_version=0,
    )
    assert finding.status == "accepted_risk"
    assert finding.status_version == 1
    assert finding.disposition_reason == "Reviewed by owner"
    assert [row.new_status for row in session.added if isinstance(row, FindingHistory)] == [
        "accepted_risk"
    ]
    assert [row.action for row in session.added if isinstance(row, AuditEvent)] == [
        "finding.status.change"
    ]
