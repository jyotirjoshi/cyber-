"""ASPM rollups use tenant-owned assets and canonical findings only."""

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from app.db.enums import Role
from app.db.models.asset import Asset
from app.db.models.canonical import CanonicalFinding, FindingObservation
from app.services.context import Principal


@pytest.mark.asyncio
async def test_application_rollup_uses_tenant_filters_and_active_finding_counts() -> None:
    from app.services.application_risk import list_application_risks

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    statements = []

    class _Result:
        def __init__(self, value):
            self.value = value

        def scalar_one(self):
            return self.value

        def all(self):
            return self.value

    class _Session:
        async def execute(self, statement):
            statements.append(statement)
            return _Result(
                1
                if len(statements) == 1
                else [
                    ("payments", 3, 5, 2, 1, 91.5),
                ]
            )

    page = await list_application_risks(_Session(), principal, limit=25, offset=0)
    assert page.total == 1
    assert page.items[0].application == "payments"
    assert page.items[0].asset_count == 3
    assert page.items[0].active_findings == 5
    assert page.items[0].critical == 2
    assert page.items[0].max_risk_score == 91.5
    for statement in statements:
        compiled = statement.compile(dialect=postgresql.dialect())
        assert org_id in compiled.params.values()


@pytest.mark.asyncio
async def test_cross_repo_pattern_needs_distinct_tenant_repositories() -> None:
    from app.services.application_risk import get_application_patterns

    org_id, foreign_org_id = uuid.uuid4(), uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    repo_a = Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="acme/api",
        asset_type="repo",
        custom_fields={"application": "payments"},
    )
    repo_b = Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="acme/worker",
        asset_type="repo",
        custom_fields={"application": "payments"},
    )
    foreign = Asset(
        id=uuid.uuid4(),
        organization_id=foreign_org_id,
        name="other/repo",
        asset_type="repo",
        custom_fields={"application": "payments"},
    )
    cve = "CVE-2026-1234"
    finding_a = CanonicalFinding(
        id=uuid.uuid4(),
        organization_id=org_id,
        asset_id=repo_a.id,
        status="open",
        cve_ids=[cve],
        risk_score=90.0,
    )
    finding_b = CanonicalFinding(
        id=uuid.uuid4(),
        organization_id=org_id,
        asset_id=repo_b.id,
        status="open",
        cve_ids=[cve],
        risk_score=72.0,
    )
    finding_foreign = CanonicalFinding(
        id=uuid.uuid4(),
        organization_id=foreign_org_id,
        asset_id=foreign.id,
        status="open",
        cve_ids=[cve],
        risk_score=99.0,
    )
    observation = FindingObservation(
        id=uuid.uuid4(),
        organization_id=org_id,
        canonical_finding_id=finding_a.id,
        provider="semgrep",
        evidence={"rule_id": "python.lang.security.audit"},
    )
    statements = []

    class _Session:
        async def execute(self, statement):
            statements.append(statement)
            return SimpleNamespace(
                all=lambda: [
                    (finding_a, repo_a, observation),
                    (finding_a, repo_a, observation),
                    (finding_b, repo_b, None),
                    (finding_foreign, foreign, None),
                ]
            )

    report = await get_application_patterns(_Session(), principal, "payments")
    assert report.application == "payments"
    assert report.truncated is False
    assert len(report.patterns) == 1
    assert report.patterns[0].key == cve
    assert report.patterns[0].repository_count == 2
    assert set(report.patterns[0].finding_ids) == {finding_a.id, finding_b.id}
    compiled = statements[0].compile(dialect=postgresql.dialect())
    assert org_id in compiled.params.values()
    assert "payments" in compiled.params.values()


@pytest.mark.asyncio
async def test_repeated_rule_across_one_repository_is_not_cross_repo_pattern() -> None:
    from app.services.application_risk import get_application_patterns

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    repo = Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="acme/api",
        asset_type="repo",
        custom_fields={"application": "payments"},
    )
    findings = [
        CanonicalFinding(
            id=uuid.uuid4(),
            organization_id=org_id,
            asset_id=repo.id,
            status="open",
            cve_ids=[],
            risk_score=55.0,
        )
        for _ in range(2)
    ]
    observations = [
        FindingObservation(
            id=uuid.uuid4(),
            organization_id=org_id,
            canonical_finding_id=finding.id,
            provider="semgrep",
            evidence={"rule_id": "python.lang.security.audit"},
        )
        for finding in findings
    ]

    class _Session:
        async def execute(self, statement):
            return SimpleNamespace(
                all=lambda: [
                    (finding, repo, observation)
                    for finding, observation in zip(findings, observations, strict=False)
                ]
            )

    report = await get_application_patterns(_Session(), principal, "payments")
    assert report.patterns == []


@pytest.mark.asyncio
async def test_repository_aliases_and_inactive_findings_do_not_make_patterns() -> None:
    from app.services.application_risk import get_application_patterns

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.SECURITY_ENGINEER)
    repos = [
        Asset(
            id=uuid.uuid4(),
            organization_id=org_id,
            name=name,
            asset_type="repo",
            custom_fields={"application": "payments"},
        )
        for name in ("Acme/API", "repo:acme/api", "acme/worker")
    ]
    findings = [
        CanonicalFinding(
            id=uuid.uuid4(),
            organization_id=org_id,
            asset_id=repo.id,
            status=status,
            cve_ids=["CVE-2026-1234"],
            risk_score=75.0,
        )
        for repo, status in zip(repos, ("open", "open", "closed"), strict=False)
    ]

    class _Session:
        async def execute(self, statement):
            return SimpleNamespace(
                all=lambda: [(finding, repo, None) for finding, repo in zip(findings, repos, strict=False)]
            )

    report = await get_application_patterns(_Session(), principal, "payments")
    assert report.patterns == []
    assert report.findings_sampled == 2


@pytest.mark.asyncio
async def test_application_risk_routes_delegate_tenant_principal(monkeypatch) -> None:
    from app.api.v1 import applications

    principal = Principal(
        user_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        role=Role.SECURITY_ENGINEER,
    )
    session = object()
    calls = []

    async def _risks(db, actor, *, limit, offset):
        calls.append(("risks", db, actor, limit, offset))
        return "risk-page"

    async def _patterns(db, actor, application):
        calls.append(("patterns", db, actor, application))
        return "patterns-page"

    monkeypatch.setattr(applications.application_risk_service, "list_application_risks", _risks)
    monkeypatch.setattr(
        applications.application_risk_service, "get_application_patterns", _patterns
    )
    assert await applications.list_application_risks(principal, session, 25, 5) == "risk-page"
    assert (
        await applications.get_application_patterns("payments", principal, session)
        == "patterns-page"
    )
    assert calls == [
        ("risks", session, principal, 25, 5),
        ("patterns", session, principal, "payments"),
    ]
    assert any(route.path == "/applications/patterns" for route in applications.router.routes)
