"""Canonical-only exposures can own deduplicated Jira tickets."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from app.core.config import Settings
from app.db.enums import Role, Severity
from app.db.models.finding import TicketLink
from app.services.context import Principal


def test_ticket_link_has_exactly_one_native_or_canonical_target() -> None:
    table = TicketLink.__table__
    assert table.c.finding_id.nullable
    assert table.c.canonical_finding_id.nullable
    checks = " ".join(str(item.sqltext) for item in table.constraints if hasattr(item, "sqltext"))
    assert "finding_id IS NOT NULL" in checks
    assert "canonical_finding_id IS NOT NULL" in checks
    assert any(
        {column.name for column in constraint.columns} == {"canonical_finding_id", "provider"}
        for constraint in table.constraints
        if getattr(constraint, "__visit_name__", None) == "unique_constraint"
    )


def test_canonical_ticket_description_preserves_source_and_marks_ai_plan() -> None:
    from app.services.ticket import build_canonical_description

    finding = SimpleNamespace(
        id=uuid.uuid4(),
        title="Vulnerable package",
        severity="high",
        risk_score=81.5,
        cve_ids=["CVE-2026-1234"],
        remediation_plan="Upgrade dependency and rescan.",
    )
    observation = SimpleNamespace(
        provider="snyk", external_id="issue-42", source_status="open", source_url=None
    )
    body = build_canonical_description(
        finding,
        asset_name="api.example.org",
        observations=[observation],
        settings=Settings(),
    )
    assert "api.example.org" in body
    assert "CVE-2026-1234" in body
    assert "snyk" in body
    assert "issue-42" in body
    assert "AI-generated" in body
    assert f"/findings/canonical/{finding.id}" in body
    without_plan = build_canonical_description(
        finding,
        asset_name="api.example.org",
        observations=[observation],
        settings=Settings(),
        include_remediation=False,
    )
    assert "Upgrade dependency" not in without_plan


@pytest.mark.asyncio
async def test_canonical_only_finding_creates_one_jira_link_with_stable_remote_identity(
    monkeypatch,
) -> None:
    from app.integrations.jira import JiraIssue
    from app.services import ticket

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    finding_id = uuid.uuid4()
    finding = SimpleNamespace(
        id=finding_id,
        organization_id=principal.organization_id,
        asset_id=uuid.uuid4(),
        title="Vulnerable dependency",
        severity="high",
        status="open",
        risk_score=88.0,
        cve_ids=["CVE-2026-1234"],
        remediation_plan="Upgrade and verify the dependency.",
    )
    statements = []
    added = []
    remote_calls = []

    class _Result:
        def __init__(self, value):
            self.value = value

        def scalar_one_or_none(self):
            return self.value

        def scalars(self):
            return self

        def all(self):
            return self.value

    class _Session:
        async def execute(self, statement):
            statements.append(statement)
            values = [None, [], None, "api.example.org", []]
            return _Result(values[len(statements) - 1])

        def add(self, value):
            added.append(value)

        async def flush(self):
            return None

    async def get_finding(self, finding_key):
        assert finding_key == finding_id
        return finding

    async def scoped(*args, **kwargs):
        return Settings()

    async def audit(*args, **kwargs):
        return None

    class _Jira:
        def __init__(self, *args):
            pass

        async def create_issue(self, **kwargs):
            remote_calls.append(kwargs)
            return JiraIssue(
                key="SEC-42",
                id="42",
                url="https://jira.example/browse/SEC-42",
                summary="Vulnerable dependency",
                status="Open",
            )

        async def aclose(self):
            return None

    monkeypatch.setattr(ticket.TenantRepository, "get_or_404", get_finding)
    monkeypatch.setattr(ticket, "resolve_settings", scoped)
    monkeypatch.setattr(ticket, "JiraClient", _Jira)
    monkeypatch.setattr(ticket.audit_service, "record", audit)
    link = await ticket.create_canonical_ticket(
        _Session(),
        principal,
        finding_id,
        settings=Settings(),
        by_agent=True,
        project_key="P" * 50,
        issue_type="T" * 70,
    )
    assert link is added[0]
    assert link.canonical_finding_id == finding_id
    assert link.finding_id is None
    assert link.created_by_agent
    assert link.project_key == "P" * 40
    assert link.issue_type == "T" * 60
    assert remote_calls[0]["finding_id"] == str(finding_id)
    assert "CVE-2026-1234" in remote_calls[0]["description"]
    assert len(remote_calls) == 1
    assert principal.organization_id in statements[0].compile().params.values()


@pytest.mark.asyncio
async def test_canonical_ticket_list_includes_direct_and_native_links_without_crossing_tenants() -> (
    None
):
    from app.services.ticket import list_canonical_tickets

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    finding_id = uuid.uuid4()
    direct = SimpleNamespace(id=uuid.uuid4())

    class _Session:
        async def execute(self, statement):
            self.statement = statement
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [direct]))

    session = _Session()
    assert await list_canonical_tickets(session, principal, finding_id) == [direct]
    compiled = session.statement.compile(dialect=postgresql.dialect())
    assert principal.organization_id in compiled.params.values()
    assert finding_id in compiled.params.values()
    assert "ticket_links.canonical_finding_id" in str(compiled)
    assert "finding_observations" in str(compiled)


@pytest.mark.asyncio
async def test_native_ticket_lookup_reuses_link_on_same_canonical_exposure() -> None:
    from app.services.ticket import find_ticket

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    native_id = uuid.uuid4()
    canonical_link = SimpleNamespace(id=uuid.uuid4(), external_key="SEC-42")
    statements = []

    class _Session:
        async def execute(self, statement):
            statements.append(statement)
            return SimpleNamespace(
                scalar_one_or_none=lambda: None if len(statements) == 1 else canonical_link
            )

    assert await find_ticket(_Session(), principal, native_id) is canonical_link
    compiled = statements[1].compile(dialect=postgresql.dialect())
    assert principal.organization_id in compiled.params.values()
    assert native_id in compiled.params.values()
    assert "finding_observations" in str(compiled)


@pytest.mark.asyncio
async def test_canonical_ticket_creation_reuses_ticket_on_any_native_observation(
    monkeypatch,
) -> None:
    from app.services import ticket

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    canonical_id = uuid.uuid4()
    finding = SimpleNamespace(id=canonical_id, status="open")
    older_native_link = SimpleNamespace(id=uuid.uuid4(), provider="jira", external_key="SEC-12")
    statements = []

    class _Result:
        def __init__(self, value):
            self.value = value

        def scalar_one_or_none(self):
            return self.value

        def scalars(self):
            return self

        def all(self):
            return self.value

    class _Session:
        async def execute(self, statement):
            statements.append(statement)
            return _Result(None if len(statements) == 1 else [older_native_link])

    async def get_finding(self, finding_key):
        return finding

    async def no_remote(*args, **kwargs):
        raise AssertionError("existing native ticket must be reused")

    monkeypatch.setattr(ticket.TenantRepository, "get_or_404", get_finding)
    monkeypatch.setattr(ticket, "resolve_settings", no_remote)
    assert (
        await ticket.create_canonical_ticket(
            _Session(),
            principal,
            canonical_id,
            settings=Settings(),
        )
        is older_native_link
    )


@pytest.mark.asyncio
async def test_assessment_ticket_candidates_exclude_already_ticketed_canonical_exposures() -> None:
    from app.services.ticket import ticket_candidates

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)

    class _Session:
        async def execute(self, statement):
            self.statement = statement
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: []))

    session = _Session()
    assert (
        await ticket_candidates(
            session, principal, uuid.uuid4(), organization_policy_floor=Severity.HIGH
        )
        == []
    )
    sql = str(session.statement.compile(dialect=postgresql.dialect()))
    assert "finding_observations" in sql
    assert "ticket_links.canonical_finding_id" in sql
