"""Agent read tools use validated filters, tenant SQL, and safe result projections."""

from __future__ import annotations

import datetime as dt
import json
import uuid
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql

from app.core.errors import InvalidModelResponseError
from app.db.enums import Role
from app.services.context import Principal


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one(self):
        return self.value

    def mappings(self):
        return self

    def scalars(self):
        return self

    def all(self):
        return self.value


class _Session:
    def __init__(self):
        self.statements = []

    async def execute(self, statement):
        self.statements.append(statement)
        if len(self.statements) == 1:
            return _Result(1)
        return _Result(
            [
                {
                    "id": uuid.UUID("00000000-0000-0000-0000-000000000007"),
                    "source": "github",
                    "title": "Exposed token sk-secretvalue",
                    "severity": "high",
                    "status": "open",
                    "resource": "acme/api",
                    "seen_at": dt.datetime(2026, 10, 2, tzinfo=dt.UTC),
                }
            ]
        )


class _Gateway:
    def __init__(self, payload):
        self.payload = payload

    async def complete_json(self, *args, **kwargs):
        return kwargs["model_cls"].model_validate(self.payload)


def test_agent_read_plan_rejects_unapproved_tool_and_provider() -> None:
    from app.services.agent_read_tools import ExposureReadPlan

    with pytest.raises(ValidationError):
        ExposureReadPlan.model_validate({"tool": "run_scanner"})
    with pytest.raises(ValidationError):
        ExposureReadPlan.model_validate({"tool": "exposures", "source": "other-tenant"})


@pytest.mark.asyncio
async def test_agent_read_tool_returns_bounded_tenant_rows_and_redacts_secrets() -> None:
    from app.services.agent_read_tools import maybe_read_exposures

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.DEVELOPER)
    session = _Session()
    result = await maybe_read_exposures(
        session,
        principal,
        _Gateway({"tool": "exposures", "source": "github", "severity": "high"}),
        "How many high-severity GitHub alerts are there?",
    )

    assert result is not None
    payload = json.loads(result)
    assert payload["total"] == 1
    assert payload["sample"][0]["source"] == "github"
    assert "sk-secretvalue" not in result
    assert len(session.statements) == 2
    for statement in session.statements:
        compiled = statement.compile(dialect=postgresql.dialect())
        assert org_id in compiled.params.values()
        assert "github" in compiled.params.values()
        assert "high" in compiled.params.values()
    assert 10 in session.statements[1].compile(dialect=postgresql.dialect()).params.values()


@pytest.mark.asyncio
async def test_agent_read_tool_is_not_called_without_finding_permission() -> None:
    from app.services.agent_read_tools import maybe_read_exposures

    class _NoCalls:
        async def execute(self, statement):
            raise AssertionError("database accessed")

        async def complete_json(self, *args, **kwargs):
            raise AssertionError("model asked to plan")

    principal = SimpleNamespace(has=lambda permission: False)
    assert (
        await maybe_read_exposures(_NoCalls(), principal, _NoCalls(), "How many exposures?") is None
    )


@pytest.mark.asyncio
async def test_agent_read_tool_falls_back_when_model_plan_is_invalid() -> None:
    from app.services.agent_read_tools import maybe_read_exposures

    class _Invalid:
        async def complete_json(self, *args, **kwargs):
            raise InvalidModelResponseError("invalid plan")

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    assert (
        await maybe_read_exposures(_Session(), principal, _Invalid(), "What about vulnerabilities?")
        is None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("question", ["How many GitHub alerts?", "List GitHub alerts"])
async def test_explicit_exposure_read_does_not_depend_on_model_planning(question: str) -> None:
    from app.services.agent_read_tools import maybe_read_exposures

    class _NoPlanning:
        async def complete_json(self, *args, **kwargs):
            raise AssertionError("explicit read should not need a model planner")

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    session = _Session()
    result = await maybe_read_exposures(session, principal, _NoPlanning(), question)
    assert result is not None
    payload = json.loads(result)
    assert payload["total"] == 1
    assert payload["source_filter"] == "github"
    assert len(session.statements) == 2


@pytest.mark.asyncio
async def test_multiple_named_sources_do_not_produce_an_unfiltered_total() -> None:
    from app.services.agent_read_tools import maybe_read_exposures

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    session = _Session()
    result = await maybe_read_exposures(
        session,
        principal,
        _Gateway({"tool": "exposures", "source": "github"}),
        "How many GitHub and GitLab alerts?",
    )
    assert result is None
    assert not session.statements


@pytest.mark.asyncio
async def test_multiple_named_severities_do_not_produce_an_unfiltered_total() -> None:
    from app.services.agent_read_tools import maybe_read_exposures

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    session = _Session()
    result = await maybe_read_exposures(
        session,
        principal,
        _Gateway({"tool": "exposures", "severity": "high"}),
        "How many high and critical alerts?",
    )
    assert result is None
    assert not session.statements


@pytest.mark.asyncio
async def test_agent_read_tool_discards_filters_not_asked_for_by_user() -> None:
    from app.services.agent_read_tools import maybe_read_exposures

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    session = _Session()
    result = await maybe_read_exposures(
        session,
        principal,
        _Gateway({"tool": "exposures", "source": "github", "severity": "high"}),
        "How many alerts are there?",
    )
    payload = json.loads(result)
    assert payload["source_filter"] is None
    assert payload["severity_filter"] is None
    for statement in session.statements:
        values = statement.compile(dialect=postgresql.dialect()).params.values()
        assert "github" not in values
        assert "high" not in values


class _CanonicalSession:
    def __init__(self, finding=None, asset_name="api.example.org"):
        self.finding = finding
        self.asset_name = asset_name
        self.statements = []

    async def execute(self, statement):
        self.statements.append(statement)
        if len(self.statements) == 1:
            return _Result(1 if self.finding else 0)
        return _Result([(self.finding, self.asset_name)] if self.finding else [])


@pytest.mark.asyncio
async def test_canonical_lookup_is_tenant_scoped_and_grounded_in_remediation_queue() -> None:
    from app.services.agent_read_tools import maybe_read_canonical_findings

    org_id = uuid.uuid4()
    user_id = uuid.uuid4()
    principal = Principal(user_id=user_id, organization_id=org_id, role=Role.DEVELOPER)
    finding = SimpleNamespace(
        id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        title="Fix sk-secretvalue now",
        severity="critical",
        status="open",
        risk_score=94.0,
        cve_ids=["CVE-2026-1234"],
        assignee_user_id=user_id,
        due_at=dt.datetime(2026, 10, 1, tzinfo=dt.UTC),
        last_seen_at=dt.datetime(2026, 10, 2, tzinfo=dt.UTC),
        remediation_plan="Upgrade the affected package.",
    )
    session = _CanonicalSession(finding)

    result = await maybe_read_canonical_findings(
        session, principal, "Show my overdue critical findings for CVE-2026-1234"
    )

    payload = json.loads(result)
    assert payload["total"] == 1
    assert payload["filters"] == {
        "mine": True,
        "overdue": True,
        "severity": "critical",
        "cve": "CVE-2026-1234",
        "status": "active",
    }
    assert payload["sample"][0]["asset"] == "api.example.org"
    assert payload["sample"][0]["risk_score"] == 94.0
    assert "sk-secretvalue" not in result
    for statement in session.statements:
        params = statement.compile(dialect=postgresql.dialect()).params.values()
        assert org_id in params
        assert user_id in params
        assert "critical" in params
        assert ["CVE-2026-1234"] in params
    assert 10 in session.statements[1].compile(dialect=postgresql.dialect()).params.values()


@pytest.mark.asyncio
async def test_canonical_lookup_skips_unrelated_or_ambiguous_questions() -> None:
    from app.services.agent_read_tools import maybe_read_canonical_findings

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.DEVELOPER)
    session = _CanonicalSession()
    assert (
        await maybe_read_canonical_findings(session, principal, "How do I configure Jira?") is None
    )
    assert (
        await maybe_read_canonical_findings(session, principal, "Show critical and high findings")
        is None
    )
    assert session.statements == []


@pytest.mark.asyncio
async def test_canonical_lookup_respects_finding_permission() -> None:
    from app.services.agent_read_tools import maybe_read_canonical_findings

    class _NoCalls:
        async def execute(self, statement):
            raise AssertionError("database accessed")

    principal = SimpleNamespace(has=lambda permission: False)
    assert await maybe_read_canonical_findings(_NoCalls(), principal, "Show findings") is None


@pytest.mark.asyncio
async def test_specific_finding_lookup_explains_score_and_provider_provenance_without_raw_evidence() -> (
    None
):
    from app.services.agent_read_tools import maybe_read_canonical_findings

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.DEVELOPER)
    finding_id = uuid.uuid4()
    finding = SimpleNamespace(
        id=finding_id,
        asset_id=uuid.uuid4(),
        title="Outdated package",
        severity="high",
        status="open",
        risk_score=81.0,
        cve_ids=["CVE-2026-1234"],
        assignee_user_id=None,
        due_at=None,
        last_seen_at=dt.datetime(2026, 10, 2, tzinfo=dt.UTC),
        remediation_plan="Upgrade",
        risk_factors={
            "components": {"severity": 30.0},
            "inputs": {"cvss_score": 9.1, "in_kev": True},
            "unavailable": ["epss"],
            "raw_secret": "must not leak",
        },
    )
    observation = SimpleNamespace(
        provider="tenable",
        source_status="open",
        last_seen_at=dt.datetime(2026, 10, 2, tzinfo=dt.UTC),
        evidence={"secret": "must not leak"},
    )

    class _DetailSession:
        def __init__(self):
            self.statements = []

        async def execute(self, statement):
            self.statements.append(statement)
            if len(self.statements) == 1:
                return _Result([(finding, "api.example.org")])
            return _Result([observation])

    session = _DetailSession()
    result = await maybe_read_canonical_findings(
        session, principal, f"Why is finding {finding_id} high risk?"
    )
    payload = json.loads(result)
    assert payload["finding"]["risk_factors"]["inputs"]["in_kev"] is True
    assert payload["sources"] == [
        {"provider": "tenable", "status": "open", "last_seen_at": "2026-10-02T00:00:00+00:00"}
    ]
    assert "must not leak" not in result
    for statement in session.statements:
        values = statement.compile(dialect=postgresql.dialect()).params.values()
        assert org_id in values
        assert finding_id in values
