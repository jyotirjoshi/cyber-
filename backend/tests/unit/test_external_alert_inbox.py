"""Tenant-scoped external alert inbox contracts."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from app.core.errors import TenantIsolationError
from app.db.enums import Role
from app.db.models.external_alert import ExternalSecurityAlert
from app.schemas.common import PaginationParams
from app.services.context import Principal
from app.services.external_alert import get_external_alert, list_external_alerts


def test_external_alert_provider_filter_includes_sonarqube() -> None:
    """A working connector must be selectable through the public inbox API."""
    from fastapi import FastAPI

    from app.api.v1.external_alerts import router

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    parameters = app.openapi()["paths"]["/api/v1/external-alerts"]["get"]["parameters"]
    provider = next(item for item in parameters if item["name"] == "provider")
    assert "sonarqube" in str(provider["schema"])


class _Result:
    def __init__(self, value: Any) -> None:
        self.value = value

    def scalar_one(self) -> Any:
        return self.value

    def scalars(self) -> _Result:
        return self

    def all(self) -> Any:
        return self.value


class _Session:
    def __init__(self, rows: list[ExternalSecurityAlert]) -> None:
        self.rows = rows
        self.statements: list[Any] = []

    async def execute(self, statement: Any) -> _Result:
        self.statements.append(statement)
        return _Result(len(self.rows) if len(self.statements) == 1 else self.rows)


class _LookupResult:
    def __init__(self, row: ExternalSecurityAlert | None) -> None:
        self.row = row

    def scalar_one_or_none(self) -> ExternalSecurityAlert | None:
        return self.row


class _LookupSession:
    def __init__(self, row: ExternalSecurityAlert | None) -> None:
        self.row = row
        self.statement: Any = None

    async def execute(self, statement: Any) -> _LookupResult:
        self.statement = statement
        return _LookupResult(self.row)


@pytest.mark.asyncio
async def test_external_alert_inbox_filters_and_paginates_with_tenant_on_both_queries() -> None:
    """Removing any org predicate or filter from count/list could leak or miscount alerts."""
    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.VIEWER)
    row = ExternalSecurityAlert(
        id=uuid.uuid4(), organization_id=org_id, provider="gitlab", external_id="a",
        category="sast", title="SQL injection", severity="high", status="open",
        cve_ids=["CVE-2026-1234"], evidence={"token": "secret"},
        raw_payload={"secret": "never-return"},
    )
    session = _Session([row])

    rows, total = await list_external_alerts(
        session, principal, provider="gitlab", severity="high", status="open",
        triage_status="new", q="SQL", pagination=PaginationParams(limit=10, offset=20),
    )

    assert total == 1
    assert rows == [row]
    assert len(session.statements) == 2
    sql = [str(s.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})) for s in session.statements]
    for statement in sql:
        assert f"organization_id = '{org_id}'" in statement
        assert "provider = 'gitlab'" in statement
        assert "severity = 'high'" in statement
        assert "status = 'open'" in statement
        assert "triage_status = 'new'" in statement
        assert "external_security_alerts.title ILIKE" in statement
    assert "LIMIT 10 OFFSET 20" in sql[1]


def test_external_alert_public_projection_excludes_sensitive_payloads() -> None:
    """Adding raw payload or evidence to the browser response leaks provider secrets."""
    from app.schemas.external_alert import ExternalAlertOut

    row = ExternalSecurityAlert(
        id=uuid.uuid4(), organization_id=uuid.uuid4(), provider="github",
        external_id="secret-scanning:7", category="secret_scanning",
        title="Exposed token", severity="critical", status="open",
        triage_status="new", triage_version=0,
        missing_sync_count=0,
        cve_ids=[], evidence={"token": "secret"}, raw_payload={"secret": "never-return"},
    )
    payload = ExternalAlertOut.model_validate(row).model_dump(mode="json")

    assert payload["title"] == "Exposed token"
    assert "evidence" not in payload
    assert "raw_payload" not in payload
    assert "never-return" not in str(payload)


def test_external_alert_projection_exposes_freshness_without_sensitive_evidence() -> None:
    from app.schemas.external_alert import ExternalAlertOut

    row = ExternalSecurityAlert(
        id=uuid.uuid4(), organization_id=uuid.uuid4(), provider="github",
        external_id="dependabot:acme/api:7", category="dependabot", title="Vulnerable package",
        severity="high", status="open", triage_status="new", triage_version=0,
        missing_sync_count=2, cve_ids=[], evidence={"token": "hidden"}, raw_payload={},
    )
    payload = ExternalAlertOut.model_validate(row).model_dump(mode="json")
    assert payload["missing_sync_count"] == 2
    assert "evidence" not in payload


@pytest.mark.asyncio
async def test_external_alert_detail_lookup_is_tenant_scoped() -> None:
    """A bare id lookup would reveal another organization's provider alert."""
    org_id = uuid.uuid4()
    alert_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.VIEWER)
    row = ExternalSecurityAlert(
        id=alert_id, organization_id=org_id, provider="gitlab", external_id="finding:1",
        category="sast", title="Injection", severity="high", status="open",
        cve_ids=[], evidence={}, raw_payload={},
    )
    session = _LookupSession(row)

    assert await get_external_alert(session, principal, alert_id) is row
    sql = str(session.statement.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
    assert f"organization_id = '{org_id}'" in sql
    assert f"external_security_alerts.id = '{alert_id}'" in sql

    with pytest.raises(TenantIsolationError):
        await get_external_alert(_LookupSession(None), principal, alert_id)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://gitlab.example.test/acme/app/-/security/vulnerability/1", "https://gitlab.example.test/acme/app/-/security/vulnerability/1"),
        ("javascript:alert(1)", None),
        ("https://user:secret@gitlab.example.test/alert", None),
        ("https://gitlab.example.test\\@evil.example/alert", None),
    ],
)
def test_external_alert_detail_only_exposes_safe_source_links(url: str, expected: str | None) -> None:
    """A provider-controlled URL must not become an executable or credential-bearing href."""
    from app.schemas.external_alert import ExternalAlertDetailOut

    row = ExternalSecurityAlert(
        id=uuid.uuid4(), organization_id=uuid.uuid4(), provider="gitlab",
        external_id="finding:1", category="sast", title="Injection", severity="high",
        status="open", triage_status="new", triage_version=0,
        missing_sync_count=0,
        cve_ids=[], source_url=url, evidence={}, raw_payload={},
    )

    payload = ExternalAlertDetailOut.model_validate(row).model_dump(mode="json")
    assert payload["source_url"] == expected
    assert payload["external_id"] == "finding:1"
    assert "raw_payload" not in payload
    assert "evidence" not in payload
