"""Read-only possible matches between provider alerts and assessment findings."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from app.db.enums import Role
from app.db.models.external_alert import ExternalSecurityAlert
from app.db.models.finding import Finding
from app.services.context import Principal


class _Result:
    def __init__(self, value: Any) -> None:
        self.value = value

    def scalar_one_or_none(self) -> Any:
        return self.value

    def scalars(self) -> _Result:
        return self

    def all(self) -> list[Finding]:
        return self.value


class _Session:
    def __init__(self, alert: ExternalSecurityAlert, findings: list[Finding]) -> None:
        self.alert = alert
        self.findings = findings
        self.statements: list[Any] = []

    async def execute(self, statement: Any) -> _Result:
        self.statements.append(statement)
        return _Result(self.alert if len(self.statements) == 1 else self.findings)


@pytest.mark.asyncio
async def test_related_findings_match_cve_inside_one_tenant_with_a_bounded_query() -> None:
    """A CVE-only search must not scan other tenants or return unbounded false positives."""
    from app.services.external_alert import related_findings_for_alert

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.VIEWER)
    alert = ExternalSecurityAlert(
        id=uuid.uuid4(), organization_id=org_id, provider="gitlab",
        external_id="alert:1", category="sast", title="Dependency issue",
        severity="high", status="open", triage_status="new", triage_version=0,
        cve_ids=["CVE-2026-1234", "CVE-2026-5678"], evidence={}, raw_payload={},
    )
    finding = Finding(
        id=uuid.uuid4(), organization_id=org_id, defectdojo_finding_id=42,
        title="Vulnerable component", severity="high", status="active",
        cve_ids=["CVE-2026-1234"], is_duplicate=False, is_false_positive=False,
    )
    session = _Session(alert, [finding])

    assert await related_findings_for_alert(session, principal, alert.id) == [finding]
    assert len(session.statements) == 2
    compiled = session.statements[1].compile(dialect=postgresql.dialect())
    sql = str(compiled)
    assert "findings.organization_id =" in sql
    assert org_id in compiled.params.values()
    assert sql.count("findings.cve_ids @>") == 2
    assert ["CVE-2026-1234"] in compiled.params.values()
    assert ["CVE-2026-5678"] in compiled.params.values()
    assert "findings.is_false_positive IS false" in sql
    assert "findings.is_duplicate IS false" in sql
    assert 20 in compiled.params.values()


@pytest.mark.asyncio
async def test_related_findings_skip_database_search_for_alert_without_cves() -> None:
    """A Wazuh rule with no CVE must not suggest unrelated findings."""
    from app.services.external_alert import related_findings_for_alert

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.VIEWER)
    alert = ExternalSecurityAlert(
        id=uuid.uuid4(), organization_id=org_id, provider="wazuh",
        external_id="alert:2", category="rule", title="Authentication event",
        severity="medium", status="open", triage_status="new", triage_version=0,
        cve_ids=[], evidence={}, raw_payload={},
    )
    session = _Session(alert, [])

    assert await related_findings_for_alert(session, principal, alert.id) == []
    assert len(session.statements) == 1
