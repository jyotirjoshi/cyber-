"""Cross-provider correlation candidates require both repository and CVE evidence."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from app.db.enums import Role
from app.db.models.external_alert import ExternalSecurityAlert
from app.services.context import Principal


class _Result:
    def __init__(self, value: Any) -> None:
        self.value = value

    def scalar_one_or_none(self) -> Any:
        return self.value

    def scalars(self) -> _Result:
        return self

    def all(self) -> Any:
        return self.value


class _Session:
    def __init__(self, alert: ExternalSecurityAlert) -> None:
        self.alert = alert
        self.statements: list[Any] = []

    async def execute(self, statement: Any) -> _Result:
        self.statements.append(statement)
        return _Result(self.alert if len(self.statements) == 1 else [])


@pytest.mark.asyncio
async def test_related_alerts_require_same_repo_and_cve_within_tenant() -> None:
    from app.services.external_alert import related_external_alerts_for_alert

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.VIEWER)
    alert = ExternalSecurityAlert(
        id=uuid.uuid4(), organization_id=org_id, provider="github",
        external_id="dependabot:acme/api:1", category="dependabot", title="Vulnerable library",
        severity="high", status="open", resource="acme/api",
        cve_ids=["CVE-2026-1234"], evidence={}, raw_payload={},
    )
    session = _Session(alert)

    assert await related_external_alerts_for_alert(session, principal, alert.id) == []
    assert len(session.statements) == 2
    compiled = session.statements[1].compile(dialect=postgresql.dialect())
    sql = str(compiled)
    assert org_id in compiled.params.values()
    assert "external_security_alerts.organization_id =" in sql
    assert "external_security_alerts.provider !=" in sql
    assert "external_security_alerts.resource =" in sql
    assert "external_security_alerts.evidence" in sql
    assert "external_security_alerts.cve_ids @>" in sql
    assert "acme/api" in compiled.params.values()
    assert ["CVE-2026-1234"] in compiled.params.values()
    assert 20 in compiled.params.values()


@pytest.mark.asyncio
async def test_related_alerts_do_not_guess_repository_from_wazuh_or_missing_cve() -> None:
    from app.services.external_alert import related_external_alerts_for_alert

    org_id = uuid.uuid4()
    principal = Principal(user_id=uuid.uuid4(), organization_id=org_id, role=Role.VIEWER)
    alert = ExternalSecurityAlert(
        id=uuid.uuid4(), organization_id=org_id, provider="wazuh",
        external_id="event:1", category="rule", title="Server event",
        severity="medium", status="open", resource="acme/api",
        cve_ids=["CVE-2026-1234"], evidence={}, raw_payload={},
    )
    session = _Session(alert)
    assert await related_external_alerts_for_alert(session, principal, alert.id) == []
    assert len(session.statements) == 1


def test_related_alerts_endpoint_exposes_safe_projection() -> None:
    from fastapi import FastAPI

    from app.api.v1.external_alerts import router

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    path = app.openapi()["paths"]["/api/v1/external-alerts/{alert_id}/related-alerts"]["get"]
    assert "200" in path["responses"]
