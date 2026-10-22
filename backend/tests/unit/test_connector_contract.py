from __future__ import annotations

import datetime as dt


def test_connector_contract_requires_live_auth_and_assurance_checks() -> None:
    from app.db.enums import IntegrationKind
    from app.schemas.integration import (
        ConnectorAssuranceCheckOut,
        ConnectorCertificationOut,
        IntegrationTestOut,
    )
    from app.services.integration import connector_contract_result

    now = dt.datetime(2026, 10, 22, tzinfo=dt.UTC)
    result = connector_contract_result(
        IntegrationTestOut(
            kind=IntegrationKind.WAZUH,
            healthy=True,
            detail="Reachable and authenticated.",
            latency_ms=42,
            checked_at=now,
        ),
        ConnectorCertificationOut(
            kind=IntegrationKind.WAZUH,
            name="Wazuh",
            grade="certified",
            score=100,
            capabilities=["connectivity_test", "finding_ingestion", "scheduled_sync"],
            checks=[
                ConnectorAssuranceCheckOut(key="credentials", passed=True, weight=20, detail="configured"),
                ConnectorAssuranceCheckOut(key="coverage", passed=True, weight=30, detail="current"),
            ],
            blockers=[],
            checked_at=now,
        ),
    )

    assert result.passed is True
    assert result.score == 100
    assert {check.key for check in result.checks} >= {"live_auth", "credentials", "coverage"}


def test_connector_contract_route_is_mounted() -> None:
    from app.api.v1.router import api_router

    assert "/integrations/{kind}/contract-test" in {route.path for route in api_router.routes}
