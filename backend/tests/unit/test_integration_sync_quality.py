from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

from app.db.enums import IntegrationKind


def test_sync_quality_reports_current_stale_failed_and_never_states() -> None:
    from app.services.integration import integration_sync_quality

    now = dt.datetime(2026, 10, 18, 12, tzinfo=dt.UTC)
    base = {
        "is_enabled": True,
        "sync_interval_minutes": 60,
        "last_sync_status": "succeeded",
        "sync_failure_count": 0,
        "status": "configured",
    }

    current = integration_sync_quality(
        SimpleNamespace(**base, last_sync_at=now - dt.timedelta(minutes=30)), now=now
    )
    stale = integration_sync_quality(
        SimpleNamespace(**base, last_sync_at=now - dt.timedelta(hours=4)), now=now
    )
    failed = integration_sync_quality(
        SimpleNamespace(
            **{**base, "last_sync_status": "failed", "sync_failure_count": 3},
            last_sync_at=now - dt.timedelta(minutes=10),
        ),
        now=now,
        circuit_open=True,
    )
    never = integration_sync_quality(SimpleNamespace(**base, last_sync_at=None), now=now)

    assert current.coverage_state == "current" and current.confidence > 0.8
    assert stale.coverage_state == "stale" and stale.confidence < current.confidence
    assert failed.coverage_state == "blocked" and failed.confidence < 0.25
    assert never.coverage_state == "never_synced" and never.confidence == 0
    assert current.freshness_seconds == 1800


def test_connector_assurance_certifies_only_fresh_operational_connectors() -> None:
    from app.services.integration import SyncQuality, certify_connector

    now = dt.datetime(2026, 10, 22, 12, tzinfo=dt.UTC)
    result = certify_connector(
        kind=IntegrationKind.GITHUB,
        name="GitHub",
        is_enabled=True,
        configured_credentials={"api_token"},
        required_credentials={"api_token"},
        last_verified_at=now - dt.timedelta(hours=2),
        status="configured",
        quality=SyncQuality(600, "current", 0.95, "Current"),
        circuit_open=False,
        now=now,
    )

    assert result.grade == "certified"
    assert result.score == 100
    assert "finding_ingestion" in result.capabilities
    assert "webhook_ingestion" in result.capabilities
    assert result.blockers == []


def test_connector_assurance_exposes_missing_credentials_and_stale_sync() -> None:
    from app.services.integration import SyncQuality, certify_connector

    now = dt.datetime(2026, 10, 22, 12, tzinfo=dt.UTC)
    result = certify_connector(
        kind=IntegrationKind.TENABLE,
        name="Tenable VM",
        is_enabled=True,
        configured_credentials={"access_key"},
        required_credentials={"access_key", "secret_key"},
        last_verified_at=now - dt.timedelta(days=30),
        status="error",
        quality=SyncQuality(20_000, "stale", 0.2, "Stale"),
        circuit_open=True,
        now=now,
    )

    assert result.grade == "failed"
    assert result.score < 40
    assert "Missing required credentials: secret_key." in result.blockers
    assert "Provider circuit breaker is open." in result.blockers


def test_integration_health_schema_keeps_sync_confidence_fields() -> None:
    from app.schemas.integration import IntegrationHealthOut

    row = IntegrationHealthOut(
        kind=IntegrationKind.GITHUB,
        name="GitHub",
        status="configured",
        is_enabled=True,
        freshness_seconds=90,
        coverage_state="current",
        sync_confidence=0.98,
        coverage_reason="Fresh sync",
    )

    assert row.model_dump()["sync_confidence"] == 0.98
    assert row.model_dump()["coverage_state"] == "current"


def test_connector_certification_route_is_mounted() -> None:
    from app.api.v1.router import api_router

    assert "/integrations/certifications" in {route.path for route in api_router.routes}
