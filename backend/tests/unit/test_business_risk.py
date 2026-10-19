from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from app.db.models.business_risk import BusinessRiskScenario
from app.schemas.business_risk import BusinessRiskScenarioIn
from app.services.business_risk import service_slug


def test_business_service_slug_is_stable_and_url_safe() -> None:
    assert service_slug(" Payments & Checkout ") == "payments-checkout"
    with pytest.raises(ValueError):
        service_slug("---")


def test_financial_scenario_requires_an_ordered_loss_range() -> None:
    with pytest.raises(ValidationError):
        BusinessRiskScenarioIn(
            name="Checkout outage",
            threat_event="Ransomware",
            annual_probability=0.2,
            loss_min_usd=100_000,
            loss_likely_usd=50_000,
            loss_max_usd=500_000,
            rationale="Historical incident and threat intelligence evidence.",
        )


def test_scenario_annualized_loss_uses_probability_and_triangular_mean() -> None:
    scenario = BusinessRiskScenario(
        organization_id=uuid.uuid4(),
        business_service_id=uuid.uuid4(),
        name="Checkout outage",
        threat_event="Ransomware",
        annual_probability=0.25,
        loss_min_usd=100_000,
        loss_likely_usd=200_000,
        loss_max_usd=600_000,
        rationale="Evidence-backed estimate",
        evidence={},
        status="active",
    )
    assert scenario.annualized_loss_expectancy_usd == 75_000


def test_business_risk_api_is_mounted() -> None:
    from app.api.v1.router import api_router

    paths = {route.path for route in api_router.routes}
    assert "/business-risk/services" in paths
    assert "/business-risk/services/{service_id}/exposure" in paths


def test_business_risk_models_are_registered_for_migrations() -> None:
    from app.db.base import Base

    assert "business_services" in Base.metadata.tables
    assert "asset_business_services" in Base.metadata.tables
    assert "business_risk_scenarios" in Base.metadata.tables
