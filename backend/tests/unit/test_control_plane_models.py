from __future__ import annotations

import importlib.util
from decimal import Decimal

import pytest
from pydantic import ValidationError
from sqlalchemy import CheckConstraint, UniqueConstraint


def test_control_plane_module_exists() -> None:
    assert importlib.util.find_spec("app.db.models.control_plane") is not None


def test_control_plane_models_are_registered_with_expected_tables() -> None:
    from app.db.base import Base

    # Importing the model package is the registration boundary used by Alembic.
    import app.db.models  # noqa: F401

    expected = {
        "security_resources",
        "security_resource_observations",
        "security_policies",
        "security_policy_evaluations",
        "security_recommendations",
        "security_events",
        "security_threat_stories",
        "security_canaries",
        "security_canary_interactions",
        "security_risk_simulations",
    }

    assert expected <= set(Base.metadata.tables)


def test_resource_identity_and_event_replay_are_database_unique() -> None:
    from app.db.models.control_plane import SecurityEvent, SecurityResource

    resource_uniques = {
        tuple(constraint.columns.keys())
        for constraint in SecurityResource.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    event_uniques = {
        tuple(constraint.columns.keys())
        for constraint in SecurityEvent.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }

    assert ("organization_id", "resource_key") in resource_uniques
    assert ("organization_id", "event_key") in event_uniques


def test_policy_and_resource_vocabularies_are_database_enforced() -> None:
    from app.db.models.control_plane import SecurityPolicy, SecurityResource

    policy_checks = " ".join(
        str(constraint.sqltext)
        for constraint in SecurityPolicy.__table__.constraints
        if isinstance(constraint, CheckConstraint)
    )
    resource_checks = " ".join(
        str(constraint.sqltext)
        for constraint in SecurityResource.__table__.constraints
        if isinstance(constraint, CheckConstraint)
    )

    assert "ai_gateway" in policy_checks
    assert "secure_web_gateway" in policy_checks
    assert "ai_agent" in resource_checks
    assert "data_store" in resource_checks


def test_risk_simulation_contract_validates_probability_effectiveness_and_losses() -> None:
    from app.schemas.control_plane import RiskSimulationCreateIn

    valid = {
        "name": "Customer portal credential compromise",
        "annual_probability": Decimal("0.2"),
        "loss_min": Decimal("10000"),
        "loss_likely": Decimal("40000"),
        "loss_max": Decimal("200000"),
        "control_effectiveness": Decimal("0.65"),
    }
    assert RiskSimulationCreateIn(**valid).loss_likely == Decimal("40000")

    for changes in (
        {"annual_probability": Decimal("1.1")},
        {"control_effectiveness": Decimal("-0.1")},
        {"loss_min": Decimal("50000"), "loss_likely": Decimal("40000")},
        {"loss_likely": Decimal("250000")},
    ):
        with pytest.raises(ValidationError):
            RiskSimulationCreateIn(**(valid | changes))


def test_risk_simulation_calculates_inherent_and_residual_annual_loss() -> None:
    from app.db.models.control_plane import SecurityRiskSimulation

    simulation = SecurityRiskSimulation(
        annual_probability=Decimal("0.25"),
        loss_min=Decimal("10000"),
        loss_likely=Decimal("50000"),
        loss_max=Decimal("200000"),
        control_effectiveness=Decimal("0.60"),
    )

    assert simulation.expected_loss == Decimal("86666.67")
    assert simulation.inherent_annual_loss == Decimal("21666.67")
    assert simulation.residual_annual_loss == Decimal("8666.67")


def test_ai_gateway_contract_forbids_raw_persistence_fields() -> None:
    from app.schemas.control_plane import AIGatewayEvaluateIn

    safe = AIGatewayEvaluateIn(
        direction="prompt",
        content="Summarize the approved runbook",
        agent_key="agent:triage",
        tool_keys=["tool:findings.read"],
    )
    assert safe.direction == "prompt"

    with pytest.raises(ValidationError):
        AIGatewayEvaluateIn(
            direction="prompt",
            content="do not persist this",
            agent_key="agent:triage",
            raw_content="forbidden",
        )
