"""Persistence and wire-contract guarantees for the assurance runtime."""

from __future__ import annotations

import importlib
import uuid

import pytest
from pydantic import ValidationError

from app.db import models as _models  # noqa: F401
from app.db.base import Base

EXPECTED_TABLES = {
    "enforcement_transactions",
    "ai_interaction_receipts",
    "ai_tool_manifests",
    "ai_access_edges",
    "agent_run_assurance",
    "validation_recipes",
    "data_security_assessments",
    "threat_response_actions",
    "risk_simulation_trials",
    "compliance_control_inheritances",
    "compliance_evidence_requests",
    "compliance_export_packages",
    "agent_evaluation_suites",
    "agent_evaluation_runs",
}


def test_assurance_runtime_registers_every_persistent_domain() -> None:
    """Removing a domain table would make one requested capability non-durable."""

    assert set(Base.metadata.tables) >= EXPECTED_TABLES


def test_assurance_tables_cannot_store_raw_sensitive_payloads() -> None:
    """Adding a raw prompt/body/secret column would violate the privacy boundary."""

    forbidden = {
        "prompt",
        "output",
        "raw_content",
        "raw_payload",
        "request_body",
        "response_body",
        "credential",
        "secret",
    }
    offenders = {
        f"{table_name}.{column.name}"
        for table_name in EXPECTED_TABLES
        for column in Base.metadata.tables[table_name].columns
        if column.name.casefold() in forbidden
    }
    assert not offenders


def test_assurance_contracts_forbid_undeclared_fields() -> None:
    """Unknown fields cannot smuggle provider payloads into durable metadata."""

    schemas = importlib.import_module("app.schemas.assurance")
    with pytest.raises(ValidationError):
        schemas.EnforcementTransactionCreateIn.model_validate(
            {
                "recommendation_id": str(uuid.uuid4()),
                "observation_seconds": 300,
                "raw_payload": {"token": "must-not-be-accepted"},
            }
        )


def test_tool_manifest_requires_a_closed_object_schema() -> None:
    """An open argument schema would let an agent add unreviewed tool arguments."""

    schemas = importlib.import_module("app.schemas.assurance")
    with pytest.raises(ValidationError, match="additionalProperties"):
        schemas.AIToolManifestCreateIn.model_validate(
            {
                "server_key": "mcp://security",
                "tool_name": "isolate_endpoint",
                "version": "1.0.0",
                "argument_schema": {
                    "type": "object",
                    "properties": {"endpoint_id": {"type": "string"}},
                },
                "permissions": ["endpoint:isolate"],
            }
        )


def test_risk_contract_rejects_unordered_frequency_and_loss_ranges() -> None:
    """Inverted ranges would produce precise-looking but meaningless loss output."""

    schemas = importlib.import_module("app.schemas.assurance")
    with pytest.raises(ValidationError, match="ordered"):
        schemas.MonteCarloSimulationCreateIn.model_validate(
            {
                "simulation_id": str(uuid.uuid4()),
                "iterations": 10_000,
                "seed": 42,
                "frequency_min": "0.4",
                "frequency_likely": "0.2",
                "frequency_max": "0.8",
                "primary_loss_min": "100",
                "primary_loss_likely": "200",
                "primary_loss_max": "300",
                "secondary_loss_min": "0",
                "secondary_loss_likely": "0",
                "secondary_loss_max": "0",
                "control_effectiveness_min": "0.1",
                "control_effectiveness_likely": "0.2",
                "control_effectiveness_max": "0.3",
                "assumptions_version": 1,
            }
        )


def test_response_action_persists_exact_scope_execution_evidence() -> None:
    columns = Base.metadata.tables["threat_response_actions"].columns
    assert {
        "provider",
        "requested_action",
        "approval_scope_digest",
        "approved_by_id",
        "approved_at",
        "rollback_receipt",
        "failure_code",
    } <= set(columns.keys())
