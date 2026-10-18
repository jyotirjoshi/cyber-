"""Deterministic exposure graph contracts: models choose words, never graph topology."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest


def _asset(
    name: str,
    *,
    internet: bool = False,
    criticality: str = "normal",
    groups: list[str] | None = None,
    controls: list[str] | None = None,
    financial_impact_usd: int | None = None,
):
    custom_fields = {"controls": controls or []}
    if financial_impact_usd is not None:
        custom_fields["financial_impact_usd"] = financial_impact_usd
    return SimpleNamespace(
        id=uuid.uuid4(),
        name=name,
        asset_type="host",
        internet_exposed=internet,
        criticality=criticality,
        environment="production",
        groups=groups or [],
        custom_fields=custom_fields,
    )


def test_deterministic_graph_uses_only_persisted_findings_and_topology() -> None:
    from app.services.attack_path import build_deterministic_attack_paths

    edge, app, database = (
        _asset("edge.example", internet=True),
        _asset("payments-api", groups=["Payments"]),
        _asset(
            "payments-db",
            criticality="critical",
            groups=["Payments"],
            financial_impact_usd=750_000,
        ),
    )
    disconnected = _asset("hr-db", criticality="critical", groups=["HR"])
    finding = SimpleNamespace(
        id=uuid.uuid4(),
        asset_id=edge.id,
        title="Remote code execution",
        severity="critical",
        risk_score=96.0,
        cve_ids=["CVE-2026-1000"],
        cwe="CWE-94",
    )
    relationships = [
        SimpleNamespace(
            id=uuid.uuid4(), source_asset_id=edge.id, target_asset_id=app.id,
            relationship_type="connects_to", evidence={"source": "network_policy"},
        ),
        SimpleNamespace(
            id=uuid.uuid4(), source_asset_id=app.id, target_asset_id=database.id,
            relationship_type="depends_on", evidence={"source": "cmdb"},
        ),
    ]

    paths = build_deterministic_attack_paths(
        [finding], [edge, app, database, disconnected], relationships
    )

    assert len(paths) == 1
    path = paths[0]
    assert path.entry_finding_id == str(finding.id)
    assert path.asset_ids == [str(edge.id), str(app.id), str(database.id)]
    assert str(disconnected.id) not in path.asset_ids
    assert path.business_services == ["Payments"]
    assert path.blast_radius_score > 0
    assert path.financial_impact == {"currency": "USD", "maximum": 750_000, "source": "asset"}
    assert {step.finding_id for step in path.steps if step.finding_id} == {str(finding.id)}
    assert {step.relationship_id for step in path.steps if step.relationship_id} == {
        str(relationships[0].id), str(relationships[1].id)
    }


def test_compensating_controls_reduce_likelihood_without_removing_evidence() -> None:
    from app.services.attack_path import build_deterministic_attack_paths

    edge = _asset("edge.example", internet=True)
    crown = _asset(
        "customer-db", criticality="critical", controls=["network_segmentation", "mfa"]
    )
    finding = SimpleNamespace(
        id=uuid.uuid4(), asset_id=edge.id, title="SSRF", severity="high",
        risk_score=80.0, cve_ids=[], cwe="CWE-918",
    )
    relation = SimpleNamespace(
        id=uuid.uuid4(), source_asset_id=edge.id, target_asset_id=crown.id,
        relationship_type="connects_to", evidence={"source": "flow_log"},
    )

    path = build_deterministic_attack_paths([finding], [edge, crown], [relation])[0]

    assert path.likelihood == "medium"
    assert path.controls == ["mfa", "network_segmentation"]
    assert "relationship:" + str(relation.id) in path.evidence_refs


def test_exposure_graph_api_is_mounted_before_dynamic_asset_route() -> None:
    from app.api.v1.assets import router

    paths = [route.path for route in router.routes]
    assert "/assets/exposure-graph/paths" in paths
    assert paths.index("/assets/exposure-graph/paths") < paths.index("/assets/{asset_id}")


@pytest.mark.asyncio
async def test_ai_explanation_cannot_mutate_graph_facts() -> None:
    from app.services.attack_path import AttackPath, _explain_paths

    original = AttackPath(
        entry_point="edge.example",
        crown_jewel="payments-db",
        likelihood="high",
        asset_ids=["a", "b"],
        evidence_refs=["finding:f1", "relationship:r1"],
    )

    class Gateway:
        async def complete_json(self, *_args, **_kwargs):
            return {
                "explanations": [{
                    "index": 0,
                    "explanation": "Patch the verified entry finding and restrict the recorded edge.",
                    "entry_point": "invented-host",
                    "likelihood": "low",
                }]
            }

    explained = (await _explain_paths(Gateway(), [original]))[0]

    assert explained.entry_point == original.entry_point
    assert explained.likelihood == original.likelihood
    assert explained.asset_ids == original.asset_ids
    assert explained.evidence_refs == original.evidence_refs
    assert explained.explanation.startswith("Patch the verified")
