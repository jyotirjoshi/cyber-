"""Cloud findings appear in the assessment report without double counting."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql


def _drive(coroutine):
    with pytest.raises(StopIteration) as finished:
        coroutine.send(None)
    return finished.value.value


def _canonical(finding_id, severity="high"):
    return SimpleNamespace(
        id=finding_id,
        title="Public storage bucket",
        severity=severity,
        status="open",
        cve_ids=[],
        risk_score=71.0,
        risk_factors={},
    )


def _asset():
    return SimpleNamespace(
        id=uuid.uuid4(),
        name="cloud:arn:aws:s3:::customer-a",
        criticality="high",
        endpoint="cloud:arn:aws:s3:::customer-a",
    )


def _summary(total=0):
    return {
        "total": total,
        "by_severity": {"critical": 0, "high": total, "medium": 0, "low": 0, "info": 0},
        "by_priority": {"P1": 0, "P2": 0, "P3": 0, "P4": 0, "P5": 0},
        "unprioritized": 0,
        "in_kev": 0,
        "kev_undetermined": 0,
        "intelligence_unavailable": [],
    }


def test_cloud_only_report_contains_real_canonical_finding() -> None:
    from app.reporting.context import merge_linked_canonical_findings

    finding_id = uuid.uuid4()
    summary, blocks = merge_linked_canonical_findings(
        _summary(),
        [],
        [
            (
                _canonical(finding_id),
                _asset(),
                False,
                {
                    "rule_id": "s3_bucket_public_access",
                    "account_uid": "123456789012",
                    "region": "us-east-1",
                    "untrusted_extra": "must not enter report",
                },
            )
        ],
    )
    assert summary["total"] == 1
    assert summary["by_severity"]["high"] == 1
    assert len(blocks) == 1
    assert blocks[0]["id"] == str(finding_id)
    assert blocks[0]["scanner"] == "prowler_aws"
    assert blocks[0]["analysis"]["ai_generated"] is False
    assert blocks[0]["priority"] == "P2"
    assert summary["by_priority"]["P2"] == 1
    assert summary["unprioritized"] == 0
    assert blocks[0]["asset"]["name"] == "cloud:arn:aws:s3:::customer-a"
    assert blocks[0]["evidence"]["prowler"]["rule_id"] == "s3_bucket_public_access"
    assert blocks[0]["evidence"]["prowler"]["account_uid"] == "123456789012"
    assert "untrusted_extra" not in blocks[0]["evidence"]["prowler"]


def test_known_exploitation_escalates_canonical_report_priority() -> None:
    from app.reporting.context import merge_linked_canonical_findings

    finding = _canonical(uuid.uuid4())
    finding.risk_score = 21.0
    finding.risk_factors = {"inputs": {"in_kev": True, "internet_exposed": False}}
    summary, blocks = merge_linked_canonical_findings(
        _summary(),
        [],
        [(finding, _asset(), False, {})],
    )
    assert blocks[0]["priority"] == "P2"
    assert summary["by_priority"]["P2"] == 1


def test_inactive_canonical_finding_cannot_be_top_priority() -> None:
    from app.reporting.context import merge_linked_canonical_findings

    finding = _canonical(uuid.uuid4())
    finding.status = "accepted_risk"
    finding.risk_score = 95.0
    summary, blocks = merge_linked_canonical_findings(
        _summary(),
        [],
        [(finding, _asset(), False, {})],
    )
    assert blocks[0]["priority"] == "P5"
    assert summary["by_priority"]["P5"] == 1


def test_malformed_canonical_risk_inputs_do_not_break_report() -> None:
    from app.reporting.context import merge_linked_canonical_findings

    finding = _canonical(uuid.uuid4())
    finding.risk_score = 78.0
    finding.risk_factors = {"inputs": "invalid", "unavailable": ["kev", "epss"]}
    summary, blocks = merge_linked_canonical_findings(
        _summary(),
        [],
        [(finding, _asset(), False, {})],
    )
    assert blocks[0]["priority"] == "P1"
    assert summary["intelligence_unavailable"] == ["epss", "kev"]


def test_internet_exposed_known_exploitation_becomes_p1() -> None:
    from app.reporting.context import merge_linked_canonical_findings

    finding = _canonical(uuid.uuid4())
    finding.risk_score = 12.0
    finding.risk_factors = {"inputs": {"in_kev": True, "internet_exposed": True}}
    summary, blocks = merge_linked_canonical_findings(
        _summary(),
        [],
        [(finding, _asset(), False, {})],
    )
    assert blocks[0]["priority"] == "P1"
    assert summary["in_kev"] == 1


def test_report_excludes_native_duplicates_and_false_positives_from_summary() -> None:
    from app.reporting.context import reportable_native_findings

    active = SimpleNamespace(id=uuid.uuid4(), is_duplicate=False, is_false_positive=False)
    duplicate = SimpleNamespace(id=uuid.uuid4(), is_duplicate=True, is_false_positive=False)
    false_positive = SimpleNamespace(id=uuid.uuid4(), is_duplicate=False, is_false_positive=True)
    assert reportable_native_findings([active, duplicate, false_positive]) == [active]


def test_report_excludes_false_positive_canonical_finding() -> None:
    from app.reporting.context import merge_linked_canonical_findings

    finding = _canonical(uuid.uuid4())
    finding.status = "false_positive"
    summary, blocks = merge_linked_canonical_findings(
        _summary(),
        [],
        [(finding, _asset(), False, {})],
    )
    assert summary["total"] == 0
    assert blocks == []


def test_native_finding_already_representing_canonical_identity_is_not_repeated() -> None:
    from app.reporting.context import merge_linked_canonical_findings

    native = {"id": str(uuid.uuid4()), "title": "Same bucket", "severity": "high"}
    summary, blocks = merge_linked_canonical_findings(
        _summary(total=1),
        [native],
        [(_canonical(uuid.uuid4()), _asset(), True, {})],
    )
    assert summary["total"] == 1
    assert blocks == [native]


def test_linked_cloud_assets_are_in_report_inventory_once() -> None:
    from app.reporting.context import merge_linked_assets

    native = _asset()
    cloud = _asset()
    linked = [
        (_canonical(uuid.uuid4()), cloud, False, {}),
        (_canonical(uuid.uuid4()), cloud, False, {}),
        (_canonical(uuid.uuid4()), native, True, {}),
    ]
    merged = merge_linked_assets([native], linked)
    assert [asset.id for asset in merged] == [native.id, cloud.id]


def test_linked_report_query_is_scoped_to_assessment_and_tenant() -> None:
    from app.reporting.context import linked_canonical_findings_for_assessment

    tenant, assessment = uuid.uuid4(), uuid.uuid4()
    statements = []

    class Result:
        def all(self):
            return []

    class Session:
        async def execute(self, statement):
            statements.append(statement)
            return Result()

    assert (
        _drive(
            linked_canonical_findings_for_assessment(
                Session(),
                tenant,
                assessment,
                native_finding_ids=[],
            )
        )
        == []
    )
    compiled = statements[0].compile(dialect=postgresql.dialect())
    assert tenant in compiled.params.values()
    assert assessment in compiled.params.values()


def test_cloud_only_assessment_snapshot_has_finding_and_asset(monkeypatch) -> None:
    from app.reporting import context as reporting

    tenant, assessment_id = uuid.uuid4(), uuid.uuid4()
    asset = _asset()
    for field, value in {
        "asset_type": "cloud",
        "ip_address": None,
        "port": None,
        "protocol": None,
        "service": None,
        "technology": [],
        "internet_exposed": False,
        "http_title": None,
        "http_status_code": None,
        "criticality_rationale": None,
        "selected_for_scanning": False,
    }.items():
        setattr(asset, field, value)
    assessment = SimpleNamespace(
        id=assessment_id,
        organization_id=tenant,
        reference="SCAN-1",
        title="Cloud account",
        scope="aws:123456789012",
        depth="standard",
        status="completed",
        current_stage="done",
        progress_percent=100,
        started_at=None,
        completed_at=None,
        duration_seconds=None,
        failure_reason=None,
        failure_category=None,
        findings_total=0,
        assets_discovered=0,
        assets_in_scope=0,
        degradations=[],
        extra_data={},
    )

    async def empty(*args, **kwargs):
        return []

    async def empty_map(*args, **kwargs):
        return {}

    async def linked(*args, **kwargs):
        assert args[1:3] == (tenant, assessment_id)
        return [(_canonical(uuid.uuid4()), asset, False, {})]

    async def no_approval(*args, **kwargs):
        return None

    monkeypatch.setattr(reporting.finding_service, "findings_for_assessment", empty)
    monkeypatch.setattr(reporting.enrichment_service, "load_enrichments", empty_map)
    monkeypatch.setattr(reporting, "_remediations_by_finding", empty_map)
    for name in ("_assets", "_scanner_jobs", "_targets", "_authorizations"):
        monkeypatch.setattr(reporting, name, empty)
    monkeypatch.setattr(reporting, "linked_canonical_findings_for_assessment", linked)
    monkeypatch.setattr(reporting, "_approval_block", no_approval)

    snapshot = _drive(
        reporting.build_report_context(
            object(),
            assessment,
            settings=SimpleNamespace(public_base_url="https://example.test"),
        )
    )
    assert snapshot["assessment"]["findings_total"] == 1
    assert snapshot["summary"]["total"] == 1
    assert snapshot["asset_count"] == 1
    assert len(snapshot["assets"]) == 1
    assert snapshot["findings"][0]["asset"]["name"] == asset.name
