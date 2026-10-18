from __future__ import annotations

import datetime as dt
import uuid
from types import SimpleNamespace


def test_field_provenance_preserves_support_and_conflicts() -> None:
    from app.services.canonical_query import build_field_provenance

    finding = SimpleNamespace(
        title="OpenSSL remote code execution",
        severity="critical",
        status="open",
        cve_ids=["CVE-2026-1000"],
        risk_score=94.5,
        first_seen_at=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
        last_seen_at=dt.datetime(2026, 1, 3, tzinfo=dt.UTC),
        intel_evidence={"kev": {"source": "cisa"}},
    )
    observations = [
        SimpleNamespace(
            id=uuid.uuid4(), provider="tenable", title=finding.title,
            severity="critical", cve_id="CVE-2026-1000", source_status="open",
        ),
        SimpleNamespace(
            id=uuid.uuid4(), provider="snyk", title=finding.title,
            severity="high", cve_id="CVE-2026-1000", source_status="open",
        ),
    ]

    fields = {item.field: item for item in build_field_provenance(finding, observations)}

    assert fields["title"].sources == ["snyk", "tenable"]
    assert fields["title"].confidence == 1.0
    assert fields["severity"].conflicts is True
    assert fields["severity"].confidence == 0.5
    assert fields["cve_ids"].sources == ["snyk", "tenable"]
    assert fields["risk_score"].sources == ["cisa", "cynux:risk_engine"]
    assert fields["status"].sources == ["cynux:lifecycle"]


def test_provenance_is_exposed_on_canonical_detail_schema() -> None:
    from app.schemas.canonical import CanonicalFindingDetailOut

    assert "field_provenance" in CanonicalFindingDetailOut.model_fields
