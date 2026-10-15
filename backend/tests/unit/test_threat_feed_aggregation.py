from __future__ import annotations

import datetime as dt

from app.services.threat_feed import (
    ThreatFeedObservation,
    merge_observations,
    normalize_github_advisory,
    normalize_ransomware_record,
)


def obs(source: str, *, exploited: bool, confidence: float) -> ThreatFeedObservation:
    return ThreatFeedObservation(
        entity_type="cve",
        entity_key="CVE-2026-1234",
        source=source,
        source_reference=f"{source}:CVE-2026-1234",
        confidence=confidence,
        observed_at=dt.datetime(2026, 10, 13, tzinfo=dt.UTC),
        facts={"exploited": exploited},
    )


def test_conflicting_observations_preserve_sources_and_confidence() -> None:
    merged = merge_observations(
        [obs("cisa_kev", exploited=True, confidence=1.0), obs("community", exploited=False, confidence=0.3)]
    )
    assert merged.facts["exploited"] is True
    assert merged.fact_confidence["exploited"] == 1.0
    assert {item.source for item in merged.provenance} == {"cisa_kev", "community"}


def test_merge_is_deterministic_regardless_of_input_order() -> None:
    high = obs("nvd", exploited=False, confidence=0.8)
    low = obs("community", exploited=True, confidence=0.8)
    assert merge_observations([high, low]).facts == merge_observations([low, high]).facts


def test_stale_positive_is_retained_but_visibly_stale() -> None:
    stale = ThreatFeedObservation(
        **{**obs("cisa_kev", exploited=True, confidence=1.0).__dict__, "freshness": "stale"}
    )
    merged = merge_observations([stale])
    assert merged.facts["exploited"] is True
    assert merged.freshness == "stale"


def test_malformed_fact_cannot_override_verified_boolean() -> None:
    malformed = ThreatFeedObservation(
        entity_type="cve",
        entity_key="CVE-2026-1234",
        source="community",
        source_reference="bad",
        confidence=1.0,
        observed_at=dt.datetime(2026, 10, 13, tzinfo=dt.UTC),
        facts={"exploited": "yes"},
    )
    merged = merge_observations([obs("cisa_kev", exploited=True, confidence=1.0), malformed])
    assert merged.facts["exploited"] is True


def test_github_advisory_normalizer_keeps_cve_provenance() -> None:
    rows = normalize_github_advisory(
        {
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
            "identifiers": [{"type": "CVE", "value": "CVE-2026-1234"}],
            "references": [{"url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"}],
        },
        observed_at=dt.datetime(2026, 10, 13, tzinfo=dt.UTC),
    )
    assert [(row.entity_key, row.source) for row in rows] == [
        ("CVE-2026-1234", "github_advisory")
    ]


def test_ransomware_normalizer_links_actor_and_cves() -> None:
    rows = normalize_ransomware_record(
        {
            "actor": "Example Group",
            "cve_ids": ["CVE-2026-1234", "CVE-2026-1234"],
            "reference": "feed:item:42",
            "license_reference": "https://feed.example/license",
        },
        observed_at=dt.datetime(2026, 10, 13, tzinfo=dt.UTC),
        source="licensed_ransomware_feed",
    )
    assert [row.entity_type for row in rows] == ["actor", "cve"]
    assert rows[0].facts["cve_ids"] == ["CVE-2026-1234"]
    assert rows[1].facts["ransomware_use"] is True
