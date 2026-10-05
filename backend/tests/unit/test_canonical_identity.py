"""Cross-provider identity must merge evidence without merging unrelated issues."""

from app.services.canonical_identity import identity_for_observation


def test_same_cve_on_same_host_merges_across_providers() -> None:
    nessus = identity_for_observation("ip", "192.0.2.10", ["CVE-2024-12345"], "nessus", "7")
    nuclei = identity_for_observation("ip", "192.0.2.10", ["cve-2024-12345"], "nuclei", "xyz")
    assert nessus == nuclei


def test_same_cve_on_distinct_assets_does_not_merge() -> None:
    first = identity_for_observation("domain", "one.example", ["CVE-2024-12345"], "tenable", "7")
    second = identity_for_observation("domain", "two.example", ["CVE-2024-12345"], "tenable", "7")
    assert first != second


def test_no_cve_keeps_provider_identity_even_with_same_title() -> None:
    first = identity_for_observation("repo", "Acme/Api", [], "github", "alert-7")
    second = identity_for_observation("repo", "Acme/Api", [], "gitlab", "alert-7")
    assert first != second


def test_invalid_cve_does_not_create_cross_provider_identity() -> None:
    first = identity_for_observation("repo", "acme/api", ["not-a-cve"], "github", "7")
    second = identity_for_observation("repo", "acme/api", ["not-a-cve"], "gitlab", "7")
    assert first != second


def test_repository_case_normalizes_for_cross_provider_match() -> None:
    first = identity_for_observation("repo", "Acme/Api", ["CVE-2024-12345"], "github", "7")
    second = identity_for_observation("repo", "acme/api", ["CVE-2024-12345"], "gitlab", "9")
    assert first == second


def test_recon_host_type_matches_tenable_domain_and_ip_identity() -> None:
    from app.services.canonical_identity import normalized_asset_identity

    assert normalized_asset_identity("host", "Host.Example") == ("domain", "host.example")
    assert normalized_asset_identity("host", "192.0.2.10") == ("ip", "192.0.2.10")
