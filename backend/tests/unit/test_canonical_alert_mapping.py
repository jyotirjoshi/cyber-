"""Provider resources must resolve to stable, correctly typed assets."""

from types import SimpleNamespace

from app.services.canonical_ingest import alert_asset_identity, asset_storage_name


def test_github_and_gitlab_use_same_repository_identity() -> None:
    github = SimpleNamespace(provider="github", resource="Acme/Api", evidence={})
    gitlab = SimpleNamespace(
        provider="gitlab", resource="acme/api:src/main.py", evidence={"project": "acme/api"}
    )
    assert alert_asset_identity(github) == ("repo", "acme/api")
    assert alert_asset_identity(gitlab) == ("repo", "acme/api")


def test_wazuh_agent_is_not_misclassified_as_internet_domain() -> None:
    alert = SimpleNamespace(provider="wazuh", resource="web-01 (002)", evidence={"agent_id": "002"})
    assert alert_asset_identity(alert) == ("endpoint_agent", "002")


def test_missing_resource_cannot_create_anonymous_shared_asset() -> None:
    alert = SimpleNamespace(provider="snyk", resource=None, evidence={})
    assert alert_asset_identity(alert) is None


def test_long_provider_resource_keeps_stable_bounded_asset_key() -> None:
    first = asset_storage_name("repo", "acme/" + "a" * 700)
    second = asset_storage_name("repo", "acme/" + "b" * 700)
    assert len(first) <= 512
    assert first != second
    assert first == asset_storage_name("repo", "acme/" + "a" * 700)


def test_tenable_host_uses_domain_or_ip_identity_shared_with_native_scans() -> None:
    domain = SimpleNamespace(provider="tenable", resource="Host.Example", evidence={})
    address = SimpleNamespace(provider="tenable", resource="192.0.2.10", evidence={})
    assert alert_asset_identity(domain) == ("domain", "host.example")
    assert alert_asset_identity(address) == ("ip", "192.0.2.10")
