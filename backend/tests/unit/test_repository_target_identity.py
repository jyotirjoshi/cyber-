"""Repository targets keep their scan type and canonical asset identity."""

from types import SimpleNamespace

from app.agent.nodes.recon import _seed_from_target
from app.core.config import TargetPolicySettings
from app.core.targets import TargetType, validate_target
from app.services.canonical_identity import normalized_asset_identity


def test_public_repository_https_url_is_a_repository_not_web_page() -> None:
    target = validate_target("https://github.com/Example/Service.git", TargetPolicySettings())
    assert target.type == TargetType.REPOSITORY
    assert target.canonical == "https://github.com/Example/Service"
    assert validate_target(target.canonical, TargetPolicySettings()).type == TargetType.REPOSITORY


def test_general_two_segment_web_url_remains_a_web_target() -> None:
    target = validate_target("https://example.com/app/login", TargetPolicySettings())
    assert target.type == TargetType.URL


def test_repository_url_matches_provider_project_identity() -> None:
    assert normalized_asset_identity("repo", "https://github.com/Example/Service.git") == (
        "repo",
        "example/service",
    )
    assert normalized_asset_identity("repo", "example/service") == ("repo", "example/service")
    assert normalized_asset_identity("repo", "git@github.com:Example/Service.git") == (
        "repo",
        "example/service",
    )
    assert normalized_asset_identity("repo", "https://git.company.example/Example/Service") == (
        "repo",
        "git.company.example/example/service",
    )


def test_repo_and_image_targets_seed_inventory_without_faking_network_exposure() -> None:
    for target_type, canonical in (
        (TargetType.REPOSITORY, "https://github.com/acme/api"),
        (TargetType.CONTAINER_IMAGE, "docker.io/acme/api:1.0"),
    ):
        asset = _seed_from_target(
            SimpleNamespace(
                target_type=target_type.value,
                canonical_value=canonical,
                host="unrelated.example",
            )
        )
        assert asset is not None
        assert asset.name == canonical
        assert asset.asset_type == target_type.value
        assert asset.internet_exposed is False


def test_container_aliases_share_one_canonical_image_identity() -> None:
    expected = ("container_image", "docker.io/acme/api:1.0")
    assert validate_target("acme/api:1.0", TargetPolicySettings()).canonical == expected[1]
    assert normalized_asset_identity("container_image", "docker.io/acme/api:1.0") == expected
    assert normalized_asset_identity("container", "docker.io/acme/api:1.0") == expected
    assert normalized_asset_identity("image", "acme/api:1.0") == expected
