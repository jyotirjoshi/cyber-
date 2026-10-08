"""Cloud account targets cannot be interpreted as image tags or network hosts."""

from types import SimpleNamespace

import pytest

from app.core.config import TargetPolicySettings
from app.core.errors import InvalidTargetError, TargetDeniedError
from app.core.targets import TargetType, classify, validate_target
from app.db.enums import AssessmentDepth, ScannerName


def test_aws_account_is_canonical_cloud_target() -> None:
    assert classify("aws:123456789012") == TargetType.CLOUD_ACCOUNT
    target = validate_target("AWS:123456789012", TargetPolicySettings())
    assert target.type == TargetType.CLOUD_ACCOUNT
    assert target.canonical == "aws:123456789012"
    assert target.host == "aws:123456789012"


@pytest.mark.parametrize(
    "raw,canonical,provider,account",
    [
        (
            "AZURE:11111111-1111-1111-1111-111111111111",
            "azure:11111111-1111-1111-1111-111111111111",
            "azure",
            "11111111-1111-1111-1111-111111111111",
        ),
        ("GCP:example-project-1", "gcp:example-project-1", "gcp", "example-project-1"),
    ],
)
def test_other_cloud_accounts_are_canonical_scoped_targets(
    raw: str,
    canonical: str,
    provider: str,
    account: str,
) -> None:
    assert classify(raw) == TargetType.CLOUD_ACCOUNT
    target = validate_target(raw, TargetPolicySettings())
    assert target.canonical == canonical
    assert target.host == canonical
    assert target.metadata == {"provider": provider, "account_id": account}


@pytest.mark.parametrize(
    "value",
    [
        "azure:not-a-subscription",
        "azure:11111111-1111-1111-1111-11111111111x",
        "gcp:bad",
        "gcp:UPPER-PROJECT",
        "gcp:example-project-1:other",
    ],
)
def test_malformed_other_cloud_accounts_are_rejected(value: str) -> None:
    with pytest.raises(InvalidTargetError):
        validate_target(value, TargetPolicySettings())


@pytest.mark.parametrize("value", ["aws:123", "aws:123456789012:other", "aws:000000000000x"])
def test_malformed_cloud_account_is_rejected(value: str) -> None:
    with pytest.raises(InvalidTargetError):
        validate_target(value, TargetPolicySettings())


def test_account_target_respects_deployment_allowlist() -> None:
    with pytest.raises(TargetDeniedError):
        validate_target("aws:123456789012", TargetPolicySettings(allow_list=["example.com"]))
    target = validate_target(
        "aws:123456789012",
        TargetPolicySettings(allow_list=["aws:123456789012"]),
    )
    assert target.canonical == "aws:123456789012"


def test_aws_account_becomes_an_asset_and_only_a_cloud_scan_job() -> None:
    from app.agent.nodes.approval import _compatible_scanners_for_target
    from app.agent.nodes.recon import _seed_from_target
    from app.agent.nodes.scan import _jobs_for_scope
    from app.scanners.registry import active_scanners

    account = "aws:123456789012"
    seed = _seed_from_target(
        SimpleNamespace(
            target_type=TargetType.CLOUD_ACCOUNT.value,
            canonical_value=account,
            host=account,
        )
    )
    assert seed is not None
    assert seed.name == account
    assert seed.asset_type == "cloud_account"
    assert active_scanners(AssessmentDepth.STANDARD).count(ScannerName.PROWLER_AWS) == 1
    compatible = _compatible_scanners_for_target(
        account,
        list(active_scanners(AssessmentDepth.STANDARD)),
    )
    assert compatible == [ScannerName.PROWLER_AWS]
    assert _jobs_for_scope([account], compatible) == [(ScannerName.PROWLER_AWS, [account])]


def test_azure_subscription_plans_only_its_cloud_scanner() -> None:
    from app.agent.nodes.approval import _compatible_scanners_for_target
    from app.agent.nodes.scan import _jobs_for_scope
    from app.scanners.registry import active_scanners

    target = "azure:11111111-1111-1111-1111-111111111111"
    compatible = _compatible_scanners_for_target(
        target,
        list(active_scanners(AssessmentDepth.STANDARD)),
    )
    assert compatible == [ScannerName.PROWLER_AZURE]
    assert _jobs_for_scope([target], compatible) == [(ScannerName.PROWLER_AZURE, [target])]
    assert _jobs_for_scope(["aws:123456789012"], compatible) == []


def test_gcp_project_plans_only_its_cloud_scanner() -> None:
    from app.agent.nodes.approval import _compatible_scanners_for_target
    from app.agent.nodes.scan import _jobs_for_scope
    from app.scanners.registry import active_scanners

    target = "gcp:example-project-1"
    compatible = _compatible_scanners_for_target(
        target,
        list(active_scanners(AssessmentDepth.STANDARD)),
    )
    assert compatible == [ScannerName.PROWLER_GCP]
    assert _jobs_for_scope([target], compatible) == [(ScannerName.PROWLER_GCP, [target])]
    assert _jobs_for_scope(["aws:123456789012"], compatible) == []
