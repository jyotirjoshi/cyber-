"""Authenticated scanner profile contracts."""

from __future__ import annotations

import pytest

from app.db.enums import ScannerName
from app.services.scan_auth import profile_target_matches, resolve_secret_material


def test_target_scope_accepts_exact_and_subdomain_patterns_only() -> None:
    assert profile_target_matches("https://api.example.com/v1", ["*.example.com"])
    assert profile_target_matches("aws:123456789012", ["aws:123456789012"])
    assert not profile_target_matches("https://example.net", ["*.example.com"])
    assert not profile_target_matches("aws:999999999999", ["aws:123456789012"])


def test_secret_material_is_mapped_only_to_adapter_declared_contract() -> None:
    resolved = resolve_secret_material(
        auth_type="aws_static",
        scanner=ScannerName.PROWLER_AWS,
        secret={"access_key_id": "AKIA_TEST", "secret_access_key": "hidden"},
    )
    assert resolved.environment == {
        "AWS_ACCESS_KEY_ID": "AKIA_TEST",
        "AWS_SECRET_ACCESS_KEY": "hidden",
    }
    assert resolved.options == {}

    with pytest.raises(ValueError, match="not compatible"):
        resolve_secret_material(
            auth_type="aws_static",
            scanner=ScannerName.NUCLEI,
            secret={"access_key_id": "AKIA_TEST", "secret_access_key": "hidden"},
        )


def test_resolved_auth_repr_never_contains_secret() -> None:
    resolved = resolve_secret_material(
        auth_type="bearer",
        scanner=ScannerName.NUCLEI,
        secret={"token": "super-secret-value"},
    )
    assert "super-secret-value" not in repr(resolved)
    assert resolved.options["api_auth_token"].reveal() == "super-secret-value"
