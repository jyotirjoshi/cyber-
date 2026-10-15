"""Production startup validation for managed and BYOK deployments."""

from __future__ import annotations

import re
from pathlib import Path

from app.core.config import Settings, validate_runtime_configuration


def test_byok_deployment_can_start_without_a_platform_llm_key() -> None:
    """Users configure their own provider after signing in; startup must stay healthy."""
    settings = Settings(
        _env_file=None,
        db={"password": "database-password"},
        security={
            "jwt_secret": "a" * 32,
            "credential_encryption_key": "dGVzdC1vbmx5LWtleS0zMi1ieXRlcy1sb25nLXh4eHg=",
        },
    )

    assert validate_runtime_configuration(settings) is not None


def test_deployed_baseline_manifest_is_complete_and_secret_free() -> None:
    """The recovery baseline must be reproducible without recording credentials."""
    text = Path("../docs/superpowers/baselines/2026-10-16-deployed-snapshot.md").read_text(
        encoding="utf-8"
    )

    for heading in ("Git baseline", "Alembic heads", "Images", "Verification"):
        assert f"## {heading}" in text
    assert not re.search(r"(?:sk-|api[_-]?key\s*[:=]|password\s*[:=])\S+", text, re.I)
