"""Production startup validation for managed and BYOK deployments."""

from __future__ import annotations

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
