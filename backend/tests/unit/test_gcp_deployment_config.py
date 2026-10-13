"""Production configuration contract for the Firebase/GCP topology."""

from __future__ import annotations

import pytest

from app.core.config import Settings, validate_runtime_configuration
from app.core.errors import ConfigurationError


def _production_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "environment": "production",
        "debug": False,
        "public_base_url": "https://cynux-security-prod.web.app",
        "cors_origins": ["https://cynux-security-prod.web.app"],
        "allowed_hosts": ["cynux-security-prod.web.app"],
        "db": {"host": "10.20.0.3", "password": "database-password"},
        "redis": {"url": "rediss://:redis-password@10.20.0.4:6378/0"},
        "security": {
            "jwt_secret": "j" * 64,
            "credential_encryption_key": "dGVzdC1vbmx5LWtleS0zMi1ieXRlcy1sb25nLXh4eHg=",
        },
        "storage": {
            "endpoint_url": "https://storage.googleapis.com",
            "region": "asia-south1",
            "bucket": "cynux-security-prod-artifacts",
            "access_key_id": "gcs-hmac-access-id",
            "secret_access_key": "gcs-hmac-secret",
            "force_path_style": True,
        },
        "defectdojo": {
            "base_url": "https://defectdojo.internal",
            "api_token": "defectdojo-token",
            "verify_tls": True,
        },
        "llm": {
            "provider": None,
            "anthropic_api_key": None,
            "openai_api_key": None,
            "openrouter_api_key": None,
            "google_api_key": None,
            "default_model": None,
            "role_models": {},
            "role_providers": {},
        },
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[arg-type]


def test_gcp_worker_configuration_is_valid_without_platform_llm() -> None:
    warnings = validate_runtime_configuration(_production_settings(), role="worker")

    assert any("provide their own key" in warning for warning in warnings)


@pytest.mark.parametrize(
    ("overrides", "setting_name", "role"),
    [
        ({"cors_origins": ["*"]}, "CYNUX_CORS_ORIGINS", "api"),
        ({"allowed_hosts": ["*"]}, "CYNUX_ALLOWED_HOSTS", "api"),
        ({"public_base_url": "http://cynux.example"}, "CYNUX_PUBLIC_BASE_URL", "api"),
        (
            {
                "storage": {
                    "bucket": "cynux-artifacts",
                    "access_key_id": None,
                    "secret_access_key": None,
                }
            },
            "CYNUX_STORAGE__",
            "worker",
        ),
    ],
)
def test_production_configuration_rejects_unsafe_or_missing_values(
    overrides: dict[str, object], setting_name: str, role: str
) -> None:
    with pytest.raises(ConfigurationError, match=setting_name):
        validate_runtime_configuration(_production_settings(**overrides), role=role)


def test_production_worker_rejects_plain_http_object_storage() -> None:
    settings = _production_settings(
        storage={
            "endpoint_url": "http://storage.internal",
            "bucket": "cynux-artifacts",
            "access_key_id": "access-id",
            "secret_access_key": "secret-key",
        }
    )

    with pytest.raises(ConfigurationError, match="CYNUX_STORAGE__ENDPOINT_URL"):
        validate_runtime_configuration(settings, role="worker")

