"""Worker runtime dependency checks must fail closed before consuming runs."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.core.errors import ConfigurationError
from app.services import runtime_checks


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        db={"password": "database-password"},
        security={
            "jwt_secret": "a" * 32,
            "credential_encryption_key": "dGVzdC1vbmx5LWtleS0zMi1ieXRlcy1sb25nLXh4eHg=",
        },
        storage={
            "endpoint_url": "http://minio.internal",
            "access_key_id": "access-key",
            "secret_access_key": "secret-key",
        },
        defectdojo={"base_url": "https://dojo.example.test", "api_token": "dojo-token"},
    )


@pytest.mark.asyncio
async def test_worker_probe_marks_storage_unhealthy_when_bucket_check_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail_storage(_settings: Settings) -> None:
        raise RuntimeError("connection refused")

    monkeypatch.setattr(runtime_checks, "_check_storage", fail_storage)

    dependencies = await runtime_checks.probe_worker_dependencies(_settings())

    storage = next(item for item in dependencies if item.name == "storage")
    assert storage.healthy is False
    assert storage.detail == "unreachable"


@pytest.mark.asyncio
async def test_worker_probe_marks_defectdojo_unhealthy_when_auth_check_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail_defectdojo(_settings: Settings) -> None:
        raise RuntimeError("unauthorized")

    monkeypatch.setattr(runtime_checks, "_check_defectdojo", fail_defectdojo)

    dependencies = await runtime_checks.probe_worker_dependencies(_settings())

    defectdojo = next(item for item in dependencies if item.name == "defectdojo")
    assert defectdojo.healthy is False
    assert defectdojo.detail == "unreachable"


@pytest.mark.asyncio
async def test_worker_dependency_assertion_refuses_to_start_when_a_check_is_unhealthy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def unhealthy(_settings: Settings):
        return [
            runtime_checks.DependencyHealth(name="storage", healthy=False, detail="unreachable"),
            runtime_checks.DependencyHealth(name="defectdojo", healthy=True),
        ]

    monkeypatch.setattr(runtime_checks, "probe_worker_dependencies", unhealthy)

    with pytest.raises(ConfigurationError, match="storage"):
        await runtime_checks.assert_worker_dependencies(_settings())
