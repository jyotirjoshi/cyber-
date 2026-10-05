"""OpenRouter is an OpenAI-compatible, tenant-configurable provider."""

from __future__ import annotations

from app.core.config import Settings
from app.llm.gateway import LLMGateway


def test_gateway_resolves_openrouter_as_an_openai_compatible_provider() -> None:
    settings = Settings(
        _env_file=None,
        db={"password": "database-password"},
        security={
            "jwt_secret": "a" * 32,
            "credential_encryption_key": "dGVzdC1vbmx5LWtleS0zMi1ieXRlcy1sb25nLXh4eHg=",
        },
        llm={
            "provider": "openrouter",
            "openrouter_api_key": "test-key",
            "default_model": "openai/gpt-4.1-mini",
        },
    )

    gateway = LLMGateway(settings)

    assert gateway.resolve("reasoning") == ("openrouter", "openai/gpt-4.1-mini")
