"""Contracts for tenant-scoped BYOK LLM providers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.core.config import LLMSettings, Settings
from app.db.enums import IntegrationKind
from app.llm.base import LLMMessage
from app.llm.google_client import GoogleClient
from app.services.integration import _ping, _spec_for


def test_openrouter_uses_its_own_encrypted_credential_slot() -> None:
    """An OpenRouter key must never be treated as an OpenAI key."""
    settings = LLMSettings(
        provider="openrouter",
        openrouter_api_key="test-openrouter-key",
        default_model="google/gemini-2.5-flash",
    )

    assert settings.key_for("openrouter").get_secret_value() == "test-openrouter-key"
    assert _spec_for(IntegrationKind.LLM).credentials["openrouter_api_key"] == "openrouter_api_key"


@pytest.mark.asyncio
async def test_llm_integration_test_runs_a_bounded_gateway_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """The integrations page's Test action must work for a configured BYOK provider."""
    observed: dict[str, object] = {}

    class _Gateway:
        def __init__(self, settings: Settings) -> None:
            observed["settings"] = settings

        async def probe(self) -> None:
            observed["probed"] = True

    monkeypatch.setattr("app.services.integration.LLMGateway", _Gateway)
    settings = Settings(
        llm={
            "provider": "google",
            "google_api_key": "test-google-key",
            "default_model": "gemini-2.5-flash",
        }
    )

    assert await _ping(IntegrationKind.LLM, settings, redis=None) is True
    assert observed == {"settings": settings, "probed": True}


@pytest.mark.asyncio
async def test_google_client_uses_nonpersistent_interactions_for_current_models(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Security prompts must not be retained at the provider just to preserve chat state."""
    observed: dict[str, object] = {}

    class _Interactions:
        async def create(self, **kwargs: object) -> object:
            observed.update(kwargs)
            return SimpleNamespace(
                output_text="OK",
                model="gemini-3.6-flash",
                usage_metadata=SimpleNamespace(prompt_token_count=4, candidates_token_count=1),
            )

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            self.aio = SimpleNamespace(interactions=_Interactions())

    monkeypatch.setattr("google.genai.Client", _Client)
    client = GoogleClient(LLMSettings(provider="google", google_api_key="test-key"))

    response = await client.complete(
        model="gemini-3.6-flash",
        messages=[LLMMessage(role="system", content="Be concise."), LLMMessage(role="user", content="Ping")],
        max_output_tokens=32,
        temperature=0.0,
    )

    assert response.text == "OK"
    assert response.provider == "google"
    assert observed == {
        "model": "gemini-3.6-flash",
        "input": [{"type": "user_input", "content": [{"type": "text", "text": "Ping"}]}],
        "system_instruction": "Be concise.",
        "generation_config": {"max_output_tokens": 32, "temperature": 0.0},
        "store": False,
    }


@pytest.mark.asyncio
async def test_google_probe_uses_low_thinking_and_requires_visible_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A provider health check must not succeed after reasoning consumes its whole budget."""
    observed: dict[str, object] = {}

    class _Interactions:
        async def create(self, **kwargs: object) -> object:
            observed.update(kwargs)
            return SimpleNamespace(output_text="OK", status="completed")

    class _Client:
        def __init__(self, **_kwargs: object) -> None:
            self.aio = SimpleNamespace(interactions=_Interactions())

    monkeypatch.setattr("google.genai.Client", _Client)
    client = GoogleClient(LLMSettings(provider="google", google_api_key="test-key"))

    await client.probe(model="gemini-3.6-flash")

    assert observed == {
        "model": "gemini-3.6-flash",
        "input": "Reply with OK.",
        "generation_config": {"thinking_level": "low", "max_output_tokens": 128},
        "store": False,
    }
