"""OpenRouter adapter using its documented OpenAI-compatible API."""

from __future__ import annotations

from app.llm.openai_client import OpenAIClient

PROVIDER = "openrouter"


class OpenRouterClient(OpenAIClient):
    """OpenRouter has the Chat Completions contract, but a distinct key and endpoint."""

    name = PROVIDER
    _key_field = "openrouter_api_key"
    _base_url_field = "openrouter_api_key"  # Unused: the endpoint must stay allowlisted.
    _fixed_base_url = "https://openrouter.ai/api/v1"
    _provider_label = "OpenRouter"


__all__ = ["PROVIDER", "OpenRouterClient"]
