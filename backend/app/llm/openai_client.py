"""OpenAI adapter.

Unlike Anthropic, OpenAI can constrain output structurally via ``response_format`` with a
JSON schema.  Cynux uses it when the schema qualifies -- OpenAI's strict mode rejects
schemas that omit ``additionalProperties: false`` or that do not list every property as
required -- and falls back to a prompt instruction when it does not, rather than failing the
call.  Either way ``LLMGateway.complete_json`` still validates the text: a provider feature
is an optimization, not a trust boundary.

``base_url`` is honoured so an operator can point this at a compatible gateway (vLLM,
LiteLLM, Azure-style proxy) without a code change.
"""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from typing import Any

from app.core.config import LLMSettings
from app.core.errors import ConfigurationError, ModelUnavailableError
from app.llm.base import LLMMessage, LLMResponse, Usage, coalesce_turns

PROVIDER = "openai"
OPENROUTER_PROVIDER = "openrouter"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

_JSON_INSTRUCTION = """\

## Output format

Reply with a single JSON object and nothing else. It must validate against this JSON Schema:

{schema}
"""


def _supports_strict_schema(schema: dict[str, Any]) -> bool:
    """Whether ``schema`` satisfies OpenAI structured-output constraints.

    Checked rather than assumed: sending a non-conforming schema is a hard 400, and a
    remediation prompt failing outright because its schema allowed extra properties would
    be a needless outage.
    """
    if schema.get("type") != "object":
        return False
    if schema.get("additionalProperties") is not False:
        return False
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return False
    required = schema.get("required")
    return isinstance(required, list) and set(required) == set(properties)


class OpenAIClient:
    name = PROVIDER

    def __init__(self, settings: LLMSettings, *, provider: str = PROVIDER) -> None:
        self.name = provider
        key = settings.key_for(provider)
        local_provider = provider in {"ollama", "vllm"}
        if (key is None or not key.get_secret_value()) and not local_provider:
            raise ConfigurationError(
                f"{provider.title()} is selected but no API key is set.",
                setting=(
                    "CYNUX_LLM__OPENROUTER_API_KEY"
                    if provider == OPENROUTER_PROVIDER
                    else f"CYNUX_LLM__{provider.upper()}_API_KEY"
                ),
            )
        try:
            from openai import AsyncAzureOpenAI, AsyncOpenAI
        except ImportError as exc:  # pragma: no cover - depends on install extras
            raise ConfigurationError(
                "The 'openai' package is not installed but OpenAI is configured.",
                setting="CYNUX_LLM__PROVIDER",
                cause=exc,
            ) from exc

        kwargs: dict[str, Any] = {
            "api_key": key.get_secret_value() if key else "local-runtime",
            "timeout": float(settings.request_timeout_seconds),
            "max_retries": settings.max_retries,
        }
        base_url = {
            "openrouter": settings.openrouter_base_url or OPENROUTER_BASE_URL,
            "openai": settings.openai_base_url,
            "azure_openai": settings.azure_openai_base_url,
            "ollama": settings.ollama_base_url,
            "vllm": settings.vllm_base_url,
        }.get(provider)
        if provider in {"azure_openai", "ollama", "vllm"} and not base_url:
            raise ConfigurationError(
                f"{provider} requires an explicitly configured base URL.",
                setting=f"CYNUX_LLM__{provider.upper()}_BASE_URL",
            )
        if provider == "azure_openai":
            self._client = AsyncAzureOpenAI(
                api_key=kwargs["api_key"],
                azure_endpoint=base_url,
                api_version=settings.azure_openai_api_version,
                timeout=kwargs["timeout"],
                max_retries=kwargs["max_retries"],
            )
        else:
            if base_url:
                kwargs["base_url"] = base_url
            self._client = AsyncOpenAI(**kwargs)

    async def complete(
        self,
        *,
        model: str,
        messages: Sequence[LLMMessage],
        max_output_tokens: int,
        temperature: float,
        json_schema: dict[str, Any] | None = None,
    ) -> LLMResponse:
        turns = [{"role": m.role, "content": m.content} for m in coalesce_turns(messages)]
        payload: dict[str, Any] = {
            "model": model,
            "messages": turns,
            "max_tokens": max_output_tokens,
            "temperature": temperature,
        }

        if json_schema is not None:
            if _supports_strict_schema(json_schema):
                payload["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {
                        "name": json_schema.get("title", "response"),
                        "schema": json_schema,
                        "strict": True,
                    },
                }
            else:
                payload["response_format"] = {"type": "json_object"}
                instruction = _JSON_INSTRUCTION.format(schema=json.dumps(json_schema, indent=2))
                turns.insert(0, {"role": "system", "content": instruction})

        started = time.perf_counter()
        try:
            response = await self._client.chat.completions.create(**payload)
        except Exception as exc:
            raise _map_error(self.name, exc) from exc
        latency_ms = int((time.perf_counter() - started) * 1000)

        choice = response.choices[0] if response.choices else None
        usage = getattr(response, "usage", None)
        return LLMResponse(
            text=(getattr(choice.message, "content", None) or "") if choice else "",
            model=getattr(response, "model", model),
            provider=self.name,
            usage=Usage(
                input_tokens=int(getattr(usage, "prompt_tokens", 0) or 0),
                output_tokens=int(getattr(usage, "completion_tokens", 0) or 0),
            ),
            stop_reason=getattr(choice, "finish_reason", None) if choice else None,
            latency_ms=latency_ms,
        )

    async def aclose(self) -> None:
        await self._client.close()


def _map_error(provider: str, exc: Exception) -> Exception:
    """Translate SDK exceptions into the Cynux taxonomy. Provider bodies are not echoed."""
    from app.core.errors import IntegrationAuthError, IntegrationRateLimitError

    name = type(exc).__name__
    if name in {"AuthenticationError", "PermissionDeniedError"}:
        return IntegrationAuthError(provider.title(), cause=exc)
    if name == "RateLimitError":
        return IntegrationRateLimitError(provider.title(), cause=exc)
    return ModelUnavailableError(f"{provider.title()} request failed: {name}", cause=exc)


__all__ = ["PROVIDER", "OpenAIClient"]
