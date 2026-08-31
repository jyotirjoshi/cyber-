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

    def __init__(self, settings: LLMSettings) -> None:
        key = settings.openai_api_key
        if key is None or not key.get_secret_value():
            raise ConfigurationError(
                "OpenAI is selected but no API key is set.",
                setting="CYNUX_LLM__OPENAI_API_KEY",
            )
        try:
            from openai import AsyncOpenAI
        except ImportError as exc:  # pragma: no cover - depends on install extras
            raise ConfigurationError(
                "The 'openai' package is not installed but OpenAI is configured.",
                setting="CYNUX_LLM__PROVIDER",
                cause=exc,
            ) from exc

        kwargs: dict[str, Any] = {
            "api_key": key.get_secret_value(),
            "timeout": float(settings.request_timeout_seconds),
            "max_retries": settings.max_retries,
        }
        if settings.openai_base_url:
            kwargs["base_url"] = settings.openai_base_url
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
            raise _map_error(exc) from exc
        latency_ms = int((time.perf_counter() - started) * 1000)

        choice = response.choices[0] if response.choices else None
        usage = getattr(response, "usage", None)
        return LLMResponse(
            text=(getattr(choice.message, "content", None) or "") if choice else "",
            model=getattr(response, "model", model),
            provider=PROVIDER,
            usage=Usage(
                input_tokens=int(getattr(usage, "prompt_tokens", 0) or 0),
                output_tokens=int(getattr(usage, "completion_tokens", 0) or 0),
            ),
            stop_reason=getattr(choice, "finish_reason", None) if choice else None,
            latency_ms=latency_ms,
        )

    async def aclose(self) -> None:
        await self._client.close()


def _map_error(exc: Exception) -> Exception:
    """Translate SDK exceptions into the Cynux taxonomy. Provider bodies are not echoed."""
    from app.core.errors import IntegrationAuthError, IntegrationRateLimitError

    name = type(exc).__name__
    if name in {"AuthenticationError", "PermissionDeniedError"}:
        return IntegrationAuthError("OpenAI", cause=exc)
    if name == "RateLimitError":
        return IntegrationRateLimitError("OpenAI", cause=exc)
    return ModelUnavailableError(f"OpenAI request failed: {name}", cause=exc)


__all__ = ["PROVIDER", "OpenAIClient"]
