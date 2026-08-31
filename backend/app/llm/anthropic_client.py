"""Anthropic adapter.

The SDK is imported inside :meth:`AnthropicClient.__init__` rather than at module scope so
that ``app.llm`` stays importable in a deployment that configured only one provider -- and
so a missing package surfaces as a :class:`~app.core.errors.ConfigurationError` naming the
setting to fix, instead of an ``ImportError`` traceback at startup.

Anthropic has no JSON-schema response mode, so ``json_schema`` is honoured by appending the
schema to the system prompt and prefilling the assistant turn with ``{``. That gets JSON out
reliably in practice, but it is a nudge and not a guarantee -- which is exactly why
``LLMGateway.complete_json`` validates the text itself and re-asks on failure.
"""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from typing import Any

from app.core.config import LLMSettings
from app.core.errors import ConfigurationError, ModelUnavailableError
from app.llm.base import LLMMessage, LLMResponse, Usage, coalesce_turns, split_system

PROVIDER = "anthropic"

_JSON_INSTRUCTION = """\

## Output format

Reply with a single JSON object and nothing else -- no prose before it, no code fence
around it. It must validate against this JSON Schema:

{schema}
"""


class AnthropicClient:
    name = PROVIDER

    def __init__(self, settings: LLMSettings) -> None:
        key = settings.anthropic_api_key
        if key is None or not key.get_secret_value():
            raise ConfigurationError(
                "Anthropic is selected but no API key is set.",
                setting="CYNUX_LLM__ANTHROPIC_API_KEY",
            )
        try:
            from anthropic import AsyncAnthropic
        except ImportError as exc:  # pragma: no cover - depends on install extras
            raise ConfigurationError(
                "The 'anthropic' package is not installed but Anthropic is configured.",
                setting="CYNUX_LLM__PROVIDER",
                cause=exc,
            ) from exc

        kwargs: dict[str, Any] = {
            "api_key": key.get_secret_value(),
            "timeout": float(settings.request_timeout_seconds),
            "max_retries": settings.max_retries,
        }
        if settings.anthropic_base_url:
            kwargs["base_url"] = settings.anthropic_base_url
        self._client = AsyncAnthropic(**kwargs)

    async def complete(
        self,
        *,
        model: str,
        messages: Sequence[LLMMessage],
        max_output_tokens: int,
        temperature: float,
        json_schema: dict[str, Any] | None = None,
    ) -> LLMResponse:
        system, conversation = split_system(messages)
        if json_schema is not None:
            schema_text = _JSON_INSTRUCTION.format(schema=json.dumps(json_schema, indent=2))
            system = f"{system}\n{schema_text}" if system else schema_text

        turns = [{"role": m.role, "content": m.content} for m in coalesce_turns(conversation)]
        if not turns:
            #: Anthropic requires at least one turn. A system-only prompt is a caller bug,
            #: but failing here with a clear message beats a 400 from the provider.
            raise ConfigurationError(
                "An Anthropic request needs at least one user or assistant message.",
                setting="prompt",
            )
        if json_schema is not None:
            #: Prefill the assistant turn so the model continues an object rather than
            #: opening with prose. The gateway re-attaches the brace before parsing.
            turns.append({"role": "assistant", "content": "{"})

        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": max_output_tokens,
            "temperature": temperature,
            "messages": turns,
        }
        if system:
            payload["system"] = system

        started = time.perf_counter()
        try:
            response = await self._client.messages.create(**payload)
        except Exception as exc:
            raise _map_error(exc) from exc
        latency_ms = int((time.perf_counter() - started) * 1000)

        text = "".join(
            block.text for block in response.content if getattr(block, "type", "") == "text"
        )
        if json_schema is not None:
            text = "{" + text

        usage = getattr(response, "usage", None)
        return LLMResponse(
            text=text,
            model=getattr(response, "model", model),
            provider=PROVIDER,
            usage=Usage(
                input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
                output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
            ),
            stop_reason=getattr(response, "stop_reason", None),
            latency_ms=latency_ms,
        )

    async def aclose(self) -> None:
        await self._client.close()


def _map_error(exc: Exception) -> Exception:
    """Translate SDK exceptions into the Cynux taxonomy.

    The provider's message is kept as the *internal* message only. ``ModelUnavailableError``
    supplies its own user-facing text, so a provider response body -- which can echo the
    prompt, and with it hostnames or credentials -- never reaches a client (SEC-002).
    """
    from app.core.errors import IntegrationAuthError, IntegrationRateLimitError

    name = type(exc).__name__
    if name in {"AuthenticationError", "PermissionDeniedError"}:
        return IntegrationAuthError("Anthropic", cause=exc)
    if name == "RateLimitError":
        return IntegrationRateLimitError("Anthropic", cause=exc)
    return ModelUnavailableError(f"Anthropic request failed: {name}", cause=exc)


__all__ = ["PROVIDER", "AnthropicClient"]
