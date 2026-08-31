"""Google Gemini adapter (``google-genai``).

Gemini's wire shape differs from the other two in three ways this module absorbs so nothing
above it has to care: the system prompt is ``config.system_instruction``, turns use ``model``
where the others use ``assistant``, and content is a list of parts rather than a string.

``response_schema`` is only used when the schema is simple enough to survive translation.
Gemini's schema dialect is a subset of JSON Schema -- no ``$ref``, no ``oneOf``/``anyOf``, no
``additionalProperties`` -- so a schema containing those is passed as a prompt instruction
instead of being silently mangled into one the model satisfies but the caller did not ask for.
"""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from typing import Any

from app.core.config import LLMSettings
from app.core.errors import ConfigurationError, ModelUnavailableError
from app.llm.base import LLMMessage, LLMResponse, Usage, coalesce_turns, split_system

PROVIDER = "google"

#: Keys Gemini's schema dialect does not accept. Presence of any of them means the schema
#: must be delivered as an instruction instead.
_UNSUPPORTED_SCHEMA_KEYS = frozenset(
    {"$ref", "$defs", "definitions", "oneOf", "anyOf", "allOf", "not", "additionalProperties"}
)

_JSON_INSTRUCTION = """\

## Output format

Reply with a single JSON object and nothing else. It must validate against this JSON Schema:

{schema}
"""


def _is_translatable(node: Any) -> bool:
    if isinstance(node, dict):
        if _UNSUPPORTED_SCHEMA_KEYS & set(node):
            return False
        return all(_is_translatable(value) for value in node.values())
    if isinstance(node, list):
        return all(_is_translatable(item) for item in node)
    return True


class GoogleClient:
    name = PROVIDER

    def __init__(self, settings: LLMSettings) -> None:
        key = settings.google_api_key
        if key is None or not key.get_secret_value():
            raise ConfigurationError(
                "Google is selected but no API key is set.",
                setting="CYNUX_LLM__GOOGLE_API_KEY",
            )
        try:
            from google import genai
            from google.genai import types
        except ImportError as exc:  # pragma: no cover - depends on install extras
            raise ConfigurationError(
                "The 'google-genai' package is not installed but Google is configured.",
                setting="CYNUX_LLM__PROVIDER",
                cause=exc,
            ) from exc

        self._types = types
        self._timeout_ms = settings.request_timeout_seconds * 1000
        self._client = genai.Client(
            api_key=key.get_secret_value(),
            http_options=types.HttpOptions(timeout=self._timeout_ms),
        )

    async def complete(
        self,
        *,
        model: str,
        messages: Sequence[LLMMessage],
        max_output_tokens: int,
        temperature: float,
        json_schema: dict[str, Any] | None = None,
    ) -> LLMResponse:
        types = self._types
        system, conversation = split_system(messages)

        contents = [
            types.Content(
                #: Gemini calls the assistant role "model".
                role="model" if m.role == "assistant" else "user",
                parts=[types.Part.from_text(text=m.content)],
            )
            for m in coalesce_turns(conversation)
        ]
        if not contents:
            raise ConfigurationError(
                "A Gemini request needs at least one user or assistant message.",
                setting="prompt",
            )

        config_kwargs: dict[str, Any] = {
            "temperature": temperature,
            "max_output_tokens": max_output_tokens,
        }
        if system:
            config_kwargs["system_instruction"] = system
        if json_schema is not None:
            config_kwargs["response_mime_type"] = "application/json"
            if _is_translatable(json_schema):
                config_kwargs["response_schema"] = json_schema
            else:
                instruction = _JSON_INSTRUCTION.format(schema=json.dumps(json_schema, indent=2))
                config_kwargs["system_instruction"] = (
                    f"{system}\n{instruction}" if system else instruction
                )

        started = time.perf_counter()
        try:
            response = await self._client.aio.models.generate_content(
                model=model,
                contents=contents,
                config=types.GenerateContentConfig(**config_kwargs),
            )
        except Exception as exc:
            raise _map_error(exc) from exc
        latency_ms = int((time.perf_counter() - started) * 1000)

        usage = getattr(response, "usage_metadata", None)
        candidates = getattr(response, "candidates", None) or []
        finish_reason = getattr(candidates[0], "finish_reason", None) if candidates else None
        return LLMResponse(
            text=getattr(response, "text", None) or "",
            model=model,
            provider=PROVIDER,
            usage=Usage(
                input_tokens=int(getattr(usage, "prompt_token_count", 0) or 0),
                output_tokens=int(getattr(usage, "candidates_token_count", 0) or 0),
            ),
            stop_reason=str(finish_reason) if finish_reason is not None else None,
            latency_ms=latency_ms,
        )

    async def aclose(self) -> None:
        #: ``genai.Client`` holds no long-lived session that needs closing in this version.
        return None


def _map_error(exc: Exception) -> Exception:
    """Translate SDK exceptions into the Cynux taxonomy. Provider bodies are not echoed."""
    from app.core.errors import IntegrationAuthError, IntegrationRateLimitError

    name = type(exc).__name__
    status = getattr(exc, "code", None) or getattr(exc, "status_code", None)
    if name in {"PermissionDenied", "Unauthenticated"} or status in {401, 403}:
        return IntegrationAuthError("Google Gemini", cause=exc)
    if name == "ResourceExhausted" or status == 429:
        return IntegrationRateLimitError("Google Gemini", cause=exc)
    return ModelUnavailableError(f"Gemini request failed: {name}", cause=exc)


__all__ = ["PROVIDER", "GoogleClient"]
