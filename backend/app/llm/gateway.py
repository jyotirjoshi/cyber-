"""Role-based LLM gateway (PRD §55).

PRD §55 requires each of the five roles -- planning, reasoning, classification, code
remediation, report generation -- to be independently configurable, because they have
genuinely different cost and capability profiles: classification runs on every finding and
wants a cheap model, code remediation runs rarely and wants the strongest one available.
Callers therefore ask for a *role*, never a model name.

Two rules this module will not bend:

*   **It never invents a model name.**  If a role resolves to nothing, that is a
    :class:`~app.core.errors.ConfigurationError` naming the exact environment variable to
    set.  Guessing ``gpt-4o`` or ``claude-sonnet-4`` would silently bill an operator for a
    model they did not choose, and would break the moment the guess was retired.
*   **It never returns a partially-parsed object.**  :meth:`LLMGateway.complete_json`
    validates the whole payload or raises.  A half-populated finding analysis is worse than
    no analysis: downstream code cannot tell which fields the model actually produced.

Everything passing through here is budget-checked first (SEC-006) and usage-logged
afterwards, so token spend is attributable per role without instrumenting each call site.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Any, TypeVar

import structlog
from pydantic import BaseModel, ValidationError

from app.core.config import REQUIRED_LLM_ROLES, LLMRole, Settings, get_settings
from app.core.errors import (
    ConfigurationError,
    InvalidModelResponseError,
    NoLLMProviderError,
)
from app.llm.base import LLMMessage, LLMProviderClient, LLMResponse
from app.llm.budget import enforce_prompt_budget, estimate_messages_tokens

logger = structlog.get_logger(__name__)

M = TypeVar("M", bound=BaseModel)

#: Strips a ```json fence when a model wraps its object despite being told not to. Cheap to
#: tolerate, and re-asking would cost a full round trip for a formatting nit.
_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*(?P<body>.*?)\s*```\s*$", re.DOTALL)


def _strip_fence(text: str) -> str:
    match = _FENCE_RE.match(text)
    return match.group("body") if match else text.strip()


def _extract_object(text: str) -> str:
    """Best-effort isolation of the outermost JSON object.

    Handles the common case of a model prefixing one sentence of prose. Brace matching is
    string-aware so a ``}`` inside a value -- a remediation patch, a regex in a finding
    description -- does not truncate the object.
    """
    cleaned = _strip_fence(text)
    start = cleaned.find("{")
    if start == -1:
        return cleaned
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(cleaned)):
        char = cleaned[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return cleaned[start : index + 1]
    return cleaned[start:]


class LLMGateway:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._llm = settings.llm
        self._clients: dict[str, LLMProviderClient] = {}

    # -- resolution ---------------------------------------------------------

    def resolve(self, role: LLMRole) -> tuple[str, str]:
        """``(provider, model)`` for ``role``.

        Precedence: a per-role override, then the global provider plus the per-role model,
        then the global provider plus the default model. Anything left unresolved raises.
        """
        if role not in REQUIRED_LLM_ROLES:
            raise ConfigurationError(
                f"Unknown LLM role {role!r}. Valid roles: {', '.join(REQUIRED_LLM_ROLES)}.",
                setting="CYNUX_LLM__ROLE_MODELS",
            )

        provider = self._llm.role_providers.get(role) or self._llm.provider
        if not provider:
            raise NoLLMProviderError()
        provider = str(provider)

        model = self._llm.role_models.get(role) or self._llm.default_model
        if not model:
            raise ConfigurationError(
                f"No model is configured for the {role!r} role and "
                "CYNUX_LLM__DEFAULT_MODEL is unset. Cynux does not guess model names: set "
                f'CYNUX_LLM__ROLE_MODELS=\'{{"{role}": "<model-id>"}}\' or a default.',
                setting="CYNUX_LLM__ROLE_MODELS",
            )
        return provider, model

    def _client(self, provider: str) -> LLMProviderClient:
        cached = self._clients.get(provider)
        if cached is not None:
            return cached

        if provider == "anthropic":
            from app.llm.anthropic_client import AnthropicClient

            client: LLMProviderClient = AnthropicClient(self._llm)
        elif provider == "openai":
            from app.llm.openai_client import OpenAIClient

            client = OpenAIClient(self._llm)
        elif provider == "google":
            from app.llm.google_client import GoogleClient

            client = GoogleClient(self._llm)
        else:
            raise ConfigurationError(
                f"Unsupported LLM provider {provider!r}. Supported: anthropic, openai, google.",
                setting="CYNUX_LLM__PROVIDER",
            )

        self._clients[provider] = client
        return client

    # -- completion ---------------------------------------------------------

    async def complete(
        self,
        role: LLMRole,
        messages: Sequence[LLMMessage],
        *,
        max_output_tokens: int | None = None,
        temperature: float | None = None,
        json_schema: dict[str, Any] | None = None,
    ) -> LLMResponse:
        provider, model = self.resolve(role)
        client = self._client(provider)

        #: SEC-006: the budget is applied here, at the single chokepoint, rather than being
        #: each caller's responsibility.
        bounded = enforce_prompt_budget(messages, limit=self._llm.max_prompt_chars)

        response = await client.complete(
            model=model,
            messages=bounded,
            max_output_tokens=max_output_tokens or self._llm.max_output_tokens,
            temperature=self._llm.temperature if temperature is None else temperature,
            json_schema=json_schema,
        )

        logger.info(
            "llm.complete",
            role=role,
            provider=provider,
            model=model,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            estimated_input_tokens=estimate_messages_tokens(bounded),
            latency_ms=response.latency_ms,
            stop_reason=response.stop_reason,
            truncated_by_length=response.truncated_by_length,
            prompt_trimmed=len(bounded) != len(messages),
        )
        return response

    async def complete_json(
        self,
        role: LLMRole,
        messages: Sequence[LLMMessage],
        *,
        schema: dict[str, Any],
        model_cls: type[M] | None = None,
        max_attempts: int = 2,
    ) -> Any:
        """Structured output, validated here rather than trusted from the provider.

        On a parse or validation failure the request is re-asked once with the specific
        error appended -- models correct a named error reliably and re-asking blindly is a
        waste of a round trip. After ``max_attempts`` it raises
        :class:`~app.core.errors.InvalidModelResponseError`.
        """
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")

        attempt_messages = list(messages)
        last_error: str = ""

        for attempt in range(1, max_attempts + 1):
            response = await self.complete(
                role, attempt_messages, json_schema=schema, temperature=0.0
            )

            if response.truncated_by_length:
                last_error = (
                    "The response was cut off at the output-token limit, so the JSON is "
                    "incomplete. Reply with a shorter but complete object."
                )
            else:
                try:
                    payload = json.loads(_extract_object(response.text))
                except (ValueError, TypeError) as exc:
                    last_error = f"The reply was not valid JSON: {exc}"
                else:
                    if model_cls is None:
                        return payload
                    try:
                        return model_cls.model_validate(payload)
                    except ValidationError as exc:
                        last_error = (
                            "The JSON did not match the required schema:\n"
                            f"{exc.errors(include_url=False)}"
                        )

            logger.warning(
                "llm.structured_output_retry",
                role=role,
                attempt=attempt,
                max_attempts=max_attempts,
                reason=last_error[:400],
            )
            if attempt >= max_attempts:
                break
            attempt_messages = [
                *messages,
                LLMMessage(role="assistant", content=response.text[:4000]),
                LLMMessage(
                    role="user",
                    content=(
                        f"That response was rejected. {last_error}\n\n"
                        "Reply again with only the corrected JSON object."
                    ),
                ),
            ]

        raise InvalidModelResponseError(
            f"Model did not return schema-valid JSON for role {role!r} after "
            f"{max_attempts} attempt(s): {last_error}",
            context={"role": role, "attempts": max_attempts},
        )

    # -- lifecycle ----------------------------------------------------------

    def configured_roles(self) -> dict[str, str]:
        """``{role: "provider/model"}`` for the health endpoint. Never raises: an
        unresolvable role reports its reason instead of taking the endpoint down."""
        out: dict[str, str] = {}
        for role in REQUIRED_LLM_ROLES:
            try:
                provider, model = self.resolve(role)  # type: ignore[arg-type]
            except ConfigurationError as exc:
                out[role] = f"unconfigured: {exc.user_message}"
            else:
                out[role] = f"{provider}/{model}"
        return out

    async def aclose(self) -> None:
        for client in self._clients.values():
            try:
                await client.aclose()
            except Exception:  # pragma: no cover - shutdown must not raise
                logger.warning("llm.client_close_failed", provider=client.name)
        self._clients.clear()


#: Process-wide singleton. ``functools.lru_cache`` is not usable here: ``Settings`` is a
#: pydantic model and therefore unhashable, so it cannot be a cache key.
_gateway: LLMGateway | None = None


def get_gateway(settings: Settings | None = None) -> LLMGateway:
    """Process-wide gateway. Cached so provider SDK clients (and their connection pools)
    are created once rather than per request."""
    global _gateway
    if _gateway is None:
        _gateway = LLMGateway(settings or get_settings())
    return _gateway


def reset_gateway_cache() -> None:
    """Drop the cached gateway. Tests use this after changing settings."""
    global _gateway
    _gateway = None


__all__ = ["LLMGateway", "get_gateway", "reset_gateway_cache"]
