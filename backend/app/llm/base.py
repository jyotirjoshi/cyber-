"""Provider-agnostic LLM types (PRD §55).

The provider SDKs are never imported outside ``app/llm/*_client.py``.  Everything above
this layer -- the agent nodes, the analysis service, the report builder -- speaks only in
:class:`LLMMessage` and :class:`LLMResponse`, so adding a provider is one new module and
one config value rather than a change at every call site.

:class:`LLMProviderClient` is a ``Protocol`` rather than an ABC on purpose: the concrete
clients are constructed lazily by the gateway, and a structural type means a test can pass
a plain object with a ``complete`` method without inheriting anything.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable

MessageRole = Literal["system", "user", "assistant"]


@dataclass(frozen=True, slots=True)
class LLMMessage:
    role: MessageRole
    content: str

    @property
    def char_count(self) -> int:
        return len(self.content)


@dataclass(frozen=True, slots=True)
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass(frozen=True, slots=True)
class LLMResponse:
    text: str
    model: str
    provider: str
    usage: Usage
    stop_reason: str | None = None
    latency_ms: int = 0

    @property
    def truncated_by_length(self) -> bool:
        """True when the provider stopped because it hit ``max_output_tokens``.

        Callers that expect JSON check this before parsing: a response cut off mid-object
        is a length problem, not a schema problem, and the two need different handling.
        """
        return self.stop_reason in {"max_tokens", "length", "MAX_TOKENS"}


@runtime_checkable
class LLMProviderClient(Protocol):
    """What a provider adapter must offer.

    ``json_schema`` is a hint, not a guarantee.  Providers differ in whether they can
    constrain output, so :meth:`app.llm.gateway.LLMGateway.complete_json` always
    validates the returned text itself instead of trusting the provider to have done it.
    """

    name: str

    async def complete(
        self,
        *,
        model: str,
        messages: Sequence[LLMMessage],
        max_output_tokens: int,
        temperature: float,
        json_schema: dict[str, Any] | None = None,
    ) -> LLMResponse:
        ...

    async def aclose(self) -> None:
        ...


def split_system(messages: Sequence[LLMMessage]) -> tuple[str | None, list[LLMMessage]]:
    """Separate system content from the conversation.

    Anthropic and Google take the system prompt as a dedicated parameter while OpenAI
    takes it as a message; every adapter needs this split, so it lives here rather than
    being reimplemented three times.  Multiple system messages are joined in order --
    dropping later ones would silently discard a guardrail appended by the caller.
    """
    system_parts = [m.content for m in messages if m.role == "system"]
    rest = [m for m in messages if m.role != "system"]
    system = "\n\n".join(p for p in system_parts if p.strip()) or None
    return system, rest


def coalesce_turns(messages: Sequence[LLMMessage]) -> list[LLMMessage]:
    """Merge consecutive same-role turns.

    Anthropic rejects two ``user`` messages in a row, and the agent legitimately produces
    them -- one carrying the operator's text, one carrying wrapped tool output.  Merging
    here keeps that a transport detail instead of a constraint on how nodes build prompts.
    """
    out: list[LLMMessage] = []
    for message in messages:
        if out and out[-1].role == message.role:
            merged = f"{out[-1].content}\n\n{message.content}"
            out[-1] = LLMMessage(role=message.role, content=merged)
        else:
            out.append(message)
    return out


__all__ = [
    "LLMMessage",
    "LLMProviderClient",
    "LLMResponse",
    "MessageRole",
    "Usage",
    "coalesce_turns",
    "split_system",
]
