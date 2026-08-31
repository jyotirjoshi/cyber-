"""LLM access layer (PRD §55, SEC-005, SEC-006, FR-024).

Import :func:`~app.llm.gateway.get_gateway` and ask for a *role*.  Nothing outside this
package imports a provider SDK, and nothing outside it decides which model to use -- both are
config, not code.

The three safety pieces are not optional add-ons; they are the reason this package exists as
a layer rather than as scattered SDK calls:

*   ``budget`` clamps everything handed to a model, so raw scanner output can never reach a
    provider (SEC-006).
*   ``prompts`` fences untrusted content and carries the guardrail text (SEC-005).
*   ``guard`` mechanically checks the output for fabricated CVEs, CVSS scores and
    intelligence claims (FR-024).

A caller that goes around the gateway skips all three.
"""

from __future__ import annotations

from app.llm.base import LLMMessage, LLMProviderClient, LLMResponse, Usage
from app.llm.budget import enforce_prompt_budget, estimate_tokens, truncate_tool_output
from app.llm.gateway import LLMGateway, get_gateway, reset_gateway_cache
from app.llm.guard import (
    UNVERIFIABLE_STATEMENT,
    Claim,
    GuardResult,
    assert_no_invented_cve,
    assert_no_invented_cvss,
    verify_claims,
)
from app.llm.prompts import build_evidence_prompt, render_evidence, wrap_untrusted

__all__ = [
    "UNVERIFIABLE_STATEMENT",
    "Claim",
    "GuardResult",
    "LLMGateway",
    "LLMMessage",
    "LLMProviderClient",
    "LLMResponse",
    "Usage",
    "assert_no_invented_cve",
    "assert_no_invented_cvss",
    "build_evidence_prompt",
    "enforce_prompt_budget",
    "estimate_tokens",
    "get_gateway",
    "render_evidence",
    "reset_gateway_cache",
    "truncate_tool_output",
    "verify_claims",
    "wrap_untrusted",
]
