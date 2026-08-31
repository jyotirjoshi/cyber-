"""Cynux error taxonomy.

FR-040 requires every failure to be *classified* so the agent can decide whether to
retry, degrade gracefully, or surface the problem to the human.  Every exception in
Cynux derives from :class:`CynuxError` and carries:

``category``
    Which of the four PRD classes the failure belongs to (user / scanner /
    integration / ai) plus two internal classes (config, authz).
``retryable``
    Whether a retry could plausibly succeed.  The agent's error-handler node reads
    this instead of pattern-matching on messages.
``degradable``
    Whether the assessment can continue without this step's result.  Reliability
    requirement in PRD section 57: ZAP failing must not fail the assessment.
``user_message``
    A message that is safe to show a human.  It never contains credentials,
    tokens, internal hostnames or stack detail (SEC-002).

The HTTP layer converts these to RFC 9457 problem documents; the agent layer
converts them into ``agent_error`` WebSocket events.
"""

from __future__ import annotations

import enum
import re
from typing import Any


class ErrorCategory(str, enum.Enum):
    """Top-level failure classes (FR-040)."""

    USER = "user_error"
    SCANNER = "scanner_error"
    INTEGRATION = "integration_error"
    AI = "ai_error"
    CONFIG = "config_error"
    AUTHZ = "authorization_error"
    INTERNAL = "internal_error"


class CynuxError(Exception):
    """Base class for every Cynux failure."""

    category: ErrorCategory = ErrorCategory.INTERNAL
    http_status: int = 500
    retryable: bool = False
    degradable: bool = False
    #: Shown to the end user verbatim. Must never embed secrets.
    default_user_message = "An unexpected error occurred."

    def __init__(
        self,
        message: str | None = None,
        *,
        user_message: str | None = None,
        context: dict[str, Any] | None = None,
        retryable: bool | None = None,
        degradable: bool | None = None,
        cause: BaseException | None = None,
    ) -> None:
        self.message = message or self.default_user_message
        self.user_message = user_message or self.default_user_message
        self.context: dict[str, Any] = context or {}
        if retryable is not None:
            self.retryable = retryable
        if degradable is not None:
            self.degradable = degradable
        self.cause = cause
        super().__init__(self.message)

    @property
    def code(self) -> str:
        """Stable machine-readable code, e.g. ``scanner_timeout``."""
        return _camel_to_snake(type(self).__name__.removesuffix("Error"))

    def to_problem(self) -> dict[str, Any]:
        """RFC 9457 problem document. Only user-safe fields are included."""
        return {
            "type": f"https://docs.cynux.io/errors/{self.code}",
            "title": self.user_message,
            "status": self.http_status,
            "code": self.code,
            "category": self.category.value,
            "retryable": self.retryable,
        }

    def to_log_fields(self) -> dict[str, Any]:
        return {
            "error_code": self.code,
            "error_category": self.category.value,
            "error_retryable": self.retryable,
            "error_degradable": self.degradable,
            **{f"ctx_{k}": v for k, v in self.context.items()},
        }


_ACRONYM_BOUNDARY = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_WORD_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _camel_to_snake(name: str) -> str:
    """``ScannerTimeout`` -> ``scanner_timeout``; ``AIProvider`` -> ``ai_provider``."""
    name = _ACRONYM_BOUNDARY.sub("_", name)
    return _WORD_BOUNDARY.sub("_", name).lower()


# ---------------------------------------------------------------------------
# User errors -- the request itself is wrong. Never retried.
# ---------------------------------------------------------------------------


class UserError(CynuxError):
    category = ErrorCategory.USER
    http_status = 400
    default_user_message = "The request could not be processed."


class InvalidTargetError(UserError):
    http_status = 422
    default_user_message = "That target isn't a form Cynux can scan."


class UnauthorizedTargetError(UserError):
    """FR-005: the user has not attested authorization to test this target."""

    http_status = 403
    default_user_message = (
        "Cynux has no authorization record for this target. Confirm you are "
        "permitted to test it before starting an assessment."
    )


class TargetDeniedError(UserError):
    """The target is on the global or organization deny list."""

    http_status = 403
    default_user_message = "Scanning this target is blocked by policy."


class InvalidConfigurationError(UserError):
    http_status = 422
    default_user_message = "The supplied configuration is not valid."


class ResourceNotFoundError(UserError):
    http_status = 404
    default_user_message = "That resource does not exist."


class ConflictError(UserError):
    http_status = 409
    default_user_message = "That action conflicts with the current state."


class QuotaExceededError(UserError):
    http_status = 429
    default_user_message = "This organization has reached its concurrency limit."


# ---------------------------------------------------------------------------
# Authorization / authentication
# ---------------------------------------------------------------------------


class AuthenticationError(CynuxError):
    category = ErrorCategory.AUTHZ
    http_status = 401
    default_user_message = "Sign in to continue."


class PermissionDeniedError(CynuxError):
    category = ErrorCategory.AUTHZ
    http_status = 403
    default_user_message = "Your role does not allow this action."


class TenantIsolationError(CynuxError):
    """SEC-003. Raised when a query would cross an organization boundary.

    This is a *bug guard*, not a normal control-flow path: it is logged at
    CRITICAL because reaching it means a query was constructed without a tenant
    filter.
    """

    category = ErrorCategory.AUTHZ
    http_status = 404  # deliberately indistinguishable from "not found"
    default_user_message = "That resource does not exist."


# ---------------------------------------------------------------------------
# Scanner errors -- degradable: one scanner failing must not fail the assessment.
# ---------------------------------------------------------------------------


class ScannerError(CynuxError):
    category = ErrorCategory.SCANNER
    http_status = 502
    degradable = True
    default_user_message = "A security scanner did not complete."


class ScannerTimeoutError(ScannerError):
    retryable = True
    default_user_message = "The scanner exceeded its time budget and was stopped."


class ScannerContainerError(ScannerError):
    retryable = True
    default_user_message = "The scanner container failed to start or exited abnormally."


class ScannerCrashError(ScannerError):
    default_user_message = "The scanner exited with an error."


class ScannerOutputError(ScannerError):
    """The scanner produced no parsable artifact."""

    default_user_message = "The scanner produced no usable output."


class ScannerCancelledError(ScannerError):
    http_status = 499
    degradable = True
    default_user_message = "The scanner job was cancelled."


class DockerUnavailableError(ScannerError):
    retryable = True
    degradable = False
    default_user_message = (
        "Cynux cannot reach the container runtime, so scanners cannot be executed."
    )


class UnsafeScannerInvocationError(ScannerError):
    """FR-008 / section 65: a scanner was about to be invoked with forbidden arguments.

    Not degradable and not retryable -- this is a guardrail trip, and the correct
    response is to fail loudly rather than run the command.
    """

    category = ErrorCategory.INTERNAL
    http_status = 500
    degradable = False
    retryable = False
    default_user_message = "Cynux blocked an unsafe scanner invocation."


# ---------------------------------------------------------------------------
# Integration errors
# ---------------------------------------------------------------------------


class IntegrationError(CynuxError):
    category = ErrorCategory.INTEGRATION
    http_status = 502
    retryable = True
    degradable = True
    provider: str = "external service"
    default_user_message = "An external service is unavailable."

    def __init__(self, message: str | None = None, *, provider: str | None = None, **kw: Any):
        if provider:
            self.provider = provider
        kw.setdefault("user_message", f"{self.provider} is currently unavailable.")
        super().__init__(message, **kw)


class IntegrationNotConfiguredError(IntegrationError):
    """The user asked for something that needs an integration nobody set up.

    Cynux never substitutes invented data for a missing integration (FR-024), so
    this surfaces as an actionable configuration problem instead.
    """

    category = ErrorCategory.CONFIG
    http_status = 424
    retryable = False
    degradable = True

    def __init__(self, provider: str, *, hint: str | None = None, **kw: Any):
        self.provider = provider
        msg = f"{provider} is not configured for this organization."
        if hint:
            msg = f"{msg} {hint}"
        kw.setdefault("user_message", msg)
        super().__init__(msg, provider=provider, **kw)


class IntegrationAuthError(IntegrationError):
    http_status = 502
    retryable = False

    def __init__(self, provider: str, **kw: Any):
        kw.setdefault(
            "user_message",
            f"Cynux was rejected by {provider}. Its credentials need to be updated.",
        )
        super().__init__(f"{provider} rejected our credentials", provider=provider, **kw)


class IntegrationRateLimitError(IntegrationError):
    http_status = 429
    retryable = True

    def __init__(self, provider: str, *, retry_after: float | None = None, **kw: Any):
        self.retry_after = retry_after
        kw.setdefault("user_message", f"{provider} is rate limiting Cynux. Retrying shortly.")
        super().__init__(f"{provider} rate limited", provider=provider, **kw)


class IntegrationTimeoutError(IntegrationError):
    http_status = 504
    retryable = True


class CircuitOpenError(IntegrationError):
    """The circuit breaker refused the call before it left the process."""

    http_status = 503
    retryable = True

    def __init__(self, provider: str, *, reopens_in: float | None = None, **kw: Any):
        self.reopens_in = reopens_in
        kw.setdefault(
            "user_message",
            f"{provider} has been failing, so Cynux paused calls to it and will retry.",
        )
        super().__init__(f"circuit open for {provider}", provider=provider, **kw)


class DefectDojoError(IntegrationError):
    provider = "DefectDojo"
    #: DefectDojo is the source of truth for findings; losing it stops finding import.
    degradable = False


class StorageError(IntegrationError):
    provider = "Object storage"
    degradable = False


# ---------------------------------------------------------------------------
# AI errors
# ---------------------------------------------------------------------------


class AIError(CynuxError):
    category = ErrorCategory.AI
    http_status = 502
    retryable = True
    default_user_message = "The AI model could not complete that step."


class ModelUnavailableError(AIError):
    default_user_message = "The configured AI model is unavailable. Retrying."


class InvalidModelResponseError(AIError):
    """The model returned output that does not satisfy the declared schema."""

    default_user_message = "The AI returned a malformed response and was asked again."


class InvalidToolCallError(AIError):
    """The model asked for a tool that does not exist, or with invalid arguments."""

    retryable = True
    default_user_message = "The AI requested an invalid action; the request was rejected."


class ToolPermissionError(AIError):
    """FR-034: the model asked for a tool above its permitted risk level."""

    category = ErrorCategory.AUTHZ
    http_status = 403
    retryable = False
    default_user_message = "The AI attempted an action that is not permitted."


class ApprovalRequiredError(CynuxError):
    """FR-011 / AI guardrails: a gated action was attempted without an approval record."""

    category = ErrorCategory.AUTHZ
    http_status = 428
    retryable = False
    default_user_message = "This action needs human approval before it can run."


class UnverifiableClaimError(AIError):
    """FR-024: the model asserted security facts with no supporting source."""

    retryable = True
    default_user_message = "Unable to verify from available security intelligence."


class ContextBudgetExceededError(AIError):
    """SEC-006: tool output was too large to pass to the model even after summarization."""

    retryable = False
    degradable = True
    default_user_message = "The tool output was too large to analyze in full; it was truncated."


# ---------------------------------------------------------------------------
# Configuration errors -- fail fast at startup.
# ---------------------------------------------------------------------------


class ConfigurationError(CynuxError):
    category = ErrorCategory.CONFIG
    http_status = 500
    retryable = False
    default_user_message = "Cynux is not correctly configured."

    def __init__(self, message: str, *, setting: str | None = None, **kw: Any):
        self.setting = setting
        kw.setdefault("user_message", message)
        super().__init__(message, **kw)


class NoLLMProviderError(ConfigurationError):
    """Section 55 + explicit product decision: there is no default LLM provider.

    Cynux refuses to guess. If nothing is configured it says exactly what to set.
    """

    def __init__(self) -> None:
        super().__init__(
            "No LLM provider is configured. Cynux has no default provider by design. "
            "Set CYNUX_LLM__PROVIDER to one of: anthropic, openai, google -- and supply "
            "the matching API key (CYNUX_LLM__ANTHROPIC_API_KEY, "
            "CYNUX_LLM__OPENAI_API_KEY or CYNUX_LLM__GOOGLE_API_KEY).",
            setting="CYNUX_LLM__PROVIDER",
        )


__all__ = [
    "AIError",
    "ApprovalRequiredError",
    "AuthenticationError",
    "CircuitOpenError",
    "ConfigurationError",
    "ConflictError",
    "ContextBudgetExceededError",
    "CynuxError",
    "DefectDojoError",
    "DockerUnavailableError",
    "ErrorCategory",
    "IntegrationAuthError",
    "IntegrationError",
    "IntegrationNotConfiguredError",
    "IntegrationRateLimitError",
    "IntegrationTimeoutError",
    "InvalidConfigurationError",
    "InvalidModelResponseError",
    "InvalidTargetError",
    "InvalidToolCallError",
    "ModelUnavailableError",
    "NoLLMProviderError",
    "PermissionDeniedError",
    "QuotaExceededError",
    "ResourceNotFoundError",
    "ScannerCancelledError",
    "ScannerContainerError",
    "ScannerCrashError",
    "ScannerError",
    "ScannerOutputError",
    "ScannerTimeoutError",
    "StorageError",
    "TargetDeniedError",
    "TenantIsolationError",
    "ToolPermissionError",
    "UnauthorizedTargetError",
    "UnsafeScannerInvocationError",
    "UnverifiableClaimError",
    "UserError",
]
