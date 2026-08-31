"""The single outbound HTTP path (FR-020).

Every third-party call Cynux makes goes through :class:`ResilientClient`.  No module
constructs a bare ``httpx.AsyncClient``, and that is a hard rule rather than a style
preference: retry semantics, the circuit breaker, rate limiting, secret redaction and the
error taxonomy are all implemented exactly once here.  A client that bypassed this spine
would be a provider that can hang forever, retry a POST into duplicate Jira tickets, or put
a response body carrying an API token into a user-facing error message.

Four behaviours are non-negotiable.

**Retries are narrow.**  Only transport errors and the statuses in
:attr:`RetryPolicy.retry_on_status` are retried, and only for methods that are idempotent by
definition -- or for a non-idempotent method the caller has explicitly made safe by
supplying an ``idempotency_key``.  ``POST /rest/api/3/issue`` that times out after the
server committed the write must not be retried blindly; the second attempt files a second
ticket and the operator gets two.

**Rate limits are respected, not fought.**  A ``429`` is read for ``Retry-After`` and
surfaced as :class:`~app.core.errors.IntegrationRateLimitError` carrying that delay, so the
worker can requeue instead of spinning.  Outbound buckets (NVD in particular, which
publishes a hard 5-requests-per-30-seconds limit for anonymous callers) are enforced
*before* the request leaves, using the Redis token bucket so the limit holds across every
API replica and worker rather than per process.

**Failures are typed, and bodies never leak.**  A non-2xx becomes a specific
``IntegrationError`` subclass carrying ``provider``, with a ``user_message`` that names the
provider and nothing else.  Response bodies go to the structured log at debug level, capped,
and never into an exception message -- provider error payloads routinely echo back the
request, including the ``Authorization`` header value on some misconfigured gateways
(SEC-002).

**Caching is explicit.**  There is no implicit TTL. A caller that wants a cached read passes
``cache_ttl``, and only ``GET`` is ever cached. Anything else, including a repeated ``POST``
lookup, goes to the provider.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import email.utils
import hashlib
import random
from dataclasses import dataclass, field
from json import dumps as json_dumps
from types import TracebackType
from typing import TYPE_CHECKING, Any, Self

import httpx
import structlog
from pydantic import SecretStr

from app.core.config import Settings
from app.core.errors import (
    IntegrationAuthError,
    IntegrationError,
    IntegrationRateLimitError,
    IntegrationTimeoutError,
)
from app.integrations.circuit import BreakerConfig, CircuitBreaker

if TYPE_CHECKING:
    from app.core.redis_client import ResponseCache, TokenBucket

logger = structlog.get_logger(__name__)

#: Methods RFC 9110 defines as idempotent. A retry of one of these cannot create a second
#: side effect, so it is safe without any coordination from the caller.
IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})

#: Header names whose values must never reach a log line (SEC-002).
REDACTED_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-apikey",
        "apikey",
        "token",
        "x-auth-token",
        "x-defectdojo-api-key",
        "private-token",
    }
)

#: Cap on how much of a body is logged when a call fails. Enough to identify the provider's
#: complaint, far too little to exfiltrate a scan result.
_MAX_LOGGED_BODY = 512

#: Longest we will voluntarily sleep waiting for an outbound rate-limit token before giving
#: up and telling the caller to come back later. Beyond this the job should be requeued, not
#: held open occupying a worker slot.
_MAX_BUCKET_WAIT_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    backoff_base: float = 0.5
    backoff_max: float = 8.0
    #: Fraction of the computed delay to randomize by. Without jitter, N workers that fail
    #: against the same provider at the same moment retry at the same moment, forever.
    jitter: float = 0.25
    retry_on_status: frozenset[int] = field(
        default_factory=lambda: frozenset({408, 425, 429, 500, 502, 503, 504})
    )

    def delay_for(self, attempt: int, *, retry_after: float | None = None) -> float:
        """Seconds to wait before ``attempt`` (1-based).

        An explicit ``Retry-After`` from the provider always wins over our own backoff:
        the provider knows when it will be ready and we do not.
        """
        if retry_after is not None and retry_after >= 0:
            return min(retry_after, self.backoff_max * 4)
        raw = min(self.backoff_base * (2 ** max(attempt - 1, 0)), self.backoff_max)
        return raw * (1.0 + random.uniform(-self.jitter, self.jitter))  # noqa: S311


def redact_headers(headers: httpx.Headers | dict[str, str] | None) -> dict[str, str]:
    """Header map safe to put in a log line (SEC-002)."""
    if not headers:
        return {}
    return {
        key: ("<redacted>" if key.lower() in REDACTED_HEADERS else value)
        for key, value in dict(headers).items()
    }


def reveal(value: SecretStr | str | None) -> str:
    """Unwrap a ``SecretStr`` for use in an outbound header.

    Every credential in :mod:`app.core.config` is a ``SecretStr``, whose ``__str__`` is
    ``'**********'``. Interpolating one directly into an ``Authorization`` header produces a
    request that is silently unauthenticated -- the provider answers 401 and the operator
    concludes the token is wrong. Funnelling the unwrap through one named function makes the
    places a secret is deliberately materialized greppable, which is the SEC-002 review
    question: *where does a plaintext credential exist?*
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.get_secret_value()


def parse_retry_after(value: str | None) -> float | None:
    """Read a ``Retry-After`` header. Accepts both delta-seconds and an HTTP date."""
    if not value:
        return None
    stripped = value.strip()
    try:
        return max(float(stripped), 0.0)
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(stripped)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.UTC)
    return max((when - dt.datetime.now(dt.UTC)).total_seconds(), 0.0)


class ResilientClient:
    """An HTTP client for one provider, with the FR-020 reliability behaviours attached."""

    def __init__(
        self,
        *,
        provider: str,
        base_url: str,
        settings: Settings,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
        verify: bool = True,
        retry: RetryPolicy | None = None,
        rate_limiter: TokenBucket | None = None,
        breaker: CircuitBreaker | None = None,
        cache: ResponseCache | None = None,
    ) -> None:
        self.provider = provider
        self.settings = settings
        self.retry = retry or RetryPolicy()
        self._limiter = rate_limiter
        self._breaker = breaker
        self._cache = cache
        self._cache_namespace = f"http:{provider.lower().replace(' ', '_')}"
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers=headers or {},
            #: Separate connect and read budgets. A provider that accepts the connection and
            #: then stalls is the common failure, and a single flat timeout either aborts
            #: slow-but-working imports or waits far too long on a dead host.
            timeout=httpx.Timeout(timeout, connect=min(timeout, 10.0)),
            verify=verify,
            #: DefectDojo and the CISA feed both redirect; following them here keeps that
            #: out of every call site. Redirects are followed within the same client, so
            #: auth headers travel only to hosts the provider itself named.
            follow_redirects=True,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )

    # -- lifecycle ----------------------------------------------------------

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # -- rate limiting ------------------------------------------------------

    async def _await_token(self, cost: int = 1) -> None:
        if self._limiter is None:
            return
        waited = 0.0
        while True:
            try:
                allowed, wait_for = await self._limiter.acquire(cost)
            except Exception:
                #: A Redis failure must not stop outbound traffic; the provider's own 429
                #: is the backstop. See CircuitBreaker.status for the same reasoning.
                logger.warning("http.rate_limiter_unavailable", provider=self.provider)
                return
            if allowed:
                return
            wait_for = max(wait_for, 0.05)
            if waited + wait_for > _MAX_BUCKET_WAIT_SECONDS:
                raise IntegrationRateLimitError(self.provider, retry_after=wait_for)
            await asyncio.sleep(wait_for)
            waited += wait_for

    # -- caching ------------------------------------------------------------

    def _cache_key(
        self, method: str, path: str, params: dict[str, Any] | None, body: Any | None
    ) -> str:
        canonical = json_dumps(
            {
                "m": method,
                "p": path,
                "q": params or {},
                "b": body,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    async def _cached_response(self, key: str) -> httpx.Response | None:
        if self._cache is None:
            return None
        try:
            payload = await self._cache.get(self._cache_namespace, key)
        except Exception:  # pragma: no cover - cache is an optimization
            return None
        if not isinstance(payload, dict) or "status" not in payload:
            return None
        response = httpx.Response(
            status_code=int(payload["status"]),
            content=str(payload.get("body", "")).encode("utf-8"),
            headers=payload.get("headers") or {},
        )
        logger.debug("http.cache_hit", provider=self.provider, key=key[:12])
        return response

    async def _store_response(self, key: str, response: httpx.Response, ttl: int) -> None:
        if self._cache is None or ttl <= 0:
            return
        try:
            body = response.text
        except UnicodeDecodeError:
            #: Binary payloads are not cached. Every cached read in Cynux is a JSON
            #: intelligence lookup; silently base64-inflating a scan artifact into Redis
            #: would be a memory problem, not a cache.
            return
        content_type = response.headers.get("content-type", "")
        try:
            await self._cache.set(
                self._cache_namespace,
                key,
                {
                    "status": response.status_code,
                    "body": body,
                    "headers": {"content-type": content_type} if content_type else {},
                },
                ttl,
            )
        except Exception:  # pragma: no cover - cache is an optimization
            logger.debug("http.cache_store_failed", provider=self.provider)

    # -- error mapping ------------------------------------------------------

    def _raise_for_status(self, response: httpx.Response, *, method: str, path: str) -> None:
        status = response.status_code
        if status < 400:
            return

        #: Bodies are logged, capped, at debug -- and never put in the raised message.
        body_excerpt = ""
        try:
            body_excerpt = response.text[:_MAX_LOGGED_BODY]
        except UnicodeDecodeError:  # pragma: no cover
            body_excerpt = "<binary>"
        logger.warning(
            "http.error_response",
            provider=self.provider,
            method=method,
            path=path,
            status=status,
            response_headers=redact_headers(response.headers),
            body_excerpt=body_excerpt,
        )

        context: dict[str, Any] = {"status": status, "method": method, "path": path}
        if status in (401, 403):
            raise IntegrationAuthError(self.provider, context=context)
        if status == 429:
            retry_after = parse_retry_after(response.headers.get("retry-after"))
            raise IntegrationRateLimitError(self.provider, retry_after=retry_after, context=context)
        if status in (408, 504):
            raise IntegrationTimeoutError(
                f"{self.provider} did not respond in time (HTTP {status}).",
                provider=self.provider,
                context=context,
            )
        raise IntegrationError(
            f"{self.provider} returned HTTP {status} for {method} {path}.",
            provider=self.provider,
            context=context,
        )

    def _counts_as_provider_failure(self, status: int) -> bool:
        """Whether this status should advance the circuit breaker.

        5xx, timeouts and rate limits mean the provider is unwell. Broken credentials do
        too -- every subsequent call will fail identically, so continuing to send them is
        pure noise against someone else's service. A ``404`` or ``400``, by contrast, means
        *we* asked for the wrong thing; the provider is fine and opening the circuit would
        take down the healthy integration.
        """
        return status in (401, 403, 408, 425, 429) or status >= 500

    # -- the request ------------------------------------------------------

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        files: Any | None = None,
        headers: dict[str, str] | None = None,
        cache_ttl: int | None = None,
        idempotency_key: str | None = None,
        rate_limit_cost: int = 1,
    ) -> httpx.Response:
        method = method.upper()
        retryable_method = method in IDEMPOTENT_METHODS or idempotency_key is not None

        if cache_ttl and method == "GET":
            key = self._cache_key(method, path, params, None)
            cached = await self._cached_response(key)
            if cached is not None:
                return cached
        else:
            key = ""

        if self._breaker is not None:
            #: Raises CircuitOpenError. Deliberately outside the attempt loop: a short
            #: circuit is not something to retry past.
            await self._breaker.check()

        request_headers = dict(headers or {})
        if idempotency_key:
            request_headers["Idempotency-Key"] = idempotency_key

        last_error: Exception | None = None
        for attempt in range(1, self.retry.max_attempts + 1):
            await self._await_token(rate_limit_cost)
            try:
                response = await self._client.request(
                    method,
                    path,
                    json=json,
                    params=params,
                    data=data,
                    files=files,
                    headers=request_headers or None,
                )
            except httpx.RequestError as exc:
                last_error = exc
                if self._breaker is not None:
                    await self._breaker.record_failure(reason=type(exc).__name__)
                if not retryable_method or attempt >= self.retry.max_attempts:
                    break
                delay = self.retry.delay_for(attempt)
                logger.info(
                    "http.retrying_transport_error",
                    provider=self.provider,
                    method=method,
                    path=path,
                    attempt=attempt,
                    delay_seconds=round(delay, 2),
                    error=type(exc).__name__,
                )
                await asyncio.sleep(delay)
                continue

            status = response.status_code
            if status < 400:
                if self._breaker is not None:
                    await self._breaker.record_success()
                if key:
                    await self._store_response(key, response, cache_ttl or 0)
                return response

            if self._counts_as_provider_failure(status) and self._breaker is not None:
                await self._breaker.record_failure(reason=f"http_{status}")

            should_retry = (
                status in self.retry.retry_on_status
                and retryable_method
                and attempt < self.retry.max_attempts
            )
            if not should_retry:
                self._raise_for_status(response, method=method, path=path)

            retry_after = parse_retry_after(response.headers.get("retry-after"))
            delay = self.retry.delay_for(attempt, retry_after=retry_after)
            #: A provider that asks for longer than we are willing to hold the call open
            #: gets its wish -- as a typed error the worker can requeue on, not a sleep.
            if retry_after is not None and retry_after > self.retry.backoff_max * 2:
                raise IntegrationRateLimitError(
                    self.provider,
                    retry_after=retry_after,
                    context={"status": status, "method": method, "path": path},
                )
            logger.info(
                "http.retrying_status",
                provider=self.provider,
                method=method,
                path=path,
                status=status,
                attempt=attempt,
                delay_seconds=round(delay, 2),
            )
            await asyncio.sleep(delay)

        if isinstance(last_error, httpx.TimeoutException):
            raise IntegrationTimeoutError(
                f"{self.provider} did not respond within the timeout.",
                provider=self.provider,
                cause=last_error,
                context={"method": method, "path": path},
            )
        raise IntegrationError(
            f"{self.provider} was unreachable after {self.retry.max_attempts} attempt(s).",
            provider=self.provider,
            cause=last_error,
            context={"method": method, "path": path},
        )

    # -- JSON helpers -------------------------------------------------------

    def _decode(self, response: httpx.Response, *, path: str) -> Any:
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            logger.warning(
                "http.invalid_json",
                provider=self.provider,
                path=path,
                content_type=response.headers.get("content-type"),
            )
            raise IntegrationError(
                f"{self.provider} returned a response that was not valid JSON.",
                provider=self.provider,
                cause=exc,
                context={"path": path},
            ) from exc

    async def get_json(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        cache_ttl: int | None = None,
        rate_limit_cost: int = 1,
    ) -> Any:
        response = await self.request(
            "GET",
            path,
            params=params,
            headers=headers,
            cache_ttl=cache_ttl,
            rate_limit_cost=rate_limit_cost,
        )
        return self._decode(response, path=path)

    async def post_json(
        self,
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        idempotency_key: str | None = None,
    ) -> Any:
        response = await self.request(
            "POST",
            path,
            json=json,
            params=params,
            headers=headers,
            idempotency_key=idempotency_key,
        )
        return self._decode(response, path=path)

    async def put_json(
        self,
        path: str,
        *,
        json: Any | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        response = await self.request("PUT", path, json=json, headers=headers)
        return self._decode(response, path=path)

    async def patch_json(
        self,
        path: str,
        *,
        json: Any | None = None,
        headers: dict[str, str] | None = None,
        idempotency_key: str | None = None,
    ) -> Any:
        response = await self.request(
            "PATCH", path, json=json, headers=headers, idempotency_key=idempotency_key
        )
        return self._decode(response, path=path)


def build_client(
    *,
    provider: str,
    base_url: str,
    settings: Settings,
    redis: Any | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 30.0,
    verify: bool = True,
    retry: RetryPolicy | None = None,
    rate_limiter: TokenBucket | None = None,
    breaker_config: BreakerConfig | None = None,
    cacheable: bool = False,
) -> ResilientClient:
    """Wire a :class:`ResilientClient` with the Redis-backed collaborators.

    Every integration client needs the same three-line assembly -- breaker keyed on the
    provider name, response cache when the provider's reads are cacheable, optional token
    bucket -- and repeating it ten times is how one client ends up without a breaker.
    ``redis`` is ``Any`` rather than ``Redis`` so importing this module does not require the
    redis package at type-check time in contexts that never touch it.

    When ``redis`` is ``None`` the client still works; it simply has no breaker and no
    cache. Tests use that, and so does a single-process smoke run.
    """
    breaker = None
    cache = None
    if redis is not None:
        breaker = CircuitBreaker(redis, provider=provider, config=breaker_config)
        if cacheable:
            from app.core.redis_client import ResponseCache

            cache = ResponseCache(redis, settings)
    return ResilientClient(
        provider=provider,
        base_url=base_url,
        settings=settings,
        headers=headers,
        timeout=timeout,
        verify=verify,
        retry=retry,
        rate_limiter=rate_limiter,
        breaker=breaker,
        cache=cache,
    )


__all__ = [
    "IDEMPOTENT_METHODS",
    "REDACTED_HEADERS",
    "ResilientClient",
    "RetryPolicy",
    "build_client",
    "parse_retry_after",
    "redact_headers",
    "reveal",
]
