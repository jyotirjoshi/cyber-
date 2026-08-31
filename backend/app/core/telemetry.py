"""OpenTelemetry bootstrap (PRD section 58).

Tracing is optional and off by default, but when enabled the whole
user -> agent -> tool -> container -> scanner -> finding -> AI -> action chain shares
one trace id.  The agent nodes add spans of their own; this module only sets up the
provider and the library instrumentations.
"""

from __future__ import annotations

from typing import Any

import structlog

from app.core.config import Settings

log = structlog.get_logger(__name__)

_initialized = False


def setup_telemetry(settings: Settings, *, service_name: str | None = None) -> None:
    global _initialized
    if _initialized or not settings.otel.enabled:
        return

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
    except ImportError:  # pragma: no cover
        log.warning("otel_unavailable", detail="opentelemetry packages not installed")
        return

    resource = Resource.create(
        {
            "service.name": service_name or settings.otel.service_name,
            "service.version": "1.1.0",
            "deployment.environment": settings.environment,
        }
    )
    provider = TracerProvider(
        resource=resource,
        sampler=ParentBased(TraceIdRatioBased(settings.otel.sample_ratio)),
    )
    provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{settings.otel.endpoint}/v1/traces"))
    )
    trace.set_tracer_provider(provider)
    _initialized = True
    log.info("otel_initialized", endpoint=settings.otel.endpoint)


def instrument_app(app: Any, settings: Settings) -> None:
    if not settings.otel.enabled:
        return
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        from opentelemetry.instrumentation.redis import RedisInstrumentor

        FastAPIInstrumentor.instrument_app(
            app,
            # /health is polled constantly and would swamp the trace budget.
            excluded_urls="health,healthz,metrics",
        )
        HTTPXClientInstrumentor().instrument()
        RedisInstrumentor().instrument()
    except Exception as exc:  # pragma: no cover - instrumentation must never break boot
        log.warning("otel_instrumentation_failed", error=str(exc))


def configure_langsmith(settings: Settings) -> None:
    """LangSmith reads its configuration from the environment, so set it explicitly
    rather than relying on the operator exporting the right variable names."""
    import os

    if not settings.langsmith.enabled or not settings.langsmith.api_key:
        os.environ["LANGCHAIN_TRACING_V2"] = "false"
        return
    os.environ["LANGCHAIN_TRACING_V2"] = "true"
    os.environ["LANGCHAIN_ENDPOINT"] = settings.langsmith.endpoint
    os.environ["LANGCHAIN_API_KEY"] = settings.langsmith.api_key.get_secret_value()
    os.environ["LANGCHAIN_PROJECT"] = settings.langsmith.project
    log.info("langsmith_enabled", project=settings.langsmith.project)


def get_tracer(name: str) -> Any:
    try:
        from opentelemetry import trace

        return trace.get_tracer(name)
    except ImportError:  # pragma: no cover
        return _NoopTracer()


class _NoopTracer:
    """Lets call sites use ``with tracer.start_as_current_span(...)`` unconditionally."""

    def start_as_current_span(self, *_: Any, **__: Any) -> Any:
        import contextlib

        return contextlib.nullcontext(_NoopSpan())


class _NoopSpan:
    def set_attribute(self, *_: Any, **__: Any) -> None:
        ...

    def add_event(self, *_: Any, **__: Any) -> None:
        ...

    def record_exception(self, *_: Any, **__: Any) -> None:
        ...

    def set_status(self, *_: Any, **__: Any) -> None:
        ...


__all__ = ["configure_langsmith", "get_tracer", "instrument_app", "setup_telemetry"]
