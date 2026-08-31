"""Turn the report context into HTML and, optionally, PDF (FR-030).

Step two of the pipeline in :mod:`app.reporting`.  :func:`render_html` is the always-path:
Jinja2 with ``autoescape=True``, which is the SEC-005 boundary for the report.  Every
finding title, endpoint, page title and TLS subject in the context originates from a
scanner or a remote host and is therefore untrusted; autoescaping means a finding titled
``<script>…`` renders as text, not markup.  There is no ``| safe`` in the templates, and
there must never be one applied to a scanner-derived value.

:func:`render_pdf` is best-effort.  WeasyPrint pulls in native libraries (Pango, cairo)
that are present in the worker image but not guaranteed in every environment the code is
imported into -- and ``tools/verify.py`` imports every module.  So WeasyPrint is imported
*inside* the worker thread, not at module load: this module imports cleanly with or
without it, and a deployment that lacks it degrades to HTML (the generator handles that)
rather than failing to start.  The import also runs off the event loop because a large
PDF render is CPU-bound and would otherwise stall every open WebSocket.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from pathlib import Path
from typing import Any

import structlog
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.errors import CynuxError, ErrorCategory

log = structlog.get_logger(__name__)

_TEMPLATE_DIR = Path(__file__).parent / "templates"

#: Severity -> CSS class, so the stylesheet owns the palette and the template stays
#: declarative. Unknown severities fall through to the info style rather than breaking.
_SEVERITY_CLASSES: dict[str, str] = {
    "critical": "sev-critical",
    "high": "sev-high",
    "medium": "sev-medium",
    "low": "sev-low",
    "info": "sev-info",
}


class ReportRenderError(CynuxError):
    """A report could not be rendered.

    ``render_html`` raising this is a hard failure -- a template or data bug the generator
    records as a failed report.  ``render_pdf`` raising it (WeasyPrint absent, or a native
    layout error) is recoverable: the generator catches it and falls back to HTML.
    """

    category = ErrorCategory.INTERNAL
    http_status = 500
    default_user_message = "The report could not be produced."


def render_html(context: dict[str, Any]) -> str:
    """Render the report to a self-contained HTML string.

    The context is spread into the template's top-level namespace, so the caller must have
    populated the keys the template reads (``assessment``, ``findings``, ``summary``,
    ``executive_summary``, ``audience`` and the rest) -- see
    :func:`app.reporting.generate.generate`.
    """
    try:
        template = _environment().get_template("report.html")
        return template.render(**context)
    except ReportRenderError:
        raise
    except Exception as exc:  # - any Jinja/rendering fault becomes one taxonomy error
        raise ReportRenderError(
            "HTML rendering failed",
            context={"error": type(exc).__name__},
            cause=exc,
        ) from exc


async def render_pdf(html: str) -> bytes:
    """Render an HTML string to PDF bytes, off the event loop.

    Raises :class:`ReportRenderError` when WeasyPrint is unavailable or the layout fails;
    the generator treats that as a signal to fall back to HTML rather than as a dead end.
    """
    return await asyncio.to_thread(_render_pdf_sync, html)


def _render_pdf_sync(html: str) -> bytes:
    try:
        from weasyprint import HTML  # - deliberately lazy; see module docstring
    except ImportError as exc:
        raise ReportRenderError(
            "the PDF renderer is not installed",
            user_message="PDF output is not available in this environment.",
            context={"renderer": "weasyprint"},
            cause=exc,
        ) from exc
    try:
        rendered = HTML(string=html).write_pdf()
    except Exception as exc:  # - WeasyPrint raises a wide range of native errors
        raise ReportRenderError(
            "PDF rendering failed",
            context={"error": type(exc).__name__},
            cause=exc,
        ) from exc
    if rendered is None:  # pragma: no cover - defensive; write_pdf returns bytes to a string target
        raise ReportRenderError("PDF renderer produced no output")
    return rendered


# ---------------------------------------------------------------------------
# Jinja environment
# ---------------------------------------------------------------------------

_env: Environment | None = None


def _environment() -> Environment:
    """Build the Jinja environment once and reuse it.

    ``autoescape`` is on for HTML/XML; ``trim_blocks``/``lstrip_blocks`` keep the rendered
    markup readable, which matters because the HTML output is itself a deliverable.
    """
    global _env
    if _env is None:
        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(("html", "xml", "htm")),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        env.filters["humandate"] = _humandate
        env.filters["humanduration"] = _humanduration
        env.filters["percent"] = _percent
        env.filters["sevclass"] = _sevclass
        env.filters["paragraphs"] = _paragraphs
        _env = env
    return _env


def _humandate(value: str | None) -> str:
    if not value:
        return "—"
    try:
        parsed = dt.datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return str(value)
    return parsed.strftime("%Y-%m-%d %H:%M UTC")


def _humanduration(seconds: int | float | None) -> str:
    if seconds is None:
        return "—"
    total = int(seconds)
    if total < 60:
        return f"{total}s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def _percent(value: float | None) -> str:
    """Format a 0..1 probability (EPSS) as a percentage. ``None`` reads as unavailable."""
    if value is None:
        return "—"
    return f"{value * 100:.1f}%"


def _sevclass(severity: str | None) -> str:
    return _SEVERITY_CLASSES.get((severity or "").lower(), "sev-info")


def _paragraphs(text: str | None) -> list[str]:
    """Split model prose on blank lines so the template can wrap each in its own <p>.

    Splitting here rather than injecting ``<br>`` keeps every character on the autoescape
    path -- the template still emits the text through ``{{ }}``.
    """
    if not text:
        return []
    return [block.strip() for block in text.replace("\r\n", "\n").split("\n\n") if block.strip()]


__all__ = ["ReportRenderError", "render_html", "render_pdf"]
