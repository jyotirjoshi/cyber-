"""Structlog bootstrap with secret redaction (SEC-002: credentials never logged)."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, MutableMapping
from typing import Any

import structlog
from structlog.typing import Processor

from app.core.config import Settings

#: Anything with one of these in the key is scrubbed from log output.
SECRET_KEY_SUBSTRINGS = (
    "secret",
    "password",
    "token",
    "key",
    "credential",
    "authorization",
    "cookie",
    "api_key",
)

#: Credentials embedded in a message *body* rather than carried in a field name.
#:
#: Key-based scrubbing cannot see the token in
#: ``GET /api/v1/assessments?api_key=abc123`` -- the key is ``event`` and the secret is in
#: the value. That line is uvicorn's access log, which is the SEC-002 leak the stdlib
#: bridge below exists to stop, so matching on value text is not optional.
#:
#: The name alternation is deliberately narrower than :data:`SECRET_KEY_SUBSTRINGS`: a bare
#: ``key`` is safe to be aggressive about in a field name, but in free text it would redact
#: ``monkey=1``. Here ``key`` must be qualified by ``api``/``access``/``private``/etc.
#:
#: The optional scheme group is load-bearing. Without it ``Authorization: Bearer <jwt>``
#: matches with ``Bearer`` as the value, so the *scheme* gets redacted and the credential
#: survives -- a line that reads as redacted while still leaking.
_SECRET_VALUE_RE = re.compile(
    r"(?i)\b("
    r"[a-z0-9_.\-]*(?:secret|password|passwd|credential|token)[a-z0-9_.\-]*"
    r"|(?:api|access|private|signing|encryption|client)[_-]?keys?"
    r"|authorization"
    r")(\s*[=:]\s*)((?:bearer|basic)\s+)?([^\s&;,\"']+)"
)

#: ``Authorization: Bearer <jwt>``, where the scheme rather than a key name marks the secret.
#: Applied after :data:`_SECRET_VALUE_RE` to catch a scheme with no preceding field name.
_SECRET_SCHEME_RE = re.compile(r"(?i)\b(bearer|basic)(\s+)([A-Za-z0-9._\-+/=]{8,})")

#: The password in a URI's userinfo -- ``postgresql://cynux:pw@db/cynux``. Connection
#: strings reach logs through driver errors, which is where a DSN password gets exposed.
#: The username part is ``*`` rather than ``+`` because ``redis://:pw@host:6379/0`` -- an
#: empty username -- is the ordinary form of a Redis URL, and Cynux's own uses it.
_SECRET_URI_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]*:)([^\s@/]+)(@)")

#: Cheap pre-filter so the regexes only run on lines that could plausibly match.
_TEXT_HINTS = (
    "secret",
    "password",
    "passwd",
    "token",
    "credential",
    "authorization",
    "key=",
    "key:",
    "bearer ",
    "basic ",
    "://",
)

REDACTED = "[REDACTED]"


def redact_text(text: str) -> str:
    """Replace credential *values* inside a string, leaving the rest readable.

    Applied to every string value that survives key-based scrubbing, so a secret is
    redacted whether it arrives as ``{"token": ...}`` or as ``"...?api_key=..."``.
    """
    if not text:
        return text
    low = text.lower()
    if not any(hint in low for hint in _TEXT_HINTS):
        return text
    text = _SECRET_VALUE_RE.sub(rf"\1\2\3{REDACTED}", text)
    text = _SECRET_SCHEME_RE.sub(rf"\1\2{REDACTED}", text)
    return _SECRET_URI_RE.sub(rf"\1{REDACTED}\3", text)


def redact_mapping(
    data: Mapping[str, Any], substrs: tuple[str, ...] = SECRET_KEY_SUBSTRINGS
) -> dict[str, Any]:
    """Key- *and* value-based redaction over a structured payload.

    Shared by :class:`RedactProcessor` and by ``app/services/audit.py``, which scrubs
    ``audit_events.detail`` through it.  The audit trail is durable in a way logs are
    not -- a credential written there outlives every log rotation -- so it must go
    through the same single implementation rather than a second, drifting one (SEC-002).
    """
    return {k: _scrub(k, v, substrs) for k, v in data.items()}


class RedactProcessor:
    """Remove secret-bearing keys from every event dict before serialization."""

    def __init__(self, substrs: tuple[str, ...] = SECRET_KEY_SUBSTRINGS) -> None:
        self.substrs = substrs

    def __call__(
        self, logger: Any, name: str, event_dict: MutableMapping[str, Any]
    ) -> MutableMapping[str, Any]:
        return redact_mapping(event_dict, self.substrs)


def _scrub(key: str, value: object, substrs: tuple[str, ...]) -> object:
    low = key.lower()
    if any(s in low for s in substrs):
        return REDACTED
    if isinstance(value, dict):
        return {k: _scrub(k, v, substrs) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_scrub(key, v, substrs) for v in value]
    if isinstance(value, str):
        #: The key looked innocent; the value may not be. See :func:`redact_text`.
        return redact_text(value)
    return value


def configure_logging(settings: Settings) -> None:
    #: Declared, then assigned in branches: a ternary makes mypy join the two renderer
    #: types to ``object``, which then fails to match the processor list.
    renderer: Processor
    if settings.otel.json_logs:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    #: Applied to every event, whichever side it came from. ``RedactProcessor`` lives here
    #: rather than only in the structlog chain because SEC-002 has to hold for uvicorn's
    #: access log too -- that is the line most likely to carry a token in a query string.
    shared: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        RedactProcessor(),
    ]

    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.otel.log_level)
        ),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Route stdlib loggers through structlog so third-party noise is formatted
    # consistently instead of leaking plaintext request paths containing tokens.
    #
    # ``ProcessorFormatter`` is a ``logging.Formatter``, not a ``logging.Handler``, so it
    # has to be *set on* a handler. Putting it directly in ``.handlers`` type-checks only
    # under a ``type: ignore`` and then fails at the first log line, because ``logging``
    # calls ``.level`` and ``.handle()`` on whatever it finds there.
    bridge = logging.StreamHandler()
    bridge.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            #: Foreign records have not been through the structlog chain, so they get it
            #: here -- redaction included.
            foreign_pre_chain=shared,
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                renderer,
            ],
        )
    )
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "docker", "botocore"):
        stdlib = logging.getLogger(name)
        stdlib.handlers = [bridge]
        stdlib.propagate = False

    root = logging.getLogger()
    root.setLevel(getattr(logging, settings.otel.log_level))
    root.handlers = [logging.NullHandler()]

    if settings.environment != "production":
        # The console still sees sqlalchemy echo if explicitly enabled.
        logging.getLogger("sqlalchemy.engine").setLevel(
            logging.DEBUG if settings.db.echo else logging.WARNING
        )


__all__ = [
    "REDACTED",
    "RedactProcessor",
    "configure_logging",
    "redact_mapping",
    "redact_text",
]
