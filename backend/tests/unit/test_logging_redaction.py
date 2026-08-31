"""SEC-002: credentials must never be logged.

The assertion style here is the point of the file.  Every must-redact case checks that
**the secret substring is absent from the output**, not that ``[REDACTED]`` is present
somewhere in it.  The weaker assertion is what let a real bug through during
development: ``Authorization: Bearer <jwt>`` was rewritten to
``Authorization: [REDACTED] eyJhbGciOi...`` because the pattern consumed ``Bearer`` as
the value.  ``[REDACTED]`` appeared, the test would have passed, and the JWT was still
in the log -- worse than no redaction at all, because the line reads as safe.

The must-keep cases matter equally.  Redaction that eats ``monkey=1`` because it
contains ``key`` makes logs useless, and a useless log gets turned off.
"""

from __future__ import annotations

import io
import logging

import pytest

from app.core.logging_conf import REDACTED, RedactProcessor, configure_logging, redact_text

# ---------------------------------------------------------------------------
# Value-level redaction (secrets in the message body)
# ---------------------------------------------------------------------------

#: ``(text, secret_that_must_not_survive)``.
MUST_REDACT: list[tuple[str, str]] = [
    # The uvicorn access-log shape -- the reason value-level redaction exists at all.
    ("GET /api/v1/assessments?api_key=SUPERSECRET123 HTTP/1.1", "SUPERSECRET123"),
    ("POST /login?password=hunter2trombone", "hunter2trombone"),
    ("GET /x?access_token=ya29.AbCdEfGhIjK", "ya29.AbCdEfGhIjK"),
    # Header-shaped, with and without a scheme.
    ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature", "eyJhbGciOiJIUzI1NiJ9"),
    ("authorization: Basic YWRtaW46cGFzc3dvcmQ=", "YWRtaW46cGFzc3dvcmQ="),
    ("Bearer eyJ0eXAiOiJKV1QifQ.abc.def", "eyJ0eXAiOiJKV1QifQ"),
    # Config dumps and driver errors.
    ("defectdojo_api_token=abc123def456ghi", "abc123def456ghi"),
    ("client_secret: s3cr3t-oauth-value", "s3cr3t-oauth-value"),
    ("CYNUX_SECURITY__JWT_SECRET=super-long-signing-value", "super-long-signing-value"),
    # DSNs. These reach logs through connection errors, which is exactly when a
    # developer is reading them and copy-pasting them into a ticket.
    ("could not connect: postgresql://cynux:pgpassword123@db:5432/cynux", "pgpassword123"),
    # Empty username is the ordinary Redis URL form, and Cynux's own DSN uses it.
    ("redis://:r3d1sp4ss@redis:6379/0", "r3d1sp4ss"),
]

#: Text that must survive untouched. Over-redaction is a real failure mode.
MUST_KEEP: list[str] = [
    "monkey=1",
    "keyboard=qwerty",
    "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-3094",
    "https://github.com/cynux/app.git",
    "nuclei -l /work/targets.txt -severity critical,high -jsonl-export /work/out/nuclei.jsonl",
    "assessment_id=8f14e45f-ce9a-4b1e-9c3a-1d2e3f4a5b6c status=awaiting_approval",
    "turkey and monkeys ate the donkey",
]


@pytest.mark.parametrize(("text", "secret"), MUST_REDACT, ids=[t[:34] for t, _ in MUST_REDACT])
def test_secret_value_does_not_survive_redaction(text: str, secret: str) -> None:
    out = redact_text(text)
    assert secret not in out, f"secret survived redaction: {out!r}"
    assert REDACTED in out, f"nothing was redacted, so the secret was never seen: {out!r}"


@pytest.mark.parametrize("text", MUST_KEEP, ids=[t[:34] for t in MUST_KEEP])
def test_innocent_text_is_left_alone(text: str) -> None:
    assert redact_text(text) == text


def test_redaction_keeps_the_line_readable() -> None:
    """A redacted line must still identify the request, or it is not a log line."""
    out = redact_text("GET /api/v1/assessments?api_key=SUPERSECRET123&limit=50 HTTP/1.1")
    assert "/api/v1/assessments" in out
    assert "limit=50" in out
    assert "SUPERSECRET123" not in out


def test_empty_and_hintless_text_is_returned_unchanged() -> None:
    assert redact_text("") == ""
    assert redact_text("scan complete: 12 findings") == "scan complete: 12 findings"


# ---------------------------------------------------------------------------
# Key-level redaction (secrets in structlog fields)
# ---------------------------------------------------------------------------


def test_secret_bearing_keys_are_replaced_wholesale() -> None:
    out = RedactProcessor()(
        None,
        "info",
        {
            "event": "integration.configured",
            "api_key": "abc123",
            "jwt_secret": "signing-value",
            "password": "hunter2",
            "authorization": "Bearer xyz",
            "cookie": "session=1",
            "provider": "defectdojo",
        },
    )
    for field in ("api_key", "jwt_secret", "password", "authorization", "cookie"):
        assert out[field] == REDACTED
    assert out["provider"] == "defectdojo"
    assert out["event"] == "integration.configured"


def test_redaction_reaches_into_nested_structures() -> None:
    """Integration config is logged as a dict; a secret one level down still leaks."""
    out = RedactProcessor()(
        None,
        "info",
        {
            "event": "integration.sync",
            "config": {
                "url": "https://dojo.example.com",
                "api_token": "nested-secret",
                "nested": {"client_secret": "deeper-secret"},
            },
            "endpoints": ["https://a.example.com?token=in-a-list"],
        },
    )
    config = out["config"]
    assert isinstance(config, dict)
    assert config["api_token"] == REDACTED
    assert config["url"] == "https://dojo.example.com"
    assert config["nested"]["client_secret"] == REDACTED
    assert "in-a-list" not in str(out["endpoints"])


def test_innocent_key_with_guilty_value_is_still_redacted() -> None:
    """The regression this file was written for.

    ``RedactProcessor`` scrubs by key name; the key here is ``event``, which is
    innocent, and the secret is in the value. Key-based scrubbing alone missed it.
    """
    out = RedactProcessor()(
        None,
        "info",
        {"event": "GET /api/v1/assessments?api_key=SUPERSECRET123"},
    )
    assert "SUPERSECRET123" not in str(out["event"])


def test_non_string_values_pass_through_with_their_types() -> None:
    """Redaction must not stringify ints and bools, or JSON logs lose their schema."""
    out = RedactProcessor()(
        None, "info", {"event": "job.done", "exit_code": 0, "timed_out": False, "duration": 12.5}
    )
    assert out["exit_code"] == 0
    assert out["timed_out"] is False
    assert out["duration"] == 12.5


# ---------------------------------------------------------------------------
# The stdlib bridge
# ---------------------------------------------------------------------------


def test_stdlib_bridge_is_a_working_handler(settings) -> None:
    """``configure_logging`` must produce handlers that ``logging`` can actually use.

    ``ProcessorFormatter`` is a ``logging.Formatter``, not a ``logging.Handler``.
    Assigning it straight into ``logger.handlers`` type-checks under an ignore and then
    dies on the first uvicorn log line, when ``logging`` calls ``.handle()`` on it. This
    asserts the shape rather than trusting it.
    """
    configure_logging(settings)
    for name in ("uvicorn", "uvicorn.access", "docker", "botocore"):
        handlers = logging.getLogger(name).handlers
        assert handlers, f"{name} was left with no handler"
        for handler in handlers:
            assert isinstance(handler, logging.Handler), f"{name} got a {type(handler).__name__}"


def test_uvicorn_access_log_is_redacted_end_to_end(settings) -> None:
    """The whole point, exercised through ``logging`` rather than through the helper.

    Redaction that works when called directly but is not wired into the uvicorn logger
    protects nothing: the access log is the single most likely place for a token in a
    query string to be written to disk.
    """
    configure_logging(settings)
    access = logging.getLogger("uvicorn.access")
    stream = io.StringIO()

    original = access.handlers
    captured = logging.StreamHandler(stream)
    captured.setFormatter(original[0].formatter)
    access.handlers = [captured]
    try:
        access.info('127.0.0.1:1 - "GET /api/v1/assessments?api_key=LEAKED_TOKEN_9 HTTP/1.1" 200')
    finally:
        access.handlers = original

    written = stream.getvalue()
    assert written, "nothing was emitted, so the assertion below would pass vacuously"
    assert "LEAKED_TOKEN_9" not in written
    assert "/api/v1/assessments" in written
