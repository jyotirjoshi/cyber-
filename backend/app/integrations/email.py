"""SMTP email notifications (FR-029).

Email is the fallback notification channel and the one most likely to be misconfigured, so
this module is deliberately strict about two things.

**Failures are visible.**  A ``send`` that cannot connect raises.  Notification delivery is
recorded per recipient in ``notifications`` with a status, so the operator can see that the
critical-finding alert was generated and that SMTP refused it.  Swallowing the error would
leave a row saying ``sent`` for a message nobody received.

**Recipients are validated before the connection opens.**  ``aiosmtplib`` will happily
attempt a send with a malformed address and fail somewhere inside the SMTP dialogue, which
produces an error naming the server rather than the address.  :func:`valid_address` catches it
first, and an all-invalid recipient list is a user error, not an integration failure.

The HTML body is built by the notification service from templates, and the plain-text
alternative is generated from it when not supplied -- a security alert that renders as blank
in a text-only client is a delivered message that failed to communicate.
"""

from __future__ import annotations

import contextlib
import re
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, parseaddr
from html import unescape
from typing import Any

import structlog

from app.core.config import Settings
from app.core.errors import (
    IntegrationAuthError,
    IntegrationError,
    IntegrationNotConfiguredError,
    IntegrationTimeoutError,
    UserError,
)
from app.integrations.http import reveal

logger = structlog.get_logger(__name__)

PROVIDER = "Email"

#: Deliberately permissive: this rejects obvious nonsense (no ``@``, spaces, a missing dot in
#: the domain) rather than attempting RFC 5322, which permits addresses no mail server in
#: practice accepts and would reject valid ones if implemented from memory.
_ADDRESS_RE = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[A-Za-z]{2,}$")

_TAG_RE = re.compile(r"<[^>]+>")
_BLOCK_END_RE = re.compile(r"(?i)</(p|div|tr|h[1-6]|li|table|section)>")
_BR_RE = re.compile(r"(?i)<br\s*/?>")
_DROP_ELEMENT_RE = re.compile(r"(?is)<(script|style|head)\b.*?</\1>")


def valid_address(address: str) -> bool:
    _, email_part = parseaddr(address or "")
    return bool(_ADDRESS_RE.match(email_part))


def html_to_text(html: str) -> str:
    """A readable plain-text alternative for an HTML body.

    Not a general converter -- it handles the structure Cynux's own templates emit. Block
    ends become newlines so a findings table does not collapse into one paragraph, and
    ``<script>``/``<style>`` contents are dropped rather than rendered as text.
    """
    text = _DROP_ELEMENT_RE.sub(" ", html or "")
    text = _BR_RE.sub("\n", text)
    text = _BLOCK_END_RE.sub("\n", text)
    text = _TAG_RE.sub("", text)
    text = unescape(text)
    lines = [line.strip() for line in text.splitlines()]
    #: Collapse runs of blank lines, which the tag stripping produces plenty of.
    out: list[str] = []
    for line in lines:
        if line or (out and out[-1]):
            out.append(line)
    return "\n".join(out).strip()


@dataclass(frozen=True, slots=True)
class SentEmail:
    recipients: list[str]
    subject: str
    #: SMTP's own message identifier where the server returned one. Useful when someone asks
    #: an administrator to trace a message through the mail logs.
    message_id: str | None = None


class EmailSender:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._cfg = settings.notify

    @property
    def configured(self) -> bool:
        return bool(self._cfg.email_configured)

    @property
    def from_address(self) -> str:
        return self._cfg.smtp_from or ""

    def _require(self) -> None:
        if not self.configured:
            raise IntegrationNotConfiguredError(
                PROVIDER,
                hint="Set CYNUX_NOTIFY__SMTP_HOST and CYNUX_NOTIFY__SMTP_FROM.",
            )

    def _build(
        self,
        *,
        to: list[str],
        subject: str,
        html: str,
        text: str | None,
        reply_to: str | None,
    ) -> EmailMessage:
        message = EmailMessage()
        message["From"] = formataddr(("Cynux Security", self.from_address))
        message["To"] = ", ".join(to)
        #: Newlines in a header are header injection: an attacker-influenced subject could
        #: otherwise append a ``Bcc:``. Finding titles reach subjects, so this is not
        #: hypothetical.
        message["Subject"] = re.sub(r"[\r\n]+", " ", subject)[:250]
        if reply_to and valid_address(reply_to):
            message["Reply-To"] = reply_to
        #: Marks the message as machine-generated so mail systems do not send vacation
        #: auto-replies back to Cynux's from address.
        message["Auto-Submitted"] = "auto-generated"

        message.set_content(text or html_to_text(html))
        message.add_alternative(html, subtype="html")
        return message

    async def send(
        self,
        to: str | list[str],
        subject: str,
        html: str,
        text: str | None = None,
        *,
        reply_to: str | None = None,
    ) -> SentEmail:
        """Deliver one message. Raises on any delivery failure."""
        self._require()

        requested = [to] if isinstance(to, str) else list(to)
        recipients = [address for address in requested if valid_address(address)]
        rejected = [address for address in requested if address not in recipients]
        if rejected:
            logger.warning("email.invalid_recipients", count=len(rejected))
        if not recipients:
            raise UserError(
                "No valid email recipients were supplied.",
                user_message="That notification has no valid email recipients.",
                context={"requested": len(requested)},
            )

        message = self._build(
            to=recipients, subject=subject, html=html, text=text, reply_to=reply_to
        )

        try:
            import aiosmtplib
        except ImportError as exc:  # pragma: no cover - dependency is pinned
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="The aiosmtplib package is not installed."
            ) from exc

        kwargs: dict[str, Any] = {
            "hostname": self._cfg.smtp_host,
            "port": self._cfg.smtp_port,
            "timeout": 30,
        }
        if self._cfg.smtp_username:
            kwargs["username"] = self._cfg.smtp_username
            kwargs["password"] = reveal(self._cfg.smtp_password)

        if self._cfg.smtp_use_tls:
            #: Port 465 is implicit TLS; 587 and everything else is STARTTLS. Getting this
            #: backwards produces a hang rather than an error, so it is decided from the
            #: port rather than left to the library's guess.
            if self._cfg.smtp_port == 465:
                kwargs["use_tls"] = True
            else:
                kwargs["start_tls"] = True
            kwargs["tls_context"] = ssl.create_default_context()

        try:
            errors, response = await aiosmtplib.send(message, **kwargs)
        except aiosmtplib.SMTPAuthenticationError as exc:
            raise IntegrationAuthError(
                PROVIDER, context={"host": self._cfg.smtp_host}, cause=exc
            ) from exc
        except TimeoutError as exc:
            raise IntegrationTimeoutError(
                "The SMTP server did not respond in time.",
                provider=PROVIDER,
                context={"host": self._cfg.smtp_host},
                cause=exc,
            ) from exc
        except aiosmtplib.SMTPException as exc:
            #: The exception text can contain the server's greeting banner. It goes to the
            #: log, never to ``user_message`` (SEC-002).
            logger.warning("email.send_failed", host=self._cfg.smtp_host, error=type(exc).__name__)
            raise IntegrationError(
                "The SMTP server refused the message.",
                provider=PROVIDER,
                context={"host": self._cfg.smtp_host, "error": type(exc).__name__},
                cause=exc,
            ) from exc

        if errors:
            #: aiosmtplib returns per-recipient refusals without raising. A partial delivery
            #: reported as success would leave someone unnotified with a green status.
            raise IntegrationError(
                f"The SMTP server rejected {len(errors)} of {len(recipients)} recipient(s).",
                provider=PROVIDER,
                context={"rejected_count": len(errors)},
            )

        logger.info("email.sent", recipients=len(recipients), subject=message["Subject"])
        return SentEmail(
            recipients=recipients,
            subject=str(message["Subject"]),
            message_id=str(response) if response else None,
        )

    async def ping(self) -> bool:
        """Open an SMTP session and authenticate without sending anything."""
        self._require()
        try:
            import aiosmtplib
        except ImportError as exc:  # pragma: no cover
            raise IntegrationNotConfiguredError(PROVIDER) from exc

        client = aiosmtplib.SMTP(
            hostname=self._cfg.smtp_host,
            port=self._cfg.smtp_port,
            timeout=15,
            use_tls=self._cfg.smtp_use_tls and self._cfg.smtp_port == 465,
        )
        try:
            await client.connect()
            if self._cfg.smtp_use_tls and self._cfg.smtp_port != 465:
                await client.starttls(tls_context=ssl.create_default_context())
            if self._cfg.smtp_username:
                await client.login(self._cfg.smtp_username, reveal(self._cfg.smtp_password))
            return True
        except aiosmtplib.SMTPAuthenticationError as exc:
            raise IntegrationAuthError(PROVIDER, cause=exc) from exc
        except (aiosmtplib.SMTPException, OSError) as exc:
            raise IntegrationError(
                "Could not open an SMTP session.",
                provider=PROVIDER,
                context={"host": self._cfg.smtp_host, "error": type(exc).__name__},
                cause=exc,
            ) from exc
        finally:
            #: A failed ``QUIT`` on a session we are abandoning tells us nothing we do not
            #: already know from the exception on the way out.
            with contextlib.suppress(Exception):
                await client.quit()


__all__ = ["PROVIDER", "EmailSender", "SentEmail", "html_to_text", "valid_address"]
