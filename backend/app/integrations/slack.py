"""Slack notifications (FR-029).

Two transports, chosen by what the operator configured.  A bot token reaches
``chat.postMessage`` and can post to any channel the bot is in; an incoming webhook posts to
exactly the one channel it was created for.  Most deployments have one or the other, so
:meth:`SlackClient.notify` picks whichever is available rather than making every caller ask.

Slack's API has a habit that this module has to handle explicitly: ``chat.postMessage``
answers **HTTP 200 with ``{"ok": false, "error": "..."}``** for application-level failures
like ``channel_not_found`` or ``invalid_auth``.  The HTTP spine sees a 200 and reports
success, so :meth:`SlackClient._check` inspects the envelope and raises.  Without that, a
notification to a mistyped channel would be silently dropped -- and a security alert nobody
receives is worse than one that visibly failed, because nobody investigates.

Message text is built from findings, which are untrusted.  A finding title can contain
Slack's ``<@U123>`` mention syntax or a ``<http://...|click me>`` link, so
:func:`escape_slack` neutralizes the three characters that make those work before any
finding-derived text reaches a message.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import structlog

from app.core.config import Settings
from app.core.errors import (
    IntegrationAuthError,
    IntegrationError,
    IntegrationNotConfiguredError,
    IntegrationRateLimitError,
)
from app.db.enums import Severity
from app.integrations.circuit import BreakerConfig
from app.integrations.http import ResilientClient, RetryPolicy, build_client, reveal

if TYPE_CHECKING:
    from redis.asyncio import Redis

logger = structlog.get_logger(__name__)

PROVIDER = "Slack"

_SLACK_API = "https://slack.com"

#: Slack errors that mean the configuration is wrong, not that Slack is unwell. These become
#: auth errors so the circuit breaker's failure count and the operator's error message both
#: say the right thing.
_CONFIG_ERRORS = frozenset(
    {
        "invalid_auth",
        "not_authed",
        "account_inactive",
        "token_revoked",
        "token_expired",
        "missing_scope",
        "channel_not_found",
        "not_in_channel",
        "is_archived",
        "invalid_arguments",
        "no_permission",
    }
)

#: Slack renders these next to a message. Severity to emoji, so an on-call engineer can
#: triage a channel by glance.
_SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: ":rotating_light:",
    Severity.HIGH: ":red_circle:",
    Severity.MEDIUM: ":large_orange_circle:",
    Severity.LOW: ":large_yellow_circle:",
    Severity.INFO: ":information_source:",
}


def escape_slack(text: str) -> str:
    """Neutralize Slack's control characters in untrusted text (SEC-005).

    Slack parses ``<``, ``>`` and ``&`` to build links and mentions. A finding title of
    ``<!channel> urgent`` would otherwise notify an entire workspace on an attacker's
    say-so, because finding titles come from scanner output.
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


@dataclass(frozen=True, slots=True)
class SlackMessage:
    channel: str
    ts: str = ""
    #: Absent for webhook posts: an incoming webhook returns the string ``ok`` and no
    #: metadata, so there is no permalink to record.
    permalink: str | None = None


def severity_emoji(severity: Severity) -> str:
    return _SEVERITY_EMOJI.get(severity, ":white_circle:")


def section(text: str) -> dict[str, Any]:
    """A ``mrkdwn`` section block, truncated to Slack's per-block limit."""
    return {"type": "section", "text": {"type": "mrkdwn", "text": text[:3000]}}


def context_line(text: str) -> dict[str, Any]:
    return {"type": "context", "elements": [{"type": "mrkdwn", "text": text[:3000]}]}


def link_button(label: str, url: str) -> dict[str, Any]:
    return {
        "type": "actions",
        "elements": [
            {
                "type": "button",
                "text": {"type": "plain_text", "text": label[:75]},
                "url": url,
                "style": "primary",
            }
        ],
    }


class SlackClient:
    def __init__(self, settings: Settings, redis: Redis | None = None) -> None:
        self.settings = settings
        self._cfg = settings.notify
        self._redis = redis
        self._api: ResilientClient | None = None
        self._hook: ResilientClient | None = None

    @property
    def configured(self) -> bool:
        return bool(self._cfg.slack_configured)

    @property
    def has_bot_token(self) -> bool:
        return bool(self._cfg.slack_bot_token)

    @property
    def has_webhook(self) -> bool:
        return bool(self._cfg.slack_webhook_url)

    @property
    def default_channel(self) -> str | None:
        return self._cfg.slack_default_channel

    def _require_api(self) -> ResilientClient:
        if not self.has_bot_token:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set CYNUX_NOTIFY__SLACK_BOT_TOKEN to post to a channel."
            )
        if self._api is None:
            self._api = build_client(
                provider=PROVIDER,
                base_url=_SLACK_API,
                settings=self.settings,
                redis=self._redis,
                headers={
                    "Authorization": f"Bearer {reveal(self._cfg.slack_bot_token)}",
                    #: Slack requires the charset on this endpoint or it rejects the body.
                    "Content-Type": "application/json; charset=utf-8",
                },
                timeout=20.0,
                retry=RetryPolicy(max_attempts=3, backoff_base=0.5),
                breaker_config=BreakerConfig(failure_threshold=5, cooldown_seconds=90),
            )
        return self._api

    def _require_hook(self) -> ResilientClient:
        if not self.has_webhook:
            raise IntegrationNotConfiguredError(
                PROVIDER, hint="Set CYNUX_NOTIFY__SLACK_WEBHOOK_URL."
            )
        if self._hook is None:
            #: The whole webhook URL is the credential, so it is the base URL and the path
            #: is empty. It must never appear in a log line -- hence provider-only logging
            #: everywhere in this class.
            self._hook = build_client(
                provider=f"{PROVIDER} webhook",
                base_url=reveal(self._cfg.slack_webhook_url),
                settings=self.settings,
                redis=self._redis,
                headers={"Content-Type": "application/json"},
                timeout=20.0,
                retry=RetryPolicy(max_attempts=3, backoff_base=0.5),
                breaker_config=BreakerConfig(failure_threshold=5, cooldown_seconds=90),
            )
        return self._hook

    async def aclose(self) -> None:
        for client in (self._api, self._hook):
            if client is not None:
                await client.aclose()
        self._api = None
        self._hook = None

    # -- envelope checking ---------------------------------------------------

    def _check(self, payload: Any, *, operation: str) -> dict[str, Any]:
        """Raise on Slack's HTTP-200-with-``ok: false`` failures.

        See the module docstring. The Slack error code is safe to surface -- it names a
        configuration problem, never a secret.
        """
        if not isinstance(payload, dict):
            raise IntegrationError(
                "Slack returned an unexpected response shape.",
                provider=PROVIDER,
                context={"operation": operation},
            )
        if payload.get("ok"):
            return payload

        error = str(payload.get("error") or "unknown_error")
        context = {"operation": operation, "slack_error": error}
        if error == "ratelimited":
            raise IntegrationRateLimitError(PROVIDER, context=context)
        if error in _CONFIG_ERRORS:
            raise IntegrationAuthError(
                PROVIDER,
                user_message=(
                    f"Slack rejected the notification ({error}). Check the bot token, "
                    "its scopes, and that the bot has been invited to the channel."
                ),
                context=context,
            )
        raise IntegrationError(
            f"Slack refused the request: {error}.", provider=PROVIDER, context=context
        )

    # -- posting -------------------------------------------------------------

    async def post_message(
        self,
        channel: str,
        text: str,
        blocks: list[dict[str, Any]] | None = None,
        *,
        thread_ts: str | None = None,
    ) -> SlackMessage:
        """Post via ``chat.postMessage``. Requires a bot token."""
        body: dict[str, Any] = {
            "channel": channel,
            #: ``text`` is required even when blocks are supplied: it is what Slack shows in
            #: the notification preview and in clients that cannot render blocks.
            "text": text[:3000],
        }
        if blocks:
            body["blocks"] = blocks[:50]
        if thread_ts:
            body["thread_ts"] = thread_ts

        payload = self._check(
            await self._require_api().post_json("/api/chat.postMessage", json=body),
            operation="chat.postMessage",
        )
        logger.info("slack.message_posted", channel=channel, threaded=bool(thread_ts))
        return SlackMessage(
            channel=str(payload.get("channel") or channel), ts=str(payload.get("ts") or "")
        )

    async def post_webhook(
        self, text: str, blocks: list[dict[str, Any]] | None = None
    ) -> SlackMessage:
        """Post via an incoming webhook.

        A webhook answers with the literal body ``ok`` rather than JSON, so there is no
        envelope to check -- the HTTP status is the entire signal.
        """
        body: dict[str, Any] = {"text": text[:3000]}
        if blocks:
            body["blocks"] = blocks[:50]
        await self._require_hook().request("POST", "", json=body)
        logger.info("slack.webhook_posted")
        return SlackMessage(channel="(webhook)")

    async def notify(
        self,
        text: str,
        *,
        channel: str | None = None,
        blocks: list[dict[str, Any]] | None = None,
    ) -> SlackMessage:
        """Send by whichever transport is configured.

        Prefers the bot token: it can address a channel, which the notification service needs
        in order to route a critical finding somewhere different from a routine completion.
        """
        target = channel or self.default_channel
        if self.has_bot_token and target:
            return await self.post_message(target, text, blocks)
        if self.has_webhook:
            if channel:
                #: Worth saying out loud. An operator who configured a per-event channel and
                #: only has a webhook would otherwise wonder why everything lands in one
                #: place.
                logger.info("slack.webhook_ignores_channel", requested_channel=channel)
            return await self.post_webhook(text, blocks)
        raise IntegrationNotConfiguredError(
            PROVIDER,
            hint=(
                "Set CYNUX_NOTIFY__SLACK_BOT_TOKEN with CYNUX_NOTIFY__SLACK_DEFAULT_CHANNEL, "
                "or CYNUX_NOTIFY__SLACK_WEBHOOK_URL."
            ),
        )

    async def ping(self) -> bool:
        if self.has_bot_token:
            self._check(
                await self._require_api().post_json("/api/auth.test", json={}),
                operation="auth.test",
            )
            return True
        if self.has_webhook:
            #: There is no way to validate a webhook without posting, and posting a test
            #: message into a real channel on every health check would be rude. Report it as
            #: configured-but-unverified instead; ``IntegrationStatus.UNVERIFIED`` exists
            #: precisely for this.
            return False
        raise IntegrationNotConfiguredError(PROVIDER)


__all__ = [
    "PROVIDER",
    "SlackClient",
    "SlackMessage",
    "context_line",
    "escape_slack",
    "link_button",
    "section",
    "severity_emoji",
]
