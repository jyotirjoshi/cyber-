"""PagerDuty Events API boundary contracts."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from app.db.enums import Severity


@pytest.mark.asyncio
async def test_trigger_uses_stable_deduplication_and_event_payload() -> None:
    """A regression must not create duplicate incidents or omit incident severity."""
    from app.integrations.pagerduty import PagerDutyClient

    settings = SimpleNamespace(
        pagerduty=SimpleNamespace(
            configured=True,
            base_url="https://events.pagerduty.example",
            routing_key=SecretStr("routing-secret"),
            source="Cynux production",
        )
    )
    client = PagerDutyClient(settings)
    requests: list[tuple[str, dict[str, object], str | None]] = []

    class Http:
        async def post_json(self, path, **kwargs):
            requests.append((path, kwargs["json"], kwargs.get("idempotency_key")))
            return {"status": "success", "message": "Event processed", "dedup_key": "cf-42"}

    client._client = Http()
    result = await client.trigger(
        summary="Critical production exposure",
        body="A public endpoint exposes credentials.",
        severity=Severity.CRITICAL,
        dedup_key="cf-42",
        link="https://cynux.example/findings/cf-42",
    )

    assert result.dedup_key == "cf-42"
    assert requests == [
        (
            "/v2/enqueue",
            {
                "routing_key": "routing-secret",
                "event_action": "trigger",
                "dedup_key": "cf-42",
                "payload": {
                    "summary": "Critical production exposure",
                    "source": "Cynux production",
                    "severity": "critical",
                    "custom_details": {
                        "body": "A public endpoint exposes credentials.",
                        "link": "https://cynux.example/findings/cf-42",
                    },
                },
            },
            "cf-42",
        )
    ]
