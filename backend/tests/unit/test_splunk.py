"""Splunk HTTP Event Collector boundary contracts."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from app.db.enums import NotificationEvent, Severity


@pytest.mark.asyncio
async def test_hec_event_preserves_security_context_and_delivery_identity() -> None:
    """A regression must not flatten the event or lose its durable dedupe identity."""
    from app.integrations.splunk import SplunkHecClient

    settings = SimpleNamespace(
        splunk=SimpleNamespace(
            configured=True,
            base_url="https://splunk.example:8088",
            hec_token=SecretStr("hec-secret"),
            index="security",
            source="cynux",
            sourcetype="cynux:notification",
            host="cynux-worker",
        )
    )
    client = SplunkHecClient(settings)
    requests: list[tuple[str, dict[str, object], str | None]] = []

    class Http:
        async def post_json(self, path, **kwargs):
            requests.append((path, kwargs["json"], kwargs.get("idempotency_key")))
            return {"text": "Success", "code": 0}

    client._client = Http()
    result = await client.emit(
        event=NotificationEvent.CRITICAL_FINDING,
        subject="Critical production exposure",
        body="A public endpoint exposes credentials.",
        severity=Severity.CRITICAL,
        dedupe_key="finding-42:splunk",
        organization_id="org-1",
        resource_type="canonical_finding",
        resource_id="finding-42",
        link="https://cynux.example/findings/finding-42",
    )

    assert result.accepted is True
    assert requests == [
        (
            "/services/collector/event",
            {
                "host": "cynux-worker",
                "index": "security",
                "source": "cynux",
                "sourcetype": "cynux:notification",
                "event": {
                    "schema_version": 1,
                    "event_type": "critical_finding",
                    "organization_id": "org-1",
                    "subject": "Critical production exposure",
                    "body": "A public endpoint exposes credentials.",
                    "severity": "critical",
                    "resource_type": "canonical_finding",
                    "resource_id": "finding-42",
                    "link": "https://cynux.example/findings/finding-42",
                    "dedupe_key": "finding-42:splunk",
                },
            },
            "finding-42:splunk",
        )
    ]


@pytest.mark.asyncio
async def test_hec_health_probe_uses_the_configured_token() -> None:
    from app.integrations.splunk import SplunkHecClient

    settings = SimpleNamespace(
        splunk=SimpleNamespace(
            configured=True,
            base_url="https://splunk.example:8088",
            hec_token=SecretStr("hec-secret"),
            index=None,
            source="cynux",
            sourcetype="cynux:notification",
            host="cynux",
        )
    )
    client = SplunkHecClient(settings)
    paths: list[str] = []

    class Http:
        async def get_json(self, path, **kwargs):
            paths.append(path)
            return {"text": "HEC is healthy", "code": 17}

    client._client = Http()
    assert await client.ping() is True
    assert paths == ["/services/collector/health"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "config",
    [
        {"index": "../../security"},
        {"source": "cynux\nforged"},
        {"sourcetype": "x" * 257},
        {"host": ""},
    ],
)
async def test_splunk_rejects_unsafe_metadata_before_database_write(
    config: dict[str, str],
) -> None:
    import uuid

    from app.core.config import Settings
    from app.core.errors import InvalidConfigurationError
    from app.db.enums import IntegrationKind, Role
    from app.schemas.integration import IntegrationUpsertIn
    from app.services.context import Principal
    from app.services.integration import upsert_integration

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    payload = IntegrationUpsertIn(kind=IntegrationKind.SPLUNK, config=config)

    with pytest.raises(InvalidConfigurationError):
        await upsert_integration(None, principal, payload, settings=Settings())
