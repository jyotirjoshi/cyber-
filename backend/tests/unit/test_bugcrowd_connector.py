"""Bugcrowd submissions connector contracts."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.integrations.bugcrowd import BugcrowdClient
from app.services.external_alert import normalize_bugcrowd_submission


def _settings() -> Settings:
    return Settings(
        bugcrowd={
            "token_username": "user",
            "token_password": "secret",
            "engagement_codes": ["acme-web"],
        }
    )


@pytest.mark.asyncio
async def test_bugcrowd_reads_paginated_engagement_snapshot_with_targets(monkeypatch) -> None:
    calls = []

    class _Client:
        async def get_json(self, path, **kwargs):
            calls.append((path, kwargs))
            return {
                "data": [_submission()],
                "included": [{"type": "target", "id": "target-1", "attributes": {"name": "https://api.example.com"}}],
                "links": {"next": None},
            }

        async def aclose(self): return None

    monkeypatch.setattr("app.integrations.bugcrowd.build_client", lambda **_kwargs: _Client())
    rows = await BugcrowdClient(_settings()).list_submissions()
    assert rows[0]["engagement_code"] == "acme-web"
    assert rows[0]["target"]["attributes"]["name"] == "https://api.example.com"
    assert calls[0][1]["params"]["filter[engagement]"] == "acme-web"
    assert calls[0][1]["headers"]["Authorization"] == "Token user:secret"


def test_bugcrowd_normalizes_target_state_and_priority() -> None:
    normalized = normalize_bugcrowd_submission(
        {"submission": _submission(), "target": {"id": "target-1", "type": "target", "attributes": {"name": "https://api.example.com"}}, "engagement_code": "acme-web"}
    )
    assert normalized.resource == "https://api.example.com/"
    assert normalized.severity == "high"
    assert normalized.status == "open"
    assert normalized.evidence["engagement_code"] == "acme-web"


def _submission():
    return {
        "type": "submission", "id": "54239bf3-59c2-45d3-b3c6-77414b24422e",
        "attributes": {"title": "Authorization bypass", "state": "unresolved", "severity": 2, "duplicate": False},
        "relationships": {"target": {"data": {"type": "target", "id": "target-1"}}},
    }
