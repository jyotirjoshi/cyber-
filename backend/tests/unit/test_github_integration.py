"""GitHub security-alert ingestion contracts."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.integrations.github import GitHubClient


class _GitHubTransport:
    def __init__(self) -> None:
        self.requests: list[tuple[str, dict[str, str] | None]] = []

    async def get_json(self, path: str, *, headers=None, **_kwargs):
        self.requests.append((path, headers))
        responses = {
            "/user": {"login": "cynux-bot"},
            "/orgs/acme/dependabot/alerts": [{"number": 7, "state": "open"}],
            "/orgs/acme/code-scanning/alerts": [{"number": 8, "state": "open"}],
            "/orgs/acme/secret-scanning/alerts": [{"number": 9, "state": "open"}],
        }
        return responses[path]


@pytest.mark.asyncio
async def test_github_reads_all_three_organization_security_alert_feeds(monkeypatch) -> None:
    """Dropping one feed silently creates a false clean-security posture."""
    transport = _GitHubTransport()
    monkeypatch.setattr("app.integrations.github.build_client", lambda **_kwargs: transport)
    client = GitHubClient(
        Settings(
            github={
                "base_url": "https://api.github.com",
                "api_token": "ghp_test_token",
                "organization": "acme",
            }
        )
    )

    feeds = await client.list_security_alerts()

    assert [feed.kind for feed in feeds] == ["dependabot", "code_scanning", "secret_scanning"]
    assert [feed.alerts[0]["number"] for feed in feeds] == [7, 8, 9]
    assert transport.requests == [
        ("/orgs/acme/dependabot/alerts", {"Authorization": "Bearer ghp_test_token", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}),
        ("/orgs/acme/code-scanning/alerts", {"Authorization": "Bearer ghp_test_token", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}),
        ("/orgs/acme/secret-scanning/alerts", {"Authorization": "Bearer ghp_test_token", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}),
    ]
