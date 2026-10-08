"""GitHub security-alert ingestion contracts."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.core.errors import IntegrationError
from app.integrations.github import GitHubClient


class _GitHubTransport:
    def __init__(self) -> None:
        self.requests: list[tuple[str, dict[str, str] | None, dict[str, int] | None]] = []

    async def get_json(self, path: str, *, headers=None, params=None, **_kwargs):
        self.requests.append((path, headers, params))
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
        (
            "/orgs/acme/dependabot/alerts",
            {
                "Authorization": "Bearer ghp_test_token",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            {"per_page": 100, "page": 1},
        ),
        (
            "/orgs/acme/code-scanning/alerts",
            {
                "Authorization": "Bearer ghp_test_token",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            {"per_page": 100, "page": 1},
        ),
        (
            "/orgs/acme/secret-scanning/alerts",
            {
                "Authorization": "Bearer ghp_test_token",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            {"per_page": 100, "page": 1},
        ),
    ]


@pytest.mark.asyncio
async def test_github_reads_following_pages_before_reporting_a_complete_feed(monkeypatch) -> None:
    class _Paged:
        def __init__(self) -> None:
            self.pages: list[tuple[str, int]] = []

        async def get_json(self, path: str, *, headers=None, params=None):
            self.pages.append((path, params["page"]))
            if "dependabot" in path:
                return (
                    [{"number": i, "state": "open"} for i in range(100)]
                    if params["page"] == 1
                    else [{"number": 100, "state": "open"}]
                )
            return []

    transport = _Paged()
    monkeypatch.setattr("app.integrations.github.build_client", lambda **_kwargs: transport)
    client = GitHubClient(Settings(github={"api_token": "token", "organization": "acme"}))
    feeds = await client.list_security_alerts()
    assert len(feeds[0].alerts) == 101
    assert transport.pages[:2] == [
        ("/orgs/acme/dependabot/alerts", 1),
        ("/orgs/acme/dependabot/alerts", 2),
    ]


@pytest.mark.asyncio
async def test_github_rejects_malformed_feed_instead_of_treating_it_as_empty(monkeypatch) -> None:
    class _Malformed:
        async def get_json(self, path: str, *, headers=None, params=None):
            return {"unexpected": "shape"}

    monkeypatch.setattr("app.integrations.github.build_client", lambda **_kwargs: _Malformed())
    client = GitHubClient(Settings(github={"api_token": "token", "organization": "acme"}))
    with pytest.raises(IntegrationError):
        await client.list_security_alerts()
