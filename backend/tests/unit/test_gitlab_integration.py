"""GitLab security-alert ingestion contracts."""

import pytest

from app.core.config import Settings
from app.db.enums import IntegrationKind
from app.integrations.gitlab import GitLabClient
from app.services.integration import _UNIMPLEMENTED


class _GitLabTransport:
    def __init__(self) -> None:
        self.requests = []

    async def get_json(self, path, *, headers=None, params=None, **_kwargs):
        self.requests.append((path, headers, params))
        return {"username": "cynux-bot"} if path == "/user" else [{"id": 11, "name": "SAST"}]


@pytest.mark.asyncio
async def test_gitlab_reads_security_findings_for_configured_projects(monkeypatch) -> None:
    transport = _GitLabTransport()
    monkeypatch.setattr("app.integrations.gitlab.build_client", lambda **_kwargs: transport)
    client = GitLabClient(
        Settings(gitlab={"api_token": "glpat_test", "project_ids": ["acme/api platform"]})
    )

    feeds = await client.list_security_alerts()

    assert feeds[0].project == "acme/api platform"
    assert feeds[0].alerts == [{"id": 11, "name": "SAST"}]
    assert transport.requests == [
        ("/projects/acme%2Fapi%20platform/vulnerability_findings", {"PRIVATE-TOKEN": "glpat_test"}, {"scope": "all", "per_page": 100})
    ]


def test_gitlab_is_enabled_as_a_configurable_connector() -> None:
    assert IntegrationKind.GITLAB not in _UNIMPLEMENTED
