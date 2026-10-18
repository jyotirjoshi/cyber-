"""Provider contracts for remediation tickets."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import SecretStr


@pytest.mark.asyncio
async def test_github_issue_creation_uses_repository_and_cynux_finding_label() -> None:
    """The change that would break this is filing an untraceable issue in an arbitrary repository."""
    from app.integrations.github import GitHubClient

    settings = SimpleNamespace(
        github=SimpleNamespace(
            configured=True,
            base_url="https://api.github.example",
            api_token=SecretStr("token"),
            organization="acme",
            repository="portal",
        )
    )
    client = GitHubClient(settings)
    requests: list[tuple[str, object]] = []

    class Http:
        async def get_json(self, path, **kwargs):
            requests.append((path, kwargs.get("params")))
            return []

        async def post_json(self, path, **kwargs):
            requests.append((path, kwargs.get("json")))
            return {
                "number": 42,
                "id": 99,
                "html_url": "https://github.example/acme/portal/issues/42",
                "state": "open",
                "title": "Critical finding",
            }

    client._client = Http()
    issue = await client.create_issue(
        summary="Critical finding",
        description="Reproduce and remediate.",
        finding_id="finding-123",
    )

    assert issue.key == "#42"
    assert issue.id == "99"
    assert issue.status == "open"
    assert requests[0][0] == "/repos/acme/portal/issues"
    assert requests[1] == (
        "/repos/acme/portal/issues",
        {
            "title": "Critical finding",
            "body": "Reproduce and remediate.",
            "labels": ["cynux", "cynux-finding-finding-123"],
        },
    )


@pytest.mark.asyncio
async def test_gitlab_issue_creation_uses_configured_project_and_cynux_label() -> None:
    """The change that would break this is filing into a project outside the tenant's configured scope."""
    from app.integrations.gitlab import GitLabClient

    settings = SimpleNamespace(
        gitlab=SimpleNamespace(
            configured=True,
            base_url="https://gitlab.example/api/v4",
            api_token=SecretStr("token"),
            project_ids=[],
            issue_project="acme/portal",
        )
    )
    client = GitLabClient(settings)
    requests: list[tuple[str, object]] = []

    class Http:
        async def get_json(self, path, **kwargs):
            requests.append((path, kwargs.get("params")))
            return []

        async def post_json(self, path, **kwargs):
            requests.append((path, kwargs.get("json")))
            return {
                "iid": 15,
                "id": 76,
                "web_url": "https://gitlab.example/acme/portal/-/issues/15",
                "state": "opened",
                "title": "Critical finding",
            }

    client._client = Http()
    issue = await client.create_issue(
        summary="Critical finding", description="Reproduce and remediate.", finding_id="finding-123"
    )

    assert issue.key == "#15"
    assert issue.id == "76"
    assert issue.status == "opened"
    assert requests[0][0] == "/projects/acme%2Fportal/issues"
    assert requests[1] == (
        "/projects/acme%2Fportal/issues",
        {
            "title": "Critical finding",
            "description": "Reproduce and remediate.",
            "labels": "cynux,cynux-finding-finding-123",
        },
    )


@pytest.mark.asyncio
async def test_github_ticket_status_is_read_from_same_configured_repository() -> None:
    """The change that would break this is looking up a ticket outside its configured repository."""
    from app.integrations.github import GitHubClient

    settings = SimpleNamespace(
        github=SimpleNamespace(
            configured=True, base_url="https://api.github.example", api_token=SecretStr("token"),
            organization="acme", repository="portal",
        )
    )
    client = GitHubClient(settings)

    class Http:
        async def get_json(self, path, **kwargs):
            assert path == "/repos/acme/portal/issues/42"
            return {"number": 42, "id": 99, "html_url": "https://github.example/acme/portal/issues/42", "state": "closed"}

    client._client = Http()
    issue = await client.get_issue("#42")
    assert issue.status == "closed"


@pytest.mark.asyncio
async def test_servicenow_incident_creation_uses_configured_table_and_finding_correlation() -> None:
    """The change that would break this is creating a duplicate or filing outside the tenant table."""
    from app.integrations.servicenow import ServiceNowClient

    settings = SimpleNamespace(
        servicenow=SimpleNamespace(
            configured=True,
            base_url="https://acme.service-now.example",
            api_token=SecretStr("token"),
            table="incident",
            assignment_group="AppSec",
        )
    )
    client = ServiceNowClient(settings)
    requests: list[tuple[str, object]] = []

    class Http:
        async def get_json(self, path, **kwargs):
            requests.append((path, kwargs.get("params")))
            return {"result": []}

        async def post_json(self, path, **kwargs):
            requests.append((path, kwargs.get("json")))
            return {
                "result": {
                    "sys_id": "sys-42",
                    "number": "INC0010042",
                    "state": "1",
                    "short_description": "Critical finding",
                    "sys_class_name": "incident",
                    "sysparm_link": "https://acme.service-now.example/nav_to.do?uri=incident.do?sys_id=sys-42",
                }
            }

    client._client = Http()
    incident = await client.create_issue(
        summary="Critical finding",
        description="Reproduce and remediate.",
        finding_id="finding-123",
    )

    assert incident.key == "INC0010042"
    assert incident.id == "sys-42"
    assert incident.status == "open"
    assert requests[0] == (
        "/api/now/table/incident",
        {"sysparm_query": "correlation_id=cynux-finding-finding-123", "sysparm_limit": 1},
    )
    assert requests[1] == (
        "/api/now/table/incident",
        {
            "short_description": "Critical finding",
            "description": "Reproduce and remediate.",
            "correlation_id": "cynux-finding-finding-123",
            "assignment_group": "AppSec",
        },
    )


@pytest.mark.asyncio
async def test_azure_devops_work_item_creation_uses_project_scoped_tag_lookup() -> None:
    """The change that would break this is creating a duplicate work item outside the tenant project."""
    from app.integrations.azure_devops import AzureDevOpsClient

    settings = SimpleNamespace(
        azure_devops=SimpleNamespace(
            configured=True,
            base_url="https://dev.azure.example",
            api_token=SecretStr("token"),
            organization="acme",
            project="Security",
            work_item_type="Issue",
        )
    )
    client = AzureDevOpsClient(settings)
    requests: list[tuple[str, object]] = []

    class Http:
        async def post_json(self, path, **kwargs):
            requests.append((path, kwargs.get("json")))
            if "/_apis/wit/wiql?" in path:
                return {"workItems": []}
            return {
                "id": 42,
                "url": "https://dev.azure.example/acme/Security/_apis/wit/workItems/42",
                "fields": {
                    "System.Title": "Critical finding",
                    "System.State": "New",
                    "System.WorkItemType": "Issue",
                },
            }

    client._client = Http()
    issue = await client.create_issue(
        summary="Critical finding", description="Reproduce and remediate.", finding_id="finding-123"
    )

    assert issue.key == "#42"
    assert issue.status == "new"
    assert requests[0] == (
        "/acme/Security/_apis/wit/wiql?api-version=7.1",
        {"query": "SELECT [System.Id] FROM WorkItems WHERE [System.Tags] CONTAINS 'cynux-finding-finding-123'"},
    )
    assert requests[1] == (
        "/acme/Security/_apis/wit/workitems/$Issue?api-version=7.1",
        [
            {"op": "add", "path": "/fields/System.Title", "value": "Critical finding"},
            {"op": "add", "path": "/fields/System.Description", "value": "Reproduce and remediate."},
            {"op": "add", "path": "/fields/System.Tags", "value": "cynux;cynux-finding-finding-123"},
        ],
    )


@pytest.mark.asyncio
async def test_linear_issue_creation_uses_team_scoped_description_marker() -> None:
    from app.integrations.linear import LinearClient

    settings = SimpleNamespace(
        linear=SimpleNamespace(
            configured=True, base_url="https://linear.example/graphql", api_token=SecretStr("token"),
            team_id="11111111-1111-1111-1111-111111111111",
        )
    )
    client = LinearClient(settings)
    requests = []

    class Http:
        async def post_json(self, path, **kwargs):
            requests.append(kwargs["json"])
            if "FindCynuxIssue" in kwargs["json"]["query"]:
                return {"data": {"issues": {"nodes": []}}}
            return {"data": {"issueCreate": {"success": True, "issue": {"id": "uuid-42", "identifier": "SEC-42", "url": "https://linear.example/SEC-42", "title": "Critical finding", "state": {"name": "Triage"}}}}}

    client._client = Http()
    issue = await client.create_issue(summary="Critical finding", description="Reproduce.", finding_id="finding-123")
    assert issue.key == "SEC-42"
    assert issue.status == "triage"
    assert requests[0]["variables"] == {"teamId": "11111111-1111-1111-1111-111111111111", "marker": "<!-- cynux-finding-finding-123 -->"}
    assert requests[1]["variables"]["input"]["teamId"] == "11111111-1111-1111-1111-111111111111"
    assert requests[1]["variables"]["input"]["description"].endswith("<!-- cynux-finding-finding-123 -->")


@pytest.mark.asyncio
async def test_github_issue_state_can_be_closed_and_reopened() -> None:
    from app.integrations.github import GitHubClient

    settings = SimpleNamespace(github=SimpleNamespace(
        configured=True, base_url="https://api.github.example", api_token=SecretStr("token"),
        organization="acme", repository="portal",
    ))
    client = GitHubClient(settings)
    requests = []

    class Http:
        async def patch_json(self, path, **kwargs):
            requests.append((path, kwargs["json"]))
            return {"number": 42, "id": 99, "state": kwargs["json"]["state"]}

    client._client = Http()
    await client.set_issue_state("#42", closed=True)
    await client.set_issue_state("#42", closed=False)
    assert requests == [
        ("/repos/acme/portal/issues/42", {"state": "closed"}),
        ("/repos/acme/portal/issues/42", {"state": "open"}),
    ]


@pytest.mark.asyncio
async def test_gitlab_issue_state_uses_provider_state_event() -> None:
    from app.integrations.gitlab import GitLabClient

    settings = SimpleNamespace(gitlab=SimpleNamespace(
        configured=True, base_url="https://gitlab.example/api/v4", api_token=SecretStr("token"),
        project_ids=[], issue_project="acme/portal",
    ))
    client = GitLabClient(settings)
    requests = []

    class Http:
        async def put_json(self, path, **kwargs):
            requests.append((path, kwargs["json"]))
            return {"iid": 15, "id": 76, "state": "closed"}

    client._client = Http()
    await client.set_issue_state("#15", closed=True)
    assert requests == [
        ("/projects/acme%2Fportal/issues/15", {"state_event": "close"})
    ]


@pytest.mark.asyncio
async def test_azure_devops_issue_state_uses_json_patch() -> None:
    from app.integrations.azure_devops import AzureDevOpsClient

    settings = SimpleNamespace(azure_devops=SimpleNamespace(
        configured=True, base_url="https://dev.azure.example", api_token=SecretStr("token"),
        organization="acme", project="Security", work_item_type="Issue",
    ))
    client = AzureDevOpsClient(settings)
    requests = []

    class Http:
        async def patch_json(self, path, **kwargs):
            requests.append((path, kwargs["json"], kwargs["headers"]["Content-Type"]))
            return {"id": 42, "fields": {"System.State": "Closed"}}

    client._client = Http()
    await client.set_issue_state("#42", closed=True)
    assert requests == [(
        "/acme/Security/_apis/wit/workitems/42?api-version=7.1",
        [{"op": "add", "path": "/fields/System.State", "value": "Closed"}],
        "application/json-patch+json",
    )]


@pytest.mark.asyncio
async def test_jira_issue_state_selects_a_matching_transition() -> None:
    from app.integrations.jira import JiraClient

    settings = SimpleNamespace(jira=SimpleNamespace(
        configured=True, base_url="https://jira.example", api_token=SecretStr("token"),
        user_email="security@example.com", project_key="SEC", issue_type="Task",
    ))
    client = JiraClient(settings)
    requests = []

    class Http:
        async def get_json(self, path, **kwargs):
            requests.append(("GET", path, None))
            return {"transitions": [
                {"id": "11", "name": "In Progress", "to": {"statusCategory": {"key": "indeterminate"}}},
                {"id": "31", "name": "Done", "to": {"statusCategory": {"key": "done"}}},
            ]}

        async def post_json(self, path, **kwargs):
            requests.append(("POST", path, kwargs["json"]))
            return {}

    client._client = Http()
    await client.set_issue_state("SEC-42", closed=True)
    assert requests[-1] == (
        "POST", "/rest/api/3/issue/SEC-42/transitions", {"transition": {"id": "31"}}
    )


@pytest.mark.asyncio
async def test_servicenow_issue_state_updates_the_linked_incident() -> None:
    from app.integrations.servicenow import ServiceNowClient

    settings = SimpleNamespace(servicenow=SimpleNamespace(
        configured=True, base_url="https://acme.service-now.example", api_token=SecretStr("token"),
        table="incident", assignment_group="",
    ))
    client = ServiceNowClient(settings)
    requests = []

    class Http:
        async def get_json(self, path, **kwargs):
            return {"result": [{"sys_id": "sys-42", "number": "INC0010042", "state": "1"}]}

        async def patch_json(self, path, **kwargs):
            requests.append((path, kwargs["json"]))
            return {"result": {"sys_id": "sys-42", "number": "INC0010042", "state": "6"}}

    client._client = Http()
    await client.set_issue_state("INC0010042", closed=True)
    assert requests == [("/api/now/table/incident/sys-42", {"state": "6"})]
