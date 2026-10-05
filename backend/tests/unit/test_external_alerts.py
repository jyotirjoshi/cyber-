"""Normalized external-alert ledger contracts."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from app.core.config import Settings
from app.core.errors import PermissionDeniedError
from app.db.enums import Role
from app.db.models.external_alert import ExternalSecurityAlert
from app.schemas.integration import IntegrationSyncOut
from app.services.context import Principal
from app.services.external_alert import (
    GitHubSyncResult,
    normalize_github_alert,
    normalize_gitlab_alert,
    normalize_wazuh_alert,
    stage_github_alerts,
    stage_gitlab_alerts,
    stage_wazuh_alerts,
)
from tests.unit._empty_rows import EmptyRows


class _RecordingSession:
    """Small session double that exposes the persistence statement as real SQL."""

    def __init__(self) -> None:
        self.statements: list[Any] = []

    async def execute(self, statement: Any) -> EmptyRows:
        self.statements.append(statement)
        return EmptyRows()


def test_external_alerts_deduplicate_per_tenant_and_provider_identity() -> None:
    """Removing provider identity from this uniqueness key merges unrelated alerts."""
    constraints = {
        constraint.name: tuple(column.name for column in constraint.columns)
        for constraint in ExternalSecurityAlert.__table__.constraints
        if constraint.name
    }

    assert constraints["unique_external_security_alert"] == (
        "organization_id",
        "provider",
        "external_id",
    )
    assert ExternalSecurityAlert.__table__.c.raw_payload.nullable is False
    assert ExternalSecurityAlert.__table__.c.evidence.default.arg(None) == {}


def test_github_dependabot_alert_is_normalized_without_discarding_cve_or_repository() -> None:
    """Dropping CVEs or the repository makes cross-source correlation impossible."""
    normalized = normalize_github_alert(
        "dependabot",
        {
            "number": 42,
            "state": "open",
            "html_url": "https://github.com/acme/payments/security/dependabot/42",
            "repository": {"full_name": "acme/payments"},
            "security_advisory": {
                "summary": "Django denial of service",
                "severity": "high",
                "identifiers": [{"type": "CVE", "value": "CVE-2026-1234"}],
            },
        },
    )

    assert normalized.external_id == "dependabot:acme/payments:42"
    assert normalized.title == "Django denial of service"
    assert normalized.severity == "high"
    assert normalized.status == "open"
    assert normalized.resource == "acme/payments"
    assert normalized.cve_ids == ["CVE-2026-1234"]


def test_github_alert_numbers_are_scoped_to_repositories() -> None:
    first = normalize_github_alert(
        "secret_scanning", {"number": 7, "repository": {"full_name": "acme/api"}}
    )
    second = normalize_github_alert(
        "secret_scanning", {"number": 7, "repository": {"full_name": "acme/web"}}
    )
    assert first.external_id != second.external_id


def test_github_alert_without_repository_cannot_be_persisted_as_ambiguous_identity() -> None:
    with pytest.raises(ValueError, match="repository"):
        normalize_github_alert("dependabot", {"number": 7})


@pytest.mark.parametrize(
    ("category", "state", "expected"),
    [
        ("code_scanning", "closed", "resolved"),
        ("dependabot", "auto_dismissed", "dismissed"),
        ("secret_scanning", "resolved", "resolved"),
    ],
)
def test_github_terminal_states_are_not_reported_as_open(
    category: str, state: str, expected: str
) -> None:
    normalized = normalize_github_alert(
        category, {"number": 7, "state": state, "repository": {"full_name": "acme/api"}}
    )
    assert normalized.status == expected


@pytest.mark.asyncio
async def test_github_staging_keeps_same_number_from_two_repositories() -> None:
    session = _RecordingSession()
    result = await stage_github_alerts(
        session,
        organization_id=uuid.uuid4(),
        integration_id=None,
        feeds=[("dependabot", [
            {"number": 7, "repository": {"full_name": "acme/api"}},
            {"number": 7, "repository": {"full_name": "acme/web"}},
        ])],
    )
    assert result.total == 2
    values = session.statements[0].compile(
        dialect=__import__("sqlalchemy").dialects.postgresql.dialect()
    ).params.values()
    assert "dependabot:acme/api:7" in values
    assert "dependabot:acme/web:7" in values


def test_gitlab_security_finding_preserves_project_cve_and_location() -> None:
    """GitLab's SAST/SCA/DAST findings need one stable tenant-local identity."""
    normalized = normalize_gitlab_alert(
        "acme/payments",
        {
            "uuid": "6e01f7ea-0bf8-4eab-bde1-acde992a1a01",
            "report_type": "dependency_scanning",
            "name": "Vulnerable payment dependency",
            "severity": "critical",
            "state": "detected",
            "project": {"full_path": "acme/payments"},
            "location": {"file": "services/payments/requirements.txt", "start_line": 12},
            "identifiers": [
                {"external_type": "cve", "external_id": "CVE-2026-4321"},
                {"external_type": "cwe", "external_id": "CWE-79"},
            ],
            "blob_path": "/acme/payments/-/blob/main/services/payments/requirements.txt#L12",
        },
    )

    assert normalized.external_id == "acme/payments:6e01f7ea-0bf8-4eab-bde1-acde992a1a01"
    assert normalized.category == "dependency_scanning"
    assert normalized.resource == "acme/payments:services/payments/requirements.txt"
    assert normalized.cve_ids == ["CVE-2026-4321"]
    assert normalized.status == "open"


def test_wazuh_indexer_alert_uses_immutable_hit_identity_and_agent_context() -> None:
    """A Wazuh rule alert must not collapse with another agent's event of the same rule."""
    normalized = normalize_wazuh_alert(
        {
            "_id": "A1b2C3",
            "_source": {
                "@timestamp": "2026-10-01T00:00:00.000Z",
                "agent": {"id": "007", "name": "payments-web"},
                "rule": {
                    "id": "5710",
                    "level": 12,
                    "description": "Multiple authentication failures",
                    "groups": ["authentication_failed", "sshd"],
                },
            },
        }
    )

    assert normalized.external_id == "A1b2C3"
    assert normalized.category == "authentication_failed"
    assert normalized.severity == "critical"
    assert normalized.resource == "payments-web (007)"
    assert normalized.evidence["rule_id"] == "5710"


async def test_github_sync_stages_a_tenant_scoped_conflict_safe_upsert() -> None:
    """A replay must update the same tenant's alert rather than create a duplicate."""
    session = _RecordingSession()
    organization_id = uuid.uuid4()
    integration_id = uuid.uuid4()

    result = await stage_github_alerts(
        session,  # type: ignore[arg-type]
        organization_id=organization_id,
        integration_id=integration_id,
        feeds=[
            (
                "dependabot",
                [
                    {
                        "number": 7,
                        "state": "open",
                        "repository": {"full_name": "acme/payments"},
                        "security_advisory": {"summary": "Dependency issue", "severity": "high"},
                    }
                ],
            )
        ],
    )

    assert result == GitHubSyncResult(total=1)
    assert len(session.statements) == 1
    statement = str(session.statements[0].compile(dialect=__import__("sqlalchemy").dialects.postgresql.dialect()))
    assert "ON CONFLICT ON CONSTRAINT unique_external_security_alert DO UPDATE" in statement
    assert "organization_id" in statement


async def test_gitlab_sync_stages_project_findings_in_the_same_tenant_ledger() -> None:
    """GitLab ingestion must use the identical conflict-safe isolation boundary as GitHub."""
    session = _RecordingSession()

    result = await stage_gitlab_alerts(
        session,  # type: ignore[arg-type]
        organization_id=uuid.uuid4(),
        integration_id=uuid.uuid4(),
        feeds=[
            (
                "acme/payments",
                [
                    {
                        "uuid": "vuln-7",
                        "name": "SQL injection",
                        "severity": "high",
                        "state": "detected",
                    }
                ],
            )
        ],
    )

    assert result.total == 1
    statement = str(
        session.statements[0].compile(dialect=__import__("sqlalchemy").dialects.postgresql.dialect())
    )
    assert "ON CONFLICT ON CONSTRAINT unique_external_security_alert DO UPDATE" in statement


async def test_wazuh_sync_stages_indexer_hits_in_the_same_tenant_ledger() -> None:
    """Wazuh's Indexer alert IDs are provider-local and must remain tenant scoped."""
    session = _RecordingSession()

    result = await stage_wazuh_alerts(
        session,  # type: ignore[arg-type]
        organization_id=uuid.uuid4(),
        integration_id=uuid.uuid4(),
        hits=[
            {
                "_id": "wazuh-alert-17",
                "_source": {"rule": {"level": 8, "description": "Suspicious login"}},
            }
        ],
    )

    assert result.total == 1
    statement = str(
        session.statements[0].compile(dialect=__import__("sqlalchemy").dialects.postgresql.dialect())
    )
    assert "ON CONFLICT ON CONSTRAINT unique_external_security_alert DO UPDATE" in statement


async def test_github_sync_requires_integration_management_permission() -> None:
    """A viewer cannot trigger provider calls or populate the organization's alert ledger."""
    from app.services.external_alert import sync_github_alerts

    with pytest.raises(PermissionDeniedError):
        await sync_github_alerts(
            None,  # type: ignore[arg-type]
            Principal(
                user_id=uuid.uuid4(),
                organization_id=uuid.uuid4(),
                role=Role.VIEWER,
                email="viewer@example.test",
            ),
            settings=Settings(),
        )


async def test_gitlab_sync_requires_integration_management_permission() -> None:
    """A viewer cannot use the GitLab token indirectly through the sync endpoint."""
    from app.services.external_alert import sync_gitlab_alerts

    with pytest.raises(PermissionDeniedError):
        await sync_gitlab_alerts(
            None,  # type: ignore[arg-type]
            Principal(
                user_id=uuid.uuid4(),
                organization_id=uuid.uuid4(),
                role=Role.VIEWER,
                email="viewer@example.test",
            ),
            settings=Settings(),
        )


async def test_wazuh_sync_requires_integration_management_permission() -> None:
    """A viewer cannot cause an Indexer query using their organization's Wazuh credentials."""
    from app.services.external_alert import sync_wazuh_alerts

    with pytest.raises(PermissionDeniedError):
        await sync_wazuh_alerts(
            None,  # type: ignore[arg-type]
            Principal(
                user_id=uuid.uuid4(),
                organization_id=uuid.uuid4(),
                role=Role.VIEWER,
                email="viewer@example.test",
            ),
            settings=Settings(),
        )


def test_integration_sync_output_exposes_counts_but_never_provider_evidence() -> None:
    """A sync response is safe to render in a browser or save in a client log."""
    assert IntegrationSyncOut(kind="github", alerts_staged=3).model_dump() == {
        "kind": "github",
        "alerts_staged": 3,
    }


def test_gitlab_sync_is_exposed_as_an_explicit_integration_action() -> None:
    """GitLab configuration alone is not enough; an operator needs a safe sync action."""
    from app.api.v1.integrations import router

    assert any(route.path == "/integrations/gitlab/sync" for route in router.routes)


def test_wazuh_sync_is_exposed_as_an_explicit_integration_action() -> None:
    """Indexer alert collection stays operator-triggered, never an unguarded background call."""
    from app.api.v1.integrations import router

    assert any(route.path == "/integrations/wazuh/sync" for route in router.routes)
