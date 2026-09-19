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
    stage_github_alerts,
)


class _RecordingSession:
    """Small session double that exposes the persistence statement as real SQL."""

    def __init__(self) -> None:
        self.statements: list[Any] = []

    async def execute(self, statement: Any) -> None:
        self.statements.append(statement)


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

    assert normalized.external_id == "dependabot:42"
    assert normalized.title == "Django denial of service"
    assert normalized.severity == "high"
    assert normalized.status == "open"
    assert normalized.resource == "acme/payments"
    assert normalized.cve_ids == ["CVE-2026-1234"]


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


def test_integration_sync_output_exposes_counts_but_never_provider_evidence() -> None:
    """A sync response is safe to render in a browser or save in a client log."""
    assert IntegrationSyncOut(kind="github", alerts_staged=3).model_dump() == {
        "kind": "github",
        "alerts_staged": 3,
    }
