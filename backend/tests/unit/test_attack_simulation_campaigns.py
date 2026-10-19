"""Breach-and-attack simulation campaign storage contracts."""

from __future__ import annotations


def test_campaign_model_declares_safe_lifecycle_constraints() -> None:
    """A campaign must persist only explicit lifecycle values, never arbitrary execution state."""
    from app.db.models.canonical import AttackSimulationCampaign

    checks = {
        constraint.name: str(constraint.sqltext)
        for constraint in AttackSimulationCampaign.__table__.constraints
        if hasattr(constraint, "sqltext")
    }

    status_check = next(value for name, value in checks.items() if name.endswith("valid_attack_simulation_campaign_status"))
    assert "draft" in status_check
    assert "completed" in status_check


def test_campaign_create_schema_requires_a_confirmed_authorization() -> None:
    """Scheduled validation cannot be created with a checkbox-less scope reference."""
    from pydantic import ValidationError

    from app.schemas.attack_simulation import AttackSimulationCampaignCreateIn

    try:
        AttackSimulationCampaignCreateIn.model_validate(
            {
                "name": "Weekly external validation",
                "scenarios": ["external_exposure"],
                "targets": ["https://app.example.test"],
                "cron_expression": "0 6 * * 1",
                "authorization": {
                    "confirmed": False,
                    "attestation_text": "not approved",
                    "evidence_reference": "ENG-42",
                },
                "authorization_expires_at": "2027-01-01T00:00:00Z",
            }
        )
    except ValidationError:
        return
    raise AssertionError("unconfirmed campaign authorization must be rejected")


def test_campaign_model_retains_expiring_attestation_evidence() -> None:
    """A future run must have the exact authority evidence needed for re-validation."""
    from app.db.models.canonical import AttackSimulationCampaign

    columns = AttackSimulationCampaign.__table__.c
    assert columns.authorization_text.nullable is False
    assert columns.authorization_expires_at.nullable is False
    assert columns.execution_policy.nullable is False


def test_execution_policy_blocks_unapproved_actions_and_oversized_plans() -> None:
    """A campaign cannot silently expand beyond its declared action or run budget."""
    import pytest

    from app.core.errors import InvalidConfigurationError
    from app.schemas.attack_simulation import ValidationExecutionPolicy
    from app.services.attack_simulation import _validate_execution_policy

    with pytest.raises(InvalidConfigurationError):
        _validate_execution_policy(
            ValidationExecutionPolicy(
                allowed_actions=["passive_discovery"],
                max_technique_runs=10,
            ),
            scenarios=["api_authorization"],
            targets=["https://api.example.test"],
        )

    with pytest.raises(InvalidConfigurationError):
        _validate_execution_policy(
            ValidationExecutionPolicy(
                allowed_actions=["passive_discovery"],
                max_technique_runs=1,
            ),
            scenarios=["external_exposure"],
            targets=["one.example.test", "two.example.test"],
        )


def test_catalog_declares_safe_action_and_cost_for_every_technique() -> None:
    from app.services.bas_techniques import list_techniques

    techniques = list_techniques()
    assert techniques
    assert all(item.safe_action for item in techniques)
    assert all(item.estimated_cost_usd >= 0 for item in techniques)


async def test_due_campaign_disables_itself_when_authority_has_expired(monkeypatch) -> None:
    """No scheduled validation can outlive the authority that permitted it."""
    import datetime as dt
    from types import SimpleNamespace

    from app.services import attack_simulation as service

    campaign = SimpleNamespace(
        organization_id=__import__("uuid").uuid4(),
        authorization_expires_at=dt.datetime(2026, 10, 1, tzinfo=dt.UTC),
        status="active",
        last_error_code=None,
    )

    async def unexpected(*args, **kwargs):
        raise AssertionError("expired authority launched a campaign")

    monkeypatch.setattr(service.assessment_service, "create_assessment", unexpected)
    result = await service.execute_due_campaign(
        object(),
        campaign,
        object(),
        object(),
        now=dt.datetime(2026, 10, 2, tzinfo=dt.UTC),
    )

    assert result is None
    assert campaign.status == "paused"
    assert campaign.last_error_code == "authorization_expired"


async def test_create_campaign_is_tenant_owned_and_scheduled_from_its_cron() -> None:
    """A campaign is owned by its creator's tenant and starts only at its calculated due time."""
    import datetime as dt
    import uuid

    from app.db.enums import Role
    from app.schemas.attack_simulation import AttackSimulationCampaignCreateIn
    from app.services.attack_simulation import create_campaign
    from app.services.context import Principal

    class Session:
        def __init__(self) -> None:
            self.added = []

        def add(self, row) -> None:
            self.added.append(row)

        async def flush(self) -> None:
            return None

    now = dt.datetime(2026, 10, 10, tzinfo=dt.UTC)
    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    campaign = await create_campaign(
        Session(),
        principal,
        AttackSimulationCampaignCreateIn.model_validate(
            {
                "name": "Weekly external validation",
                "scenarios": ["external_exposure"],
                "targets": ["https://app.example.test"],
                "cron_expression": "0 6 * * 1",
                "authorization": {
                    "confirmed": True,
                    "attestation_text": "Authorized under ENG-42",
                    "evidence_reference": "ENG-42",
                },
                "authorization_expires_at": "2027-01-01T00:00:00Z",
            }
        ),
        now=now,
    )

    assert campaign.organization_id == principal.organization_id
    assert campaign.created_by_id == principal.user_id
    assert campaign.status == "active"
    assert campaign.next_run_at > now


def test_campaign_routes_are_mounted_in_versioned_api() -> None:
    """Campaign management must be reachable through the public versioned API."""
    from app.api.v1.router import api_router

    paths = {route.path for route in api_router.routes}
    assert "/attack-simulations" in paths


async def test_due_campaign_sweep_uses_the_creators_current_membership(monkeypatch) -> None:
    """A campaign uses current tenant membership rather than stale creator privileges."""
    import datetime as dt
    import uuid
    from types import SimpleNamespace

    from app.db.enums import Role
    from app.services import attack_simulation as service

    campaign = SimpleNamespace(
        organization_id=uuid.uuid4(), created_by_id=uuid.uuid4(), status="active", last_error_code=None
    )
    calls = []

    class Session:
        def __init__(self) -> None:
            self.calls = 0

        async def execute(self, statement):
            self.calls += 1
            if self.calls == 1:
                return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [campaign]))
            return SimpleNamespace(scalar_one_or_none=lambda: Role.SECURITY_ENGINEER.value)

    async def execute(session, selected_campaign, principal, settings, *, now):
        calls.append((selected_campaign, principal))
        return uuid.uuid4()

    monkeypatch.setattr(service, "execute_due_campaign", execute)
    count = await service.run_due_campaigns(
        Session(), object(), now=dt.datetime(2026, 10, 10, tzinfo=dt.UTC)
    )

    assert count == 1
    assert calls[0][1].organization_id == campaign.organization_id
    assert calls[0][1].user_id == campaign.created_by_id


async def test_successful_due_campaign_advances_its_next_run(monkeypatch) -> None:
    """A campaign is not repeatedly launched by every maintenance tick after success."""
    import datetime as dt
    import uuid
    from types import SimpleNamespace

    from app.db.enums import Role
    from app.services import attack_simulation as service
    from app.services.context import Principal

    now = dt.datetime(2026, 10, 10, tzinfo=dt.UTC)
    campaign = SimpleNamespace(
        organization_id=uuid.uuid4(),
        status="active",
        authorization_expires_at=dt.datetime(2027, 1, 1, tzinfo=dt.UTC),
        targets=["https://app.example.test"],
        name="Weekly validation",
        scenarios=["external_exposure"],
        authorization_text="Authorized under ENG-42",
        authorization_reference="ENG-42",
        cron_expression="0 6 * * 1",
        timezone="UTC",
        next_run_at=now,
        last_run_at=None,
        last_assessment_id=None,
        last_error_code=None,
    )

    async def create_assessment(*args, **kwargs):
        return SimpleNamespace(id=uuid.uuid4())

    async def flush() -> None:
        return None

    monkeypatch.setattr(service.assessment_service, "create_assessment", create_assessment)
    monkeypatch.setattr(service, "stage_assessment_run", lambda *args: (uuid.uuid4(), uuid.uuid4()))
    async def create_execution_run(*args, **kwargs):
        return SimpleNamespace(id=uuid.uuid4())

    monkeypatch.setattr(service, "_create_execution_run", create_execution_run)
    await service.execute_due_campaign(
        SimpleNamespace(flush=flush),
        campaign,
        Principal(user_id=uuid.uuid4(), organization_id=campaign.organization_id, role=Role.OWNER),
        object(),
        now=now,
    )

    assert campaign.last_run_at == now
    assert campaign.next_run_at > now


def test_worker_maintenance_invokes_campaign_sweep() -> None:
    """Due campaigns must be driven by the durable worker maintenance loop."""
    import inspect

    from app.worker.worker import AgentWorker

    assert "run_due_campaigns" in inspect.getsource(AgentWorker._maintenance_loop)


def test_campaign_api_exposes_lifecycle_controls() -> None:
    """Operators need an explicit tenant-scoped control to pause a scheduled campaign."""
    from app.api.v1.attack_simulations import router

    paths = {route.path for route in router.routes}
    assert "/attack-simulations/{campaign_id}/pause" in paths


def test_campaign_pause_has_a_dedicated_audit_action() -> None:
    """Campaign operations must not be indistinguishable from assessment cancellation."""
    from app.services.audit import AuditAction

    assert AuditAction.ATTACK_SIMULATION_PAUSE == "attack_simulation.pause"
