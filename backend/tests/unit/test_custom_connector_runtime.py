import inspect
import uuid

import pytest
from sqlalchemy import JSON, Column, MetaData, Table, Uuid, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import Settings
from app.core.errors import ConflictError, InvalidConfigurationError
from app.db.enums import Role
from app.db.models.custom_connector import CustomConnector, CustomConnectorRun
from app.schemas.custom_connector import CustomConnectorIn
from app.services.context import Principal
from app.services.custom_connector import (
    collect_records,
    execute_connector,
    map_record,
    normalize_record,
    reserve_connector_run,
    run_pending_connector_runs,
    safe_response_origin,
    validate_definition,
)


def connector(base_url: str = "https://security.example.com") -> CustomConnectorIn:
    return CustomConnectorIn(name="Provider", base_url=base_url, routes=[{"name": "alerts", "method": "GET", "path": "/api/v1/alerts", "records_path": "data.items"}], field_mapping={"title": "attributes.title", "severity": "attributes.severity"}, output_type="external_alert")


def test_connector_rejects_private_or_unsafe_destination() -> None:
    with pytest.raises(InvalidConfigurationError):
        validate_definition(connector("https://127.0.0.1"))
    with pytest.raises(InvalidConfigurationError):
        validate_definition(connector("http://security.example.com"))


def test_connector_rejects_path_traversal_and_unknown_methods() -> None:
    payload = connector()
    payload.routes = [{"method": "POST", "path": "/api/../admin"}]
    with pytest.raises(InvalidConfigurationError):
        validate_definition(payload)


def test_mapping_uses_declared_json_paths_only() -> None:
    assert map_record({"attributes": {"title": "Issue", "severity": "high", "secret": "x"}}, connector().field_mapping) == {"title": "Issue", "severity": "high"}


class FakeConnectorClient:
    """A deterministic provider boundary; pagination and mapping remain real."""

    def __init__(self, pages: list[dict]) -> None:
        self.pages = list(pages)
        self.requests: list[tuple[str, dict]] = []

    async def get_json(self, path: str, *, params: dict | None = None, **_: object) -> dict:
        self.requests.append((path, dict(params or {})))
        return self.pages.pop(0)


@pytest.mark.asyncio
async def test_cursor_pagination_collects_records_and_returns_resume_checkpoint() -> None:
    client = FakeConnectorClient(
        [
            {"data": {"items": [{"id": "A"}]}, "paging": {"next": "cursor-2"}},
            {"data": {"items": [{"id": "B"}]}, "paging": {"next": None}},
        ]
    )
    route = {"name": "alerts", "method": "GET", "path": "/alerts", "records_path": "data.items"}
    pagination = {
        "type": "cursor",
        "cursor_path": "paging.next",
        "query_parameter": "after",
        "max_pages": 5,
        "page_size": 100,
    }

    records, checkpoint = await collect_records(client, route, pagination, checkpoint={})

    assert records == [{"id": "A"}, {"id": "B"}]
    assert client.requests == [
        ("/alerts", {"page_size": 100}),
        ("/alerts", {"page_size": 100, "after": "cursor-2"}),
    ]
    assert checkpoint == {"pages": 2, "complete": True}


@pytest.mark.asyncio
async def test_page_pagination_stops_on_short_page_without_unbounded_requests() -> None:
    client = FakeConnectorClient([{"items": [{"id": "A"}, {"id": "B"}]}, {"items": []}])
    route = {"name": "alerts", "method": "GET", "path": "/alerts", "records_path": "items"}
    pagination = {
        "type": "page",
        "query_parameter": "page",
        "max_pages": 3,
        "page_size": 2,
    }

    records, checkpoint = await collect_records(client, route, pagination, checkpoint={})

    assert records == [{"id": "A"}, {"id": "B"}]
    assert client.requests == [
        ("/alerts", {"page_size": 2, "page": 1}),
        ("/alerts", {"page_size": 2, "page": 2}),
    ]
    assert checkpoint == {"pages": 2, "complete": True}


def test_normalized_record_has_stable_identity_and_drops_undeclared_raw_fields() -> None:
    mapped = {
        "external_id": "provider-123",
        "title": "Public bucket",
        "severity": "HIGH",
        "status": "active",
        "asset_type": "cloud_resource",
        "asset_value": "arn:aws:s3:::public",
        "cve_ids": ["CVE-2024-1234", "not-a-cve"],
    }
    raw = {**mapped, "provider_secret": "must-not-be-retained"}

    alert = normalize_record(mapped, raw=raw, provider="custom:inventory")

    assert alert.external_id == "provider-123"
    assert alert.severity == "high"
    assert alert.status == "open"
    assert alert.resource == "arn:aws:s3:::public"
    assert alert.cve_ids == ["CVE-2024-1234"]
    assert alert.raw_payload == mapped
    assert "provider_secret" not in alert.raw_payload


def test_normalized_record_rejects_missing_identity_or_title() -> None:
    with pytest.raises(InvalidConfigurationError):
        normalize_record({"title": "No identity"}, raw={}, provider="custom:test")
    with pytest.raises(InvalidConfigurationError):
        normalize_record({"external_id": "A"}, raw={}, provider="custom:test")


def test_redirects_cannot_change_connector_origin() -> None:
    assert safe_response_origin("https://scanner.example.com", "https://scanner.example.com/v2/items")
    assert not safe_response_origin("https://scanner.example.com", "https://evil.example.net/items")
    assert not safe_response_origin("https://scanner.example.com", "http://scanner.example.com/items")


@pytest.fixture
async def connector_session():
    engine = create_async_engine("sqlite+aiosqlite://")
    metadata = MetaData()
    for model in (CustomConnector, CustomConnectorRun):
        Table(
            model.__tablename__,
            metadata,
            *[
                Column(
                    column.name,
                    JSON()
                    if isinstance(column.type, JSONB)
                    else Uuid()
                    if isinstance(column.type, Uuid)
                    else column.type,
                    primary_key=column.primary_key,
                    nullable=column.nullable,
                    server_default=column.server_default,
                )
                for column in model.__table__.columns
            ],
        )
    async with engine.begin() as connection:
        await connection.run_sync(metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            yield session
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_run_reservation_replays_same_request_without_duplicate(connector_session) -> None:
    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    row = CustomConnector(
        organization_id=principal.organization_id,
        name="Provider",
        base_url="https://security.example.com",
        routes=[{"name": "alerts", "method": "GET", "path": "/alerts", "records_path": "items"}],
        pagination={},
        field_mapping={"external_id": "id", "title": "title"},
        output_type="external_alert",
        rate_limit_per_minute=60,
    )
    connector_session.add(row)
    await connector_session.flush()

    first, replayed_first = await reserve_connector_run(
        connector_session, principal, row, idempotency_key="manual-run-1"
    )
    second, replayed_second = await reserve_connector_run(
        connector_session, principal, row, idempotency_key="manual-run-1"
    )

    assert replayed_first is False
    assert replayed_second is True
    assert second.id == first.id
    assert len((await connector_session.scalars(select(CustomConnectorRun))).all()) == 1


@pytest.mark.asyncio
async def test_run_reservation_rejects_reused_key_after_definition_changes(connector_session) -> None:
    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    row = CustomConnector(
        organization_id=principal.organization_id,
        name="Provider",
        base_url="https://security.example.com",
        routes=[{"name": "alerts", "method": "GET", "path": "/alerts", "records_path": "items"}],
        pagination={},
        field_mapping={"external_id": "id", "title": "title"},
        output_type="external_alert",
        rate_limit_per_minute=60,
    )
    connector_session.add(row)
    await connector_session.flush()
    await reserve_connector_run(connector_session, principal, row, idempotency_key="manual-run-1")
    row.field_mapping = {"external_id": "id", "title": "summary"}

    with pytest.raises(ConflictError):
        await reserve_connector_run(
            connector_session, principal, row, idempotency_key="manual-run-1"
        )


def test_custom_connector_run_route_is_mounted() -> None:
    from app.api.v1.custom_connectors import router

    assert "/custom-connectors/{connector_id}/runs" in {route.path for route in router.routes}
    assert any(
        route.path == "/custom-connectors/{connector_id}/runs" and "POST" in route.methods
        for route in router.routes
    )


@pytest.mark.asyncio
async def test_execute_connector_normalizes_and_completes_durable_run(monkeypatch) -> None:
    organization_id = uuid.uuid4()
    connector_id = uuid.uuid4()
    connector_row = CustomConnector(
        id=connector_id,
        organization_id=organization_id,
        name="Provider",
        base_url="https://security.example.com",
        routes=[{"name": "alerts", "method": "GET", "path": "/alerts", "records_path": "items"}],
        pagination={},
        field_mapping={
            "external_id": "id",
            "title": "summary",
            "severity": "severity",
            "asset_type": "asset.kind",
            "asset_value": "asset.value",
        },
        output_type="canonical_finding",
        rate_limit_per_minute=60,
        is_enabled=True,
    )
    run = CustomConnectorRun(
        id=uuid.uuid4(),
        organization_id=organization_id,
        connector_id=connector_id,
        status="running",
        checkpoint={},
        result={},
        records_read=0,
        records_written=0,
        started_at=func.now(),
    )
    client = FakeConnectorClient(
        [{"items": [{"id": "A", "summary": "Issue", "severity": "high", "asset": {"kind": "domain", "value": "example.com"}}]}]
    )
    staged: list = []

    async def stage(_session, *, organization_id, integration_id, provider, alerts):
        staged.extend(alerts)
        return len(staged)

    monkeypatch.setattr("app.services.custom_connector._stage_alerts", stage)
    principal = Principal(user_id=None, organization_id=organization_id, role=Role.OWNER)

    completed = await execute_connector(None, principal, connector_row, run, client=client)

    assert completed.status == "completed"
    assert completed.records_read == 1
    assert completed.records_written == 1
    assert completed.checkpoint == {"routes": {"alerts": {"pages": 1, "complete": True}}}
    assert completed.result == {"routes": {"alerts": {"read": 1}}, "output_type": "canonical_finding"}
    assert [(alert.external_id, alert.resource) for alert in staged] == [("A", "example.com")]


@pytest.mark.asyncio
async def test_worker_claims_pending_run_and_persists_completion(connector_session, monkeypatch) -> None:
    organization_id = uuid.uuid4()
    connector_row = CustomConnector(
        organization_id=organization_id,
        name="Provider",
        base_url="https://security.example.com",
        routes=[{"name": "alerts", "method": "GET", "path": "/alerts", "records_path": "items"}],
        pagination={},
        field_mapping={"external_id": "id", "title": "summary"},
        output_type="external_alert",
        rate_limit_per_minute=60,
        is_enabled=True,
    )
    connector_session.add(connector_row)
    await connector_session.flush()
    run = CustomConnectorRun(
        organization_id=organization_id,
        connector_id=connector_row.id,
        status="pending",
        checkpoint={},
        result={},
        records_read=0,
        records_written=0,
        started_at=func.now(),
    )
    connector_session.add(run)
    await connector_session.flush()

    async def stage(_session, *, organization_id, integration_id, provider, alerts):
        return len(alerts)

    monkeypatch.setattr("app.services.custom_connector._stage_alerts", stage)

    processed = await run_pending_connector_runs(
        connector_session,
        settings=Settings(_env_file=None, security={"jwt_secret": "s" * 32}),
        redis=None,
        client_factory=lambda _connector, _settings, _redis: FakeConnectorClient(
            [{"items": [{"id": "A", "summary": "Issue"}]}]
        ),
    )

    await connector_session.refresh(run)
    assert processed == 1
    assert run.status == "completed"
    assert run.records_read == 1
    assert run.records_written == 1


def test_worker_maintenance_executes_pending_custom_connector_runs() -> None:
    from app.worker.worker import AgentWorker

    source = inspect.getsource(AgentWorker._maintenance_loop)
    assert "run_pending_connector_runs" in source
