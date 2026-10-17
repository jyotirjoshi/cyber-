"""Asset inventory write contracts preserve identity and topology invariants."""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest


class _ScalarResult:
    def __init__(self, *, one=None, many=None):
        self.one = one
        self.many = list(many or [])

    def scalar_one_or_none(self):
        return self.one

    def scalars(self):
        return SimpleNamespace(all=lambda: self.many)


class _Session:
    def __init__(self, results):
        self.results = iter(results)
        self.added = []

    async def execute(self, _statement):
        return next(self.results)

    def add(self, value):
        self.added.append(value)

    async def flush(self):
        return None


def test_asset_create_normalizes_identity_and_csv_round_trips() -> None:
    from app.services.asset_merge import _canonical_name, export_asset_csv, parse_asset_csv

    kind, name = _canonical_name("domain", "API.Example.COM.")
    assert (kind, name) == ("domain", "domain:api.example.com")
    rows = parse_asset_csv(
        b"name,asset_type,port,protocol,service,internet_exposed\n"
        b"API.Example.COM.,domain,443,tcp,https,true\n"
    )
    assert rows[0].port == 443
    assert rows[0].internet_exposed is True
    exported = export_asset_csv(
        [
            SimpleNamespace(
                id=uuid4(),
                name=name,
                asset_type=kind,
                port=443,
                protocol="tcp",
                service="https",
                status="active",
                environment="production",
            )
        ]
    )
    assert b"domain:api.example.com" in exported


def test_asset_bulk_merge_and_relationship_payloads_reject_ambiguous_work() -> None:
    from app.schemas.asset import AssetBulkUpdateIn, AssetMergeIn, AssetRelationshipIn

    asset_id = uuid4()
    with pytest.raises(ValueError, match="unique"):
        AssetBulkUpdateIn.model_validate(
            {
                "items": [
                    {"asset_id": asset_id, "expected_version": 1, "status": "inactive"},
                    {"asset_id": asset_id, "expected_version": 1, "status": "active"},
                ]
            }
        )
    with pytest.raises(ValueError, match="must differ"):
        AssetMergeIn(
            source_asset_id=asset_id,
            target_asset_id=asset_id,
            source_expected_version=1,
            target_expected_version=1,
            reason="duplicate",
        )
    with pytest.raises(ValueError, match="themselves"):
        AssetRelationshipIn(
            source_asset_id=asset_id,
            target_asset_id=asset_id,
            relationship_type="depends_on",
        )


@pytest.mark.asyncio
async def test_dependency_cycle_detection_is_bounded_and_tenant_scoped() -> None:
    from app.services.asset_merge import _depends_on_reaches

    first, second, third = uuid4(), uuid4(), uuid4()
    class Session:
        def __init__(self, responses):
            self.responses = iter(responses)
            self.statements = []

        async def execute(self, statement):
            self.statements.append(statement)
            targets = next(self.responses, [])
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: targets))

    assert await _depends_on_reaches(
        Session([[second], [third]]), organization_id=uuid4(), start=first, target=third
    )
    assert not await _depends_on_reaches(
        Session([[]]), organization_id=uuid4(), start=third, target=first
    )


@pytest.mark.asyncio
async def test_merge_preserves_original_snapshot_and_moves_aliases(monkeypatch) -> None:
    from app.schemas.asset import AssetMergeIn
    from app.services.asset_merge import merge_assets

    source_id, target_id, organization_id, user_id = uuid4(), uuid4(), uuid4(), uuid4()
    source = SimpleNamespace(
        id=source_id,
        name="domain:old.example.com",
        asset_type="domain",
        port=None,
        protocol=None,
        status="active",
        selected_for_scanning=True,
        merged_into_id=None,
        version=3,
    )
    target = SimpleNamespace(
        id=target_id,
        merged_into_id=None,
        version=7,
    )
    prior_alias = SimpleNamespace(asset_id=source_id)
    session = _Session(
        [
            _ScalarResult(many=[source, target]),
            _ScalarResult(one=None),
            _ScalarResult(many=[prior_alias]),
        ]
    )
    principal = SimpleNamespace(
        organization_id=organization_id,
        user_id=user_id,
        require=lambda _permission: None,
    )

    async def record(*_args, **_kwargs):
        return None

    monkeypatch.setattr("app.services.asset_merge.audit_service.record", record)
    event = await merge_assets(
        session,
        principal,
        AssetMergeIn(
            source_asset_id=source_id,
            target_asset_id=target_id,
            source_expected_version=3,
            target_expected_version=7,
            reason="Same endpoint discovered twice",
        ),
    )

    assert event.source_snapshot["status"] == "active"
    assert event.source_snapshot["version"] == 3
    assert event.moved_counts == {"aliases": 2, "provenance_rewritten": 0}
    assert prior_alias.asset_id == target_id
    assert source.merged_into_id == target_id
    assert source.status == "out_of_scope"
    assert source.version == 4 and target.version == 8


@pytest.mark.asyncio
async def test_manual_owner_must_be_an_active_member_of_the_tenant(monkeypatch) -> None:
    from app.core.errors import UserError
    from app.schemas.asset import AssetCreateIn
    from app.services.asset_merge import create_asset

    principal = SimpleNamespace(
        organization_id=uuid4(),
        user_id=uuid4(),
        require=lambda _permission: None,
    )
    session = _Session([_ScalarResult(one=None), _ScalarResult(one=None)])

    async def record(*_args, **_kwargs):
        return None

    monkeypatch.setattr("app.services.asset_merge.audit_service.record", record)
    with pytest.raises(UserError, match="active member"):
        await create_asset(
            session,
            principal,
            AssetCreateIn.model_validate(
                {
                    "name": "api.example.com",
                    "asset_type": "domain",
                    "context": {"owner_user_id": str(uuid4())},
                }
            ),
        )
    assert session.added == []
