"""Report share links are opaque, tenant-scoped, revocable, and expiring."""

from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

import pytest


def test_report_share_link_never_persists_plaintext_token() -> None:
    from sqlalchemy import UniqueConstraint

    from app.db.models.report import ReportShareLink

    columns = ReportShareLink.__table__.c
    assert "token_hash" in columns
    assert "token_prefix" in columns
    assert "token" not in columns
    assert ReportShareLink.organization_id.nullable is False
    unique_constraint = any(
        {column.name for column in constraint.columns} == {"token_prefix"}
        for constraint in ReportShareLink.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    )
    unique_index = any(
        index.unique and {column.name for column in index.columns} == {"token_prefix"}
        for index in ReportShareLink.__table__.indexes
    )
    assert unique_constraint or unique_index


async def test_issue_report_share_link_returns_token_once_and_stores_hash() -> None:
    import uuid

    from app.db.enums import Role
    from app.services.context import Principal
    from app.services.report_sharing import issue_share_link

    class Session:
        def __init__(self) -> None:
            self.added = []

        def add(self, row) -> None:
            self.added.append(row)

        async def flush(self) -> None:
            return None

    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    session = Session()
    issued = await issue_share_link(
        session,
        principal,
        report_id=uuid.uuid4(),
        expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(days=1),
    )
    assert issued.token.startswith("cynux_share_")
    assert issued.link.token_hash != issued.token
    assert any(getattr(event, "action", None) == "report.share.create" for event in session.added)


async def test_resolve_share_link_verifies_the_full_opaque_secret() -> None:
    """A matching prefix alone must never grant access to a report."""
    from app.core.security import hash_password
    from app.services.report_sharing import resolve_share_link

    token = "cynux_share_example-secret"
    link = SimpleNamespace(
        token_hash=hash_password(token),
        revoked_at=None,
        expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(hours=1),
    )

    class Result:
        def scalar_one_or_none(self):
            return link

    class Session:
        async def execute(self, _statement):
            return Result()

    assert await resolve_share_link(Session(), token) is link


@pytest.mark.parametrize(
    "token, revoked_at, expires_at",
    [
        ("not-a-share-token", None, dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)),
        ("cynux_share_example-secret", dt.datetime.now(dt.UTC), dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)),
        ("cynux_share_example-secret", None, dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)),
    ],
)
async def test_resolve_share_link_hides_invalid_expired_and_revoked_grants(
    token: str, revoked_at: dt.datetime | None, expires_at: dt.datetime
) -> None:
    """Public callers receive the same absence response for every invalid grant state."""
    from app.core.errors import ResourceNotFoundError
    from app.core.security import hash_password
    from app.services.report_sharing import resolve_share_link

    link = SimpleNamespace(token_hash=hash_password("cynux_share_example-secret"), revoked_at=revoked_at, expires_at=expires_at)

    class Result:
        def scalar_one_or_none(self):
            return link

    class Session:
        async def execute(self, _statement):
            return Result()

    with pytest.raises(ResourceNotFoundError, match="share link not found"):
        await resolve_share_link(Session(), token)


async def test_shared_report_download_reads_only_the_granted_tenant_artifact() -> None:
    """An external grant can read one ready artifact and leaves an audit trail."""
    import uuid

    from app.core.security import hash_password
    from app.db.enums import ReportStatus
    from app.services.report_sharing import read_shared_report_bytes

    organization_id = uuid.uuid4()
    report_id = uuid.uuid4()
    token = "cynux_share_example-secret"
    link = SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=organization_id,
        report_id=report_id,
        token_hash=hash_password(token),
        revoked_at=None,
        expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(hours=1),
    )
    report = SimpleNamespace(
        id=report_id,
        organization_id=organization_id,
        assessment_id=uuid.uuid4(),
        status=ReportStatus.READY.value,
        storage_key="reports/tenant/report.pdf",
        format="pdf",
        size_bytes=4,
    )

    class Result:
        def __init__(self, value):
            self.value = value

        def scalar_one_or_none(self):
            return self.value

    class Session:
        def __init__(self) -> None:
            self.results = iter((Result(link), Result(report)))
            self.added = []

        async def execute(self, _statement):
            return next(self.results)

        def add(self, row) -> None:
            self.added.append(row)

        async def flush(self) -> None:
            return None

    class Storage:
        async def get_bytes(self, key: str, *, organization_id: uuid.UUID) -> bytes:
            assert key == "reports/tenant/report.pdf"
            assert organization_id == link.organization_id
            return b"data"

    session = Session()
    downloaded_report, data = await read_shared_report_bytes(session, token, storage=Storage())
    assert downloaded_report is report
    assert data == b"data"
    assert session.added[-1].action == "report.share.download"


async def test_owner_can_revoke_a_report_share_link_in_its_organization() -> None:
    """Revocation is a durable state change, so a leaked link can be stopped immediately."""
    import uuid

    from app.db.enums import Role
    from app.services.context import Principal
    from app.services.report_sharing import revoke_share_link

    organization_id = uuid.uuid4()
    link = SimpleNamespace(id=uuid.uuid4(), organization_id=organization_id, revoked_at=None)

    class Result:
        def scalar_one_or_none(self):
            return link

    class Session:
        async def execute(self, _statement):
            return Result()

        async def flush(self) -> None:
            return None

    principal = Principal(user_id=uuid.uuid4(), organization_id=organization_id, role=Role.OWNER)
    revoked = await revoke_share_link(Session(), principal, link.id)
    assert revoked is link
    assert revoked.revoked_at is not None


def test_report_share_creation_route_is_mounted() -> None:
    from app.api.v1.router import api_router

    paths = {route.path for route in api_router.routes}
    assert "/reports/{report_id}/share-links" in paths
    assert "/reports/share-links/{share_link_id}/revoke" in paths
    assert "/shared/reports/{token}" in paths

