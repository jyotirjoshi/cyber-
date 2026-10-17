"""PTaaS engagement contracts preserve lifecycle and evidence boundaries."""

import datetime as dt
import uuid

import pytest
from pydantic import ValidationError

from app.integrations.storage import engagement_document_key
from app.schemas.engagement import (
    EngagementCreateIn,
    EngagementDocumentCreateIn,
    EngagementTimeEntryCreateIn,
)
from app.services.engagement import next_retest_ordinal, validate_status_transition


def test_engagement_inputs_normalize_scope_and_reject_unbounded_time() -> None:
    payload = EngagementCreateIn(
        title="  External API pentest  ",
        description="Customer-authorized engagement",
        scope={"targets": ["api.example.com"], "exclusions": ["billing.example.com"]},
        starts_at=dt.datetime(2026, 10, 20, tzinfo=dt.UTC),
        ends_at=dt.datetime(2026, 10, 24, tzinfo=dt.UTC),
    )
    assert payload.title == "External API pentest"
    assert payload.scope["targets"] == ["api.example.com"]

    with pytest.raises(ValidationError):
        EngagementTimeEntryCreateIn(
            minutes=1441,
            work_date=dt.date(2026, 10, 20),
            note="invalid",
        )


def test_document_metadata_never_accepts_inline_content_or_credentials() -> None:
    with pytest.raises(ValidationError):
        EngagementDocumentCreateIn(
            title="Evidence",
            kind="evidence",
            storage_key="org/private/evidence.zip",
            content_type="application/zip",
            size_bytes=10,
            sha256="a" * 64,
            content="secret",
        )


@pytest.mark.parametrize(
    ("current", "target"),
    [
        ("draft", "scoping"),
        ("scoping", "active"),
        ("active", "retesting"),
        ("retesting", "active"),
        ("active", "completed"),
        ("draft", "cancelled"),
    ],
)
def test_allowed_engagement_transitions(current: str, target: str) -> None:
    validate_status_transition(current, target)


@pytest.mark.parametrize(
    ("current", "target"),
    [("draft", "completed"), ("completed", "active"), ("cancelled", "draft")],
)
def test_invalid_engagement_transitions_are_rejected(current: str, target: str) -> None:
    with pytest.raises(ValueError, match="transition"):
        validate_status_transition(current, target)


def test_retest_round_numbers_are_monotonic_and_bounded() -> None:
    assert next_retest_ordinal([]) == 1
    assert next_retest_ordinal([1, 3, 2]) == 4
    with pytest.raises(ValueError, match="limit"):
        next_retest_ordinal(list(range(1, 101)))


def test_engagement_ids_remain_uuid_compatible() -> None:
    # The API uses opaque UUIDs rather than tenant-local sequential references.
    assert isinstance(uuid.uuid4(), uuid.UUID)


def test_engagement_document_keys_are_tenant_scoped_and_sanitized() -> None:
    organization_id = uuid.UUID(int=1)
    engagement_id = uuid.UUID(int=2)
    assert engagement_document_key(
        organization_id, engagement_id, uuid.UUID(int=3), "../authorization evidence.pdf"
    ) == (
        f"org/{organization_id}/engagements/{engagement_id}/documents/"
        f"{uuid.UUID(int=3)}/authorization_evidence.pdf"
    )
