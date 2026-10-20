"""Behavioral tests for universal enforcement transactions."""

from __future__ import annotations

import datetime as dt
import uuid
from types import SimpleNamespace

import pytest

from app.core.errors import ConflictError


def _transaction(**overrides: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "status": "simulated",
        "diff_digest": "a" * 64,
        "approved_at": None,
        "approved_by_id": None,
        "approval_id": None,
        "mutation_receipt": {},
        "confirmation": {},
        "verification": {},
        "rollback_plan": {
            "action": "zpa.update_application_access",
            "target_external_id": "app-7",
            "desired_state": {"enabled": True, "groups": ["engineering"]},
        },
        "provider": "zscaler",
        "operation": "zpa.update_application_access",
        "idempotency_key": "tx-1234567890abcdef",
        "desired_state": {"enabled": False, "groups": ["engineering"]},
        "observation_ends_at": None,
        "executed_at": None,
        "verified_at": None,
        "last_error": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_canonical_diff_is_deterministic_and_reversible() -> None:
    """Changing dictionary order must not change an approved transaction digest."""

    from app.services.assurance_transactions import canonical_digest, deterministic_diff

    current = {"enabled": True, "groups": ["engineering"], "timeout": 60}
    desired = {"timeout": 30, "groups": ["engineering"], "enabled": False}
    diff = deterministic_diff(current, desired)

    assert diff == [
        {"op": "replace", "path": "/enabled", "before": True, "after": False},
        {"op": "replace", "path": "/timeout", "before": 60, "after": 30},
    ]
    assert canonical_digest(diff) == canonical_digest(list(diff))


def test_approval_is_bound_to_exact_diff_and_actor() -> None:
    """A stale approval cannot authorize a changed provider mutation."""

    from app.services.assurance_transactions import approve_transaction

    transaction = _transaction()
    actor = uuid.uuid4()
    approve_transaction(transaction, actor_user_id=actor, expected_diff_digest="a" * 64)
    assert transaction.status == "approved"
    assert transaction.approved_by_id == actor
    assert transaction.approved_at is not None

    changed = _transaction()
    with pytest.raises(ConflictError, match="diff changed"):
        approve_transaction(changed, actor_user_id=actor, expected_diff_digest="b" * 64)


@pytest.mark.asyncio
async def test_execute_is_idempotent_and_enters_observation_window() -> None:
    """Retrying an already executed transaction must not call the provider twice."""

    from app.services.assurance_transactions import execute_transaction

    class Adapter:
        provider = "zscaler"

        def __init__(self) -> None:
            self.calls = 0

        async def apply(self, command: object) -> dict[str, object]:
            self.calls += 1
            return {"status": "applied", "request_id": "provider-1"}

        async def confirm(self, command: object) -> dict[str, object]:
            return {"matches": True, "state_digest": "c" * 64}

    adapter = Adapter()
    now = dt.datetime(2026, 10, 20, tzinfo=dt.UTC)
    transaction = _transaction(status="approved")
    await execute_transaction(
        transaction,
        adapter,
        target_external_id="app-7",
        observation_seconds=300,
        now=now,
    )
    first_receipt = dict(transaction.mutation_receipt)
    await execute_transaction(
        transaction,
        adapter,
        target_external_id="app-7",
        observation_seconds=300,
        now=now,
    )

    assert adapter.calls == 1
    assert transaction.mutation_receipt == first_receipt
    assert transaction.confirmation["matches"] is True
    assert transaction.status == "observing"
    assert transaction.observation_ends_at == now + dt.timedelta(seconds=300)


def test_verification_cannot_start_before_observation_window() -> None:
    """Immediate success cannot hide a delayed outage caused by the policy change."""

    from app.services.assurance_transactions import begin_verification

    now = dt.datetime(2026, 10, 20, tzinfo=dt.UTC)
    transaction = _transaction(
        status="observing", observation_ends_at=now + dt.timedelta(minutes=5)
    )
    with pytest.raises(ConflictError, match="observation window"):
        begin_verification(transaction, now=now)

    begin_verification(transaction, now=now + dt.timedelta(minutes=5))
    assert transaction.status == "verifying"


def test_failed_verification_requires_rollback() -> None:
    """A failed post-change check must never be represented as a completed change."""

    from app.services.assurance_transactions import record_verification

    transaction = _transaction(status="verifying")
    record_verification(
        transaction,
        success=False,
        evidence={"checks": [{"name": "synthetic_login", "passed": False}]},
    )
    assert transaction.status == "rollback_pending"
    assert transaction.verification["success"] is False

