"""Saved-view storage contracts for tenant query presets."""

from __future__ import annotations

import pytest


def test_saved_view_is_tenant_owned_and_only_targets_supported_resources() -> None:
    from app.db.models.platform import SavedView

    checks = {
        constraint.name: str(constraint.sqltext)
        for constraint in SavedView.__table__.constraints
        if hasattr(constraint, "sqltext")
    }
    resource_check = next(value for name, value in checks.items() if name.endswith("valid_saved_view_resource"))
    assert "findings" in resource_check
    assert "assets" in resource_check
    assert SavedView.__table__.c.organization_id.nullable is False


def test_saved_view_routes_are_mounted() -> None:
    from app.api.v1.router import api_router

    assert "/saved-views" in {route.path for route in api_router.routes}


def test_saved_view_creation_has_a_dedicated_audit_action() -> None:
    from app.services.audit import AuditAction

    assert AuditAction.SAVED_VIEW_CREATE == "saved_view.create"
    assert AuditAction.SAVED_VIEW_DELETE == "saved_view.delete"


def test_saved_view_router_exposes_deletion() -> None:
    from app.api.v1.saved_views import router

    assert "/saved-views/{view_id}" in {route.path for route in router.routes}


def test_saved_view_router_exposes_tenant_safe_updates() -> None:
    """A saved view remains useful when its name or filters change."""
    from fastapi import status

    from app.api.v1.saved_views import router

    update_routes = [
        route
        for route in router.routes
        if route.path == "/saved-views/{view_id}" and "PUT" in route.methods
    ]

    assert len(update_routes) == 1
    assert update_routes[0].status_code == status.HTTP_200_OK


def test_saved_view_updates_have_a_dedicated_audit_action() -> None:
    from app.services.audit import AuditAction

    assert AuditAction.SAVED_VIEW_UPDATE == "saved_view.update"


def test_saved_view_update_requires_a_change_and_validates_filters_for_existing_resource() -> None:
    from pydantic import ValidationError

    from app.schemas.saved_view import SavedViewUpdateIn

    assert SavedViewUpdateIn(name="Triage queue").model_dump(exclude_unset=True) == {
        "name": "Triage queue"
    }
    assert SavedViewUpdateIn(filters={"severity": "critical"}).model_dump(
        exclude_unset=True
    ) == {"filters": {"severity": "critical"}}

    with pytest.raises(ValidationError, match="at least one"):
        SavedViewUpdateIn()
    with pytest.raises(ValidationError, match="unsupported"):
        SavedViewUpdateIn(filters={"not_a_filter": "value"})
