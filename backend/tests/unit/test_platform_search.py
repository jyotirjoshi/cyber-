"""Cross-product search stays tenant-scoped and resists wildcard broadening."""

from app.api.v1.router import api_router


def test_global_search_route_is_mounted() -> None:
    paths = {route.path for route in api_router.routes}
    assert "/platform/search" in paths
    assert "/platform/demo-workspace" in paths


def test_search_pattern_escapes_sql_wildcards() -> None:
    from app.services.platform_search import search_pattern

    assert search_pattern("  prod%_api  ") == "%prod\\%\\_api%"


def test_demo_fingerprint_is_tenant_stable_and_entity_specific() -> None:
    import uuid

    from app.services.demo_workspace import demo_fingerprint

    organization_id = uuid.UUID("00000000-0000-0000-0000-000000000123")
    assert demo_fingerprint(organization_id, "finding:web") == demo_fingerprint(
        organization_id, "finding:web"
    )
    assert demo_fingerprint(organization_id, "finding:web") != demo_fingerprint(
        organization_id, "finding:cloud"
    )


def test_demo_report_document_is_downloadable_json() -> None:
    import json

    from app.services.demo_workspace import demo_report_document

    document = demo_report_document(
        assessment_reference=7,
        assessment_id="00000000-0000-0000-0000-000000000007",
    )
    payload = json.loads(document)
    assert payload["schema_version"] == "1.0"
    assert payload["assessment"]["reference"] == 7
    assert payload["summary"] == {"assets": 3, "critical": 1, "findings": 3}
    assert len(payload["attack_paths"]) == 1
