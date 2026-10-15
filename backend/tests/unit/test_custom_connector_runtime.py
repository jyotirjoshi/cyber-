import pytest
from app.core.errors import InvalidConfigurationError
from app.schemas.custom_connector import CustomConnectorIn
from app.services.custom_connector import map_record, validate_definition


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
