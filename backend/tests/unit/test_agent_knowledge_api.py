"""Public agent management contracts, policy preview, and learning authorization."""
import uuid

import pytest
from fastapi import FastAPI

from app.core.errors import PermissionDeniedError
from app.db.enums import Role
from app.services.context import Principal


def test_custom_agent_and_learning_routes_are_mounted_with_typed_contracts():
    from app.api.v1.router import api_router
    app = FastAPI()
    app.include_router(api_router, prefix="/api/v1")
    schema = app.openapi()
    for path in ("/agents/definitions", "/agents/tools", "/agents/definitions/{agent_id}/versions",
                 "/agents/definitions/{agent_id}/disable", "/agents/policy-preview",
                 "/agents/memory-candidates", "/agents/memory-candidates/{candidate_id}/approve"):
        assert "/api/v1" + path in schema["paths"]
    version = schema["components"]["schemas"]["AgentDefinitionVersionOut"]
    assert {"tool_names", "collection_ids"} <= version["properties"].keys()


@pytest.mark.asyncio
async def test_reader_cannot_create_custom_agent():
    from app.api.v1.agent_definitions import create_definition
    from app.schemas.agent_definition import AgentDefinitionCreateIn
    reader = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.VIEWER)
    with pytest.raises(PermissionDeniedError):
        await create_definition(AgentDefinitionCreateIn(name="Triage", role="Triager",
            instructions="Use evidence", provider="openai", model="my-model"), reader, None)


@pytest.mark.asyncio
async def test_policy_preview_excludes_mutations_in_manual_mode_and_gates_supervised():
    from app.api.v1.agent_definitions import preview_policy
    from app.schemas.agent_definition import AgentVersionConfigurationIn
    principal = Principal(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), role=Role.OWNER)
    payload = AgentVersionConfigurationIn(role="Triager", instructions="Use evidence", provider="openai",
        model="my-model", autonomy_mode="manual", tool_names=["read_assets", "sync_wazuh_alerts"])
    preview = await preview_policy(payload, principal)
    assert [tool.name for tool in preview.tools] == ["read_assets"]
    assert preview.rejected["sync_wazuh_alerts"] == "manual_mode"
    preview = await preview_policy(payload.model_copy(update={"autonomy_mode": "supervised"}), principal)
    assert next(tool for tool in preview.tools if tool.name == "sync_wazuh_alerts").approval == "always"
