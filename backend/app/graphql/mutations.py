"""Service-backed, retry-safe mutations for custom agent administration."""

from __future__ import annotations

import strawberry
from pydantic import ValidationError
from strawberry.scalars import JSON
from strawberry.types import Info

from app.api.deps import require_custom_agents
from app.db.enums import Permission
from app.db.models.agent_definition import AgentDefinition
from app.db.repository import tenant_select
from app.graphql.context import require_context
from app.graphql.errors import PublicGraphQLError
from app.graphql.ids import decode_global_id
from app.graphql.types import AgentDefinitionNode
from app.schemas.agent_definition import AgentDefinitionCreateIn
from app.services import agent_definition as agent_service
from app.services.graphql_idempotency import input_digest, reserve


@strawberry.input
class CreateAgentDefinitionInput:
    idempotency_key: str
    client_mutation_id: str
    name: str
    role: str
    instructions: str
    provider: str
    model: str
    autonomy_mode: str = "supervised"
    description: str | None = None
    avatar_reference: str | None = None
    temperature: float = 0
    max_output_tokens: int = 4096
    max_parallel_tasks: int = 1
    max_runtime_seconds: int = 900
    max_tool_calls: int = 20
    max_input_tokens: int = 100_000
    max_estimated_spend_micros: str = "1000000"
    scope_policy: JSON | None = None
    retrieval_policy: JSON | None = None
    tool_names: list[str] = strawberry.field(default_factory=list)
    collection_ids: list[strawberry.ID] = strawberry.field(default_factory=list)


@strawberry.type
class AgentDefinitionMutationPayload:
    agent: AgentDefinitionNode
    client_mutation_id: str


def _validated_payload(value: CreateAgentDefinitionInput) -> AgentDefinitionCreateIn:
    try:
        spend = int(value.max_estimated_spend_micros)
    except (TypeError, ValueError) as exc:
        raise PublicGraphQLError(
            "BAD_USER_INPUT", "Estimated spend must be a decimal integer string."
        ) from exc
    if value.scope_policy is not None and not isinstance(value.scope_policy, dict):
        raise PublicGraphQLError("BAD_USER_INPUT", "Scope policy must be an object.")
    if value.retrieval_policy is not None and not isinstance(value.retrieval_policy, dict):
        raise PublicGraphQLError("BAD_USER_INPUT", "Retrieval policy must be an object.")
    try:
        return AgentDefinitionCreateIn(
            name=value.name,
            description=value.description,
            avatar_reference=value.avatar_reference,
            role=value.role,
            instructions=value.instructions,
            provider=value.provider,
            model=value.model,
            autonomy_mode=value.autonomy_mode,
            temperature=value.temperature,
            max_output_tokens=value.max_output_tokens,
            max_parallel_tasks=value.max_parallel_tasks,
            max_runtime_seconds=value.max_runtime_seconds,
            max_tool_calls=value.max_tool_calls,
            max_input_tokens=value.max_input_tokens,
            max_estimated_spend_micros=spend,
            scope_policy=dict(value.scope_policy or {}),
            retrieval_policy=dict(value.retrieval_policy or {}),
            tool_names=list(value.tool_names),
            collection_ids=[
                decode_global_id(str(identifier), "KnowledgeCollection")
                for identifier in value.collection_ids
            ],
        )
    except ValidationError as exc:
        raise PublicGraphQLError("BAD_USER_INPUT", "Agent configuration is invalid.") from exc


@strawberry.type
class AgentMutations:
    @strawberry.mutation
    async def create_agent_definition(
        self, info: Info, input: CreateAgentDefinitionInput
    ) -> AgentDefinitionMutationPayload:
        context = require_context(info)
        require_custom_agents(context.settings)
        context.principal.require(Permission.ORG_MANAGE)
        if not input.client_mutation_id or len(input.client_mutation_id) > 160:
            raise PublicGraphQLError(
                "BAD_USER_INPUT",
                "Client mutation ID must contain 1 to 160 characters.",
            )
        payload = _validated_payload(input)
        digest = input_digest(payload.model_dump(mode="json"))
        async with context.session_factory() as session:
            receipt, replayed = await reserve(
                session,
                context.principal,
                operation="createAgentDefinition",
                idempotency_key=input.idempotency_key,
                digest=digest,
            )
            if replayed:
                row = await session.scalar(
                    tenant_select(AgentDefinition, context.principal.organization_id).where(
                        AgentDefinition.id == receipt.resource_id
                    )
                )
                if row is None:
                    raise PublicGraphQLError(
                        "RESOURCE_NOT_FOUND", "The mutation result is no longer available."
                    )
            else:
                row = await agent_service.create_agent(session, context.principal, payload)
                receipt.resource_type = "AgentDefinition"
                receipt.resource_id = row.id
            await session.flush()
            await session.refresh(row)
            projected = AgentDefinitionNode.from_row(row)
            await session.commit()
        return AgentDefinitionMutationPayload(
            agent=projected,
            client_mutation_id=input.client_mutation_id,
        )


__all__ = ["AgentMutations"]
