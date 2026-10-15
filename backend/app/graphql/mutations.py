"""Service-backed, retry-safe mutations for custom agent administration."""

from __future__ import annotations

import strawberry
from pydantic import ValidationError
from strawberry.scalars import JSON
from strawberry.types import Info

from app.api.deps import require_custom_agents, require_internal_knowledge
from app.db.enums import Permission
from app.db.models.agent_definition import AgentDefinition, AgentDefinitionVersion
from app.db.models.knowledge import KnowledgeCollection
from app.db.repository import tenant_select
from app.graphql.context import require_context
from app.graphql.errors import PublicGraphQLError
from app.graphql.ids import decode_global_id
from app.graphql.types import (
    AgentDefinitionNode,
    AgentDefinitionVersionNode,
    KnowledgeCollectionNode,
)
from app.schemas.agent_definition import AgentDefinitionCreateIn, AgentVersionCreateIn
from app.schemas.knowledge import KnowledgeCollectionCreateIn
from app.services import agent_definition as agent_service
from app.services.graphql_idempotency import input_digest, reserve
from app.services.knowledge_ingest import create_collection


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


@strawberry.input
class CreateAgentDefinitionVersionInput:
    idempotency_key: str
    client_mutation_id: str
    agent_definition_id: strawberry.ID
    expected_active_version_id: strawberry.ID
    role: str
    instructions: str
    provider: str
    model: str
    autonomy_mode: str = "supervised"
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


@strawberry.input
class DisableAgentDefinitionInput:
    idempotency_key: str
    client_mutation_id: str
    agent_definition_id: strawberry.ID


@strawberry.input
class CreateKnowledgeCollectionInput:
    idempotency_key: str
    client_mutation_id: str
    name: str
    description: str | None = None
    retrieval_provider: str = "internal"
    retrieval_policy: JSON | None = None


@strawberry.type
class AgentDefinitionMutationPayload:
    agent: AgentDefinitionNode
    client_mutation_id: str


@strawberry.type
class AgentDefinitionVersionMutationPayload:
    version: AgentDefinitionVersionNode
    client_mutation_id: str


@strawberry.type
class KnowledgeCollectionMutationPayload:
    collection: KnowledgeCollectionNode
    client_mutation_id: str


def _client_mutation_id(value: str) -> str:
    if not value or len(value) > 160:
        raise PublicGraphQLError(
            "BAD_USER_INPUT",
            "Client mutation ID must contain 1 to 160 characters.",
        )
    return value


def _configuration_payload(
    value: CreateAgentDefinitionInput | CreateAgentDefinitionVersionInput,
) -> dict:
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
    return {
        "role": value.role,
        "instructions": value.instructions,
        "provider": value.provider,
        "model": value.model,
        "autonomy_mode": value.autonomy_mode,
        "temperature": value.temperature,
        "max_output_tokens": value.max_output_tokens,
        "max_parallel_tasks": value.max_parallel_tasks,
        "max_runtime_seconds": value.max_runtime_seconds,
        "max_tool_calls": value.max_tool_calls,
        "max_input_tokens": value.max_input_tokens,
        "max_estimated_spend_micros": spend,
        "scope_policy": dict(value.scope_policy or {}),
        "retrieval_policy": dict(value.retrieval_policy or {}),
        "tool_names": list(value.tool_names),
        "collection_ids": [
            decode_global_id(str(identifier), "KnowledgeCollection")
            for identifier in value.collection_ids
        ],
    }


def _validated_agent_payload(value: CreateAgentDefinitionInput) -> AgentDefinitionCreateIn:
    try:
        return AgentDefinitionCreateIn(
            name=value.name,
            description=value.description,
            avatar_reference=value.avatar_reference,
            **_configuration_payload(value),
        )
    except ValidationError as exc:
        raise PublicGraphQLError("BAD_USER_INPUT", "Agent configuration is invalid.") from exc


def _validated_version_payload(
    value: CreateAgentDefinitionVersionInput,
) -> AgentVersionCreateIn:
    try:
        return AgentVersionCreateIn(
            expected_active_version_id=decode_global_id(
                str(value.expected_active_version_id), "AgentDefinitionVersion"
            ),
            **_configuration_payload(value),
        )
    except ValidationError as exc:
        raise PublicGraphQLError("BAD_USER_INPUT", "Agent configuration is invalid.") from exc


def _validated_collection_payload(
    value: CreateKnowledgeCollectionInput,
) -> KnowledgeCollectionCreateIn:
    if value.retrieval_policy is not None and not isinstance(value.retrieval_policy, dict):
        raise PublicGraphQLError("BAD_USER_INPUT", "Retrieval policy must be an object.")
    try:
        return KnowledgeCollectionCreateIn(
            name=value.name,
            description=value.description,
            retrieval_provider=value.retrieval_provider,
            retrieval_policy=dict(value.retrieval_policy or {}),
        )
    except ValidationError as exc:
        raise PublicGraphQLError(
            "BAD_USER_INPUT", "Knowledge collection configuration is invalid."
        ) from exc


@strawberry.type
class AgentMutations:
    @strawberry.mutation
    async def create_agent_definition(
        self, info: Info, input: CreateAgentDefinitionInput
    ) -> AgentDefinitionMutationPayload:
        context = require_context(info)
        require_custom_agents(context.settings)
        context.principal.require(Permission.ORG_MANAGE)
        _client_mutation_id(input.client_mutation_id)
        payload = _validated_agent_payload(input)
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

    @strawberry.mutation
    async def create_agent_definition_version(
        self, info: Info, input: CreateAgentDefinitionVersionInput
    ) -> AgentDefinitionVersionMutationPayload:
        context = require_context(info)
        require_custom_agents(context.settings)
        context.principal.require(Permission.ORG_MANAGE)
        _client_mutation_id(input.client_mutation_id)
        agent_id = decode_global_id(str(input.agent_definition_id), "AgentDefinition")
        payload = _validated_version_payload(input)
        digest = input_digest(
            {
                "agent_definition_id": str(agent_id),
                "configuration": payload.model_dump(mode="json"),
            }
        )
        async with context.session_factory() as session:
            receipt, replayed = await reserve(
                session,
                context.principal,
                operation="createAgentDefinitionVersion",
                idempotency_key=input.idempotency_key,
                digest=digest,
            )
            if replayed:
                row = await session.scalar(
                    tenant_select(
                        AgentDefinitionVersion, context.principal.organization_id
                    ).where(
                        AgentDefinitionVersion.id == receipt.resource_id,
                        AgentDefinitionVersion.agent_definition_id == agent_id,
                    )
                )
                if row is None:
                    raise PublicGraphQLError(
                        "RESOURCE_NOT_FOUND", "The mutation result is no longer available."
                    )
            else:
                row = await agent_service.create_agent_version(
                    session,
                    context.principal,
                    agent_id,
                    payload,
                )
                receipt.resource_type = "AgentDefinitionVersion"
                receipt.resource_id = row.id
            await session.flush()
            await session.refresh(row)
            projected = AgentDefinitionVersionNode.from_row(row)
            await session.commit()
        return AgentDefinitionVersionMutationPayload(
            version=projected,
            client_mutation_id=input.client_mutation_id,
        )

    @strawberry.mutation
    async def disable_agent_definition(
        self, info: Info, input: DisableAgentDefinitionInput
    ) -> AgentDefinitionMutationPayload:
        context = require_context(info)
        require_custom_agents(context.settings)
        context.principal.require(Permission.ORG_MANAGE)
        _client_mutation_id(input.client_mutation_id)
        agent_id = decode_global_id(str(input.agent_definition_id), "AgentDefinition")
        digest = input_digest({"agent_definition_id": str(agent_id)})
        async with context.session_factory() as session:
            receipt, replayed = await reserve(
                session,
                context.principal,
                operation="disableAgentDefinition",
                idempotency_key=input.idempotency_key,
                digest=digest,
            )
            if replayed:
                row = await session.scalar(
                    tenant_select(AgentDefinition, context.principal.organization_id).where(
                        AgentDefinition.id == receipt.resource_id,
                        AgentDefinition.id == agent_id,
                    )
                )
                if row is None:
                    raise PublicGraphQLError(
                        "RESOURCE_NOT_FOUND", "The mutation result is no longer available."
                    )
            else:
                row = await agent_service.disable_agent(
                    session,
                    context.principal,
                    agent_id,
                )
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

    @strawberry.mutation
    async def create_knowledge_collection(
        self, info: Info, input: CreateKnowledgeCollectionInput
    ) -> KnowledgeCollectionMutationPayload:
        context = require_context(info)
        require_internal_knowledge(context.settings)
        context.principal.require(Permission.ORG_MANAGE)
        _client_mutation_id(input.client_mutation_id)
        payload = _validated_collection_payload(input)
        digest = input_digest(payload.model_dump(mode="json"))
        async with context.session_factory() as session:
            receipt, replayed = await reserve(
                session,
                context.principal,
                operation="createKnowledgeCollection",
                idempotency_key=input.idempotency_key,
                digest=digest,
            )
            if replayed:
                row = await session.scalar(
                    tenant_select(
                        KnowledgeCollection, context.principal.organization_id
                    ).where(KnowledgeCollection.id == receipt.resource_id)
                )
                if row is None:
                    raise PublicGraphQLError(
                        "RESOURCE_NOT_FOUND", "The mutation result is no longer available."
                    )
            else:
                row = await create_collection(session, context.principal, payload)
                receipt.resource_type = "KnowledgeCollection"
                receipt.resource_id = row.id
            await session.flush()
            await session.refresh(row)
            projected = KnowledgeCollectionNode.from_row(row)
            await session.commit()
        return KnowledgeCollectionMutationPayload(
            collection=projected,
            client_mutation_id=input.client_mutation_id,
        )


__all__ = ["AgentMutations"]
