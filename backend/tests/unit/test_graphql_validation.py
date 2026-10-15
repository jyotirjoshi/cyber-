"""Reject expensive documents before any business resolver is evaluated."""
import pytest

from app.graphql.schema import schema


@pytest.mark.asyncio
async def test_alias_fanout_is_rejected_before_auth_or_database():
    query = (
        "{ "
        + " ".join(f"a{i}: agentDefinitions(first: 100) {{ nodes {{ name }} }}" for i in range(60))
        + " }"
    )
    result = await schema.execute(query)
    assert result.errors[0].extensions["code"] == "QUERY_TOO_COMPLEX"


@pytest.mark.asyncio
async def test_fragment_expansion_cannot_hide_query_cost():
    query = (
        "{ "
        + " ".join(f"a{i}: agentDefinitions(first: 100) {{ ...Fields }}" for i in range(15))
        + " } fragment Fields on AgentDefinitionConnection { nodes { id name description versionCount isEnabled } }"
    )
    result = await schema.execute(query)
    assert result.errors[0].extensions["code"] == "QUERY_TOO_COMPLEX"


@pytest.mark.asyncio
async def test_public_introspection_is_disabled():
    result = await schema.execute("{ __schema { queryType { name } } }")
    assert result.errors[0].extensions["code"] == "INTROSPECTION_DISABLED"


@pytest.mark.asyncio
async def test_variable_pagination_counts_toward_budget():
    fields = " ".join(
        f"a{i}: agentDefinitions(first: $count) {{ nodes {{ id name description }} }}"
        for i in range(20)
    )
    result = await schema.execute(
        "query($count: Int!) {" + fields + "}", variable_values={"count": 100}
    )
    assert result.errors[0].extensions["code"] == "QUERY_TOO_COMPLEX"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "parent_argument"),
    (
        ("agentDefinitionVersions", 'agentDefinitionId: "opaque"'),
        ("knowledgeSources", 'collectionId: "opaque"'),
    ),
)
async def test_nested_connections_count_pagination_toward_budget(field, parent_argument):
    selections = " ".join(
        f"a{i}: {field}({parent_argument}, first: 100) "
        "{ nodes { id createdAt __typename } }"
        for i in range(20)
    )
    result = await schema.execute("{ " + selections + " }")
    assert result.errors[0].extensions["code"] == "QUERY_TOO_COMPLEX"


@pytest.mark.asyncio
async def test_cyclic_fragments_and_oversized_documents_are_bounded():
    result = await schema.execute("{ ...Cycle } fragment Cycle on Query { ...Cycle }")
    assert result.errors[0].extensions["code"] == "QUERY_TOO_COMPLEX"
    result = await schema.execute("{ system { apiVersion } }" + " " * 65_536)
    assert result.errors[0].extensions["code"] == "QUERY_TOO_LARGE"
