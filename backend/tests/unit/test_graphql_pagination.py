"""Cursors must not cross tenants or connection boundaries."""
import uuid

import pytest


def test_cursor_round_trip_and_scope_binding():
    from app.graphql.errors import PublicGraphQLError
    from app.graphql.pagination import CursorCodec

    org, identifier = uuid.uuid4(), uuid.uuid4()
    codec = CursorCodec("s" * 32, org, "agentDefinitions")
    cursor = codec.encode("Agent A", identifier)
    assert codec.decode(cursor) == ("Agent A", identifier)
    for other in (
        CursorCodec("s" * 32, uuid.uuid4(), "agentDefinitions"),
        CursorCodec("s" * 32, org, "knowledgeCollections"),
        CursorCodec("x" * 32, org, "agentDefinitions"),
    ):
        with pytest.raises(PublicGraphQLError, match="Invalid cursor"):
            other.decode(cursor)


@pytest.mark.parametrize("value", ["", "nonsense", "a.b.c", "a" * 5000])
def test_malformed_cursor_is_rejected(value):
    from app.graphql.errors import PublicGraphQLError
    from app.graphql.pagination import CursorCodec

    with pytest.raises(PublicGraphQLError, match="Invalid cursor"):
        CursorCodec("s" * 32, uuid.uuid4(), "agentDefinitions").decode(value)


def test_expired_cursor_and_invalid_limits_are_rejected():
    from app.graphql.errors import PublicGraphQLError
    from app.graphql.pagination import CursorCodec, page_size

    codec = CursorCodec("s" * 32, uuid.uuid4(), "agentDefinitions", clock=lambda: 1)
    cursor = codec.encode("A", uuid.uuid4())
    codec.clock = lambda: 100000
    with pytest.raises(PublicGraphQLError):
        codec.decode(cursor)
    assert page_size(None) == 25
    assert page_size(100) == 100
    for invalid in (0, -1, 101):
        with pytest.raises(PublicGraphQLError):
            page_size(invalid)


def test_global_ids_validate_type_and_format():
    from app.graphql.errors import PublicGraphQLError
    from app.graphql.ids import decode_global_id, encode_global_id

    identifier = uuid.uuid4()
    encoded = encode_global_id("AgentDefinition", identifier)
    assert decode_global_id(encoded, "AgentDefinition") == identifier
    for invalid in (encoded, "not-base64", "", "x" * 1000):
        with pytest.raises(PublicGraphQLError):
            decode_global_id(invalid, "KnowledgeCollection")
