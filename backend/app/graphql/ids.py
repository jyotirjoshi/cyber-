"""Opaque typed identifiers; decoding never grants authority."""
import base64
import binascii
import uuid

from app.graphql.errors import PublicGraphQLError


def encode_global_id(type_name: str, identifier: uuid.UUID) -> str:
    return base64.urlsafe_b64encode(f"{type_name}:{identifier}".encode()).decode()


def decode_global_id(value: str, expected_type: str) -> uuid.UUID:
    try:
        if len(value) > 256:
            raise ValueError
        decoded = base64.b64decode(value, altchars=b"-_", validate=True).decode("ascii")
        type_name, identifier = decoded.split(":", 1)
        if type_name != expected_type:
            raise ValueError
        return uuid.UUID(identifier)
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise PublicGraphQLError("NOT_FOUND", "Resource not found.") from exc
