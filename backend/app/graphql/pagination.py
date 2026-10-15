"""Tenant/connection-bound signed keyset cursors with a bounded lifetime."""
import base64
import binascii
import hashlib
import hmac
import json
import time
import uuid
from collections.abc import Callable

from app.graphql.errors import PublicGraphQLError


def page_size(first: int | None) -> int:
    value = 25 if first is None else first
    if not 1 <= value <= 100:
        raise PublicGraphQLError("INVALID_PAGE_SIZE", "Page size must be between 1 and 100.")
    return value


class CursorCodec:
    def __init__(
        self,
        secret: str,
        organization_id: uuid.UUID,
        connection: str,
        *,
        clock: Callable[[], float] = time.time,
    ):
        if len(secret) < 32:
            raise PublicGraphQLError("UNAVAILABLE", "Pagination is not configured.")
        self.key = hmac.digest(secret.encode(), b"cynux:graphql:cursor:v1", "sha256")
        self.organization_id = str(organization_id)
        self.connection = connection
        self.clock = clock

    def encode(self, name: str, identifier: uuid.UUID) -> str:
        payload = json.dumps(
            [1, self.organization_id, self.connection, name, str(identifier), int(self.clock())],
            separators=(",", ":"),
        ).encode()
        signature = hmac.digest(self.key, payload, hashlib.sha256)
        return base64.urlsafe_b64encode(signature + payload).decode()

    def decode(self, cursor: str) -> tuple[str, uuid.UUID]:
        try:
            if not cursor or len(cursor) > 4096:
                raise ValueError
            raw = base64.b64decode(cursor, altchars=b"-_", validate=True)
            signature, payload = raw[:32], raw[32:]
            if not hmac.compare_digest(signature, hmac.digest(self.key, payload, hashlib.sha256)):
                raise ValueError
            version, org, connection, name, identifier, issued = json.loads(payload)
            if version != 1 or org != self.organization_id or connection != self.connection:
                raise ValueError
            if (
                not isinstance(name, str)
                or len(name) > 160
                or not isinstance(issued, int)
                or isinstance(issued, bool)
            ):
                raise ValueError
            if not 0 <= self.clock() - issued <= 86400:
                raise ValueError
            return name, uuid.UUID(identifier)
        except (ValueError, TypeError, UnicodeError, binascii.Error) as exc:
            raise PublicGraphQLError(
                "INVALID_CURSOR", "Invalid cursor; restart pagination."
            ) from exc
