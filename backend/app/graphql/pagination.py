"""Tenant/connection-bound signed keyset cursors with a bounded lifetime."""
import base64
import binascii
import datetime as dt
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

    @staticmethod
    def _serialize_sort(value: str | int | dt.datetime) -> list[object]:
        if isinstance(value, bool):
            raise PublicGraphQLError("INVALID_CURSOR", "Invalid cursor sort value.")
        if isinstance(value, int):
            return ["i", value]
        if isinstance(value, dt.datetime):
            if value.tzinfo is None:
                raise PublicGraphQLError("INVALID_CURSOR", "Invalid cursor sort value.")
            return ["d", value.astimezone(dt.UTC).isoformat()]
        if isinstance(value, str) and len(value) <= 500:
            return ["s", value]
        raise PublicGraphQLError("INVALID_CURSOR", "Invalid cursor sort value.")

    @staticmethod
    def _deserialize_sort(value: object) -> str | int | dt.datetime:
        if not isinstance(value, list) or len(value) != 2:
            raise ValueError
        kind, raw = value
        if kind == "i" and isinstance(raw, int) and not isinstance(raw, bool):
            return raw
        if kind == "s" and isinstance(raw, str) and len(raw) <= 500:
            return raw
        if kind == "d" and isinstance(raw, str):
            parsed = dt.datetime.fromisoformat(raw)
            if parsed.tzinfo is not None:
                return parsed.astimezone(dt.UTC)
        raise ValueError

    def encode(self, sort_value: str | int | dt.datetime, identifier: uuid.UUID) -> str:
        payload = json.dumps(
            [
                1,
                self.organization_id,
                self.connection,
                self._serialize_sort(sort_value),
                str(identifier),
                int(self.clock()),
            ],
            separators=(",", ":"),
        ).encode()
        signature = hmac.digest(self.key, payload, hashlib.sha256)
        return base64.urlsafe_b64encode(signature + payload).decode()

    def decode(self, cursor: str) -> tuple[str | int | dt.datetime, uuid.UUID]:
        try:
            if not cursor or len(cursor) > 4096:
                raise ValueError
            raw = base64.b64decode(cursor, altchars=b"-_", validate=True)
            signature, payload = raw[:32], raw[32:]
            if not hmac.compare_digest(signature, hmac.digest(self.key, payload, hashlib.sha256)):
                raise ValueError
            version, org, connection, sort_value, identifier, issued = json.loads(payload)
            if version != 1 or org != self.organization_id or connection != self.connection:
                raise ValueError
            if not isinstance(issued, int) or isinstance(issued, bool):
                raise ValueError
            if not 0 <= self.clock() - issued <= 86400:
                raise ValueError
            return self._deserialize_sort(sort_value), uuid.UUID(identifier)
        except (ValueError, TypeError, UnicodeError, binascii.Error) as exc:
            raise PublicGraphQLError(
                "INVALID_CURSOR", "Invalid cursor; restart pagination."
            ) from exc
