"""The agent run-request queue contract shared by the API and the worker (FR-033; §54, §57).

An assessment is driven by a background worker, never inside the request that created it: the
API validates the target, records the authorization, creates the ``AgentRun`` row and then
*enqueues* a request here for a worker to pick up.  A Redis Stream (not a fire-and-forget
pub/sub message) is what makes that durable -- a request sits in the stream, and then in a
consumer group's pending-entries list once claimed, until a worker acknowledges it, so an
assessment survives the worker running it crashing (FR-033): another worker reclaims the idle
pending entry and resumes from the LangGraph checkpoint.

This module is deliberately the whole contract and nothing else.  It imports neither LangGraph
nor the agent runtime, so the API process can publish a run without loading the graph, and it
speaks only in the flat ``dict[str, str]`` field map a stream entry actually stores:

* :class:`RunAction` -- START a freshly-queued run or RESUME one past the approval gate.  It is
  *advisory*: the runner decides what to actually do from the run's own database status -- a
  reclaim re-presents the original message unchanged (FR-011, FR-033) -- so the action is
  really the carrier for "does this message bring a principal to seed a fresh run with".
* :class:`RunRequest` -- one message: the run id, the action, when it was enqueued, and, for a
  START, the JSON-safe :class:`~app.services.context.Principal` dict the run must execute under.
  The principal rides the message rather than being re-derived in the worker so the run acts
  with the initiating operator's own authority and never a superuser's; it carries no secret
  (SEC-002), which is what lets it cross the process boundary at all.

Robust decoding matters as much as encoding: :meth:`RunRequest.from_fields` raises
:class:`ValueError` on anything it cannot parse, so the worker can treat a bad entry as a
poison message -- acknowledge and drop -- and one malformed message cannot wedge the consumer
group.  No error raised here ever quotes the principal payload (SEC-002).
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast

from redis.asyncio.client import Redis
from redis.typing import EncodableT, FieldT

from app.core.config import Settings

# ``RunAction`` is a wire-protocol vocabulary, not a persisted domain value, but it reuses the
# project's string-enum base (a stdlib-only leaf) so ``.value`` serialization and equality
# behave exactly as every other enum in the codebase.
from app.db.enums import StrEnum


class RunAction(StrEnum):
    """What a queue message asks the worker to do -- advisory; DB status is the authority.

    The distinction the worker actually acts on is whether the message carries a principal to
    seed a fresh run with (``START``) or resumes an existing checkpoint (``RESUME``).  A crash
    reclaim re-delivers the original message, so :meth:`~app.agent.runner.AgentRunner.advance`
    never trusts this field over the run's recorded status (FR-011, FR-033).
    """

    START = "start"
    RESUME = "resume"


@dataclass(frozen=True, slots=True)
class RunRequest:
    """One agent run request as it travels the stream.

    Frozen and JSON-safe end to end: the id is stringified and the principal is its
    credential-free ``to_dict`` form, so the message survives a stream round-trip and a worker
    process boundary unchanged.
    """

    run_id: uuid.UUID
    action: RunAction
    #: ISO-8601 UTC instant the request was enqueued, for queue-latency observability.
    enqueued_at: str
    #: ``Principal.to_dict()`` for a START (the authority to seed the run under); ``None`` for a
    #: RESUME, where the principal is recovered from the checkpoint instead.
    principal: dict[str, Any] | None = None

    @classmethod
    def new(
        cls,
        run_id: uuid.UUID,
        action: RunAction,
        *,
        principal: dict[str, Any] | None = None,
    ) -> RunRequest:
        """Build a request stamped with the current time.

        The one constructor callers should use, so ``enqueued_at`` is always set and always in
        the same format.  ``principal`` is the initiator's :meth:`Principal.to_dict` for a START
        and omitted for a RESUME.
        """
        return cls(
            run_id=run_id,
            action=action,
            enqueued_at=dt.datetime.now(dt.UTC).isoformat(),
            principal=principal,
        )

    def to_fields(self) -> dict[str, str]:
        """Flatten to the stream entry's field map (every value a string).

        The principal, itself a nested object, is JSON-encoded into a single field, and is
        omitted entirely when absent rather than written as an empty value -- so a RESUME
        message carries no principal key at all.
        """
        fields = {
            "run_id": str(self.run_id),
            "action": self.action.value,
            "enqueued_at": self.enqueued_at,
        }
        if self.principal is not None:
            fields["principal"] = json.dumps(self.principal, separators=(",", ":"))
        return fields

    @classmethod
    def from_fields(cls, fields: Mapping[str, str]) -> RunRequest:
        """Rebuild from a stream entry, raising :class:`ValueError` on a malformed message.

        Every failure mode -- a missing or non-UUID ``run_id``, a missing or unknown
        ``action``, a principal field that is not a JSON object -- becomes a ``ValueError`` so
        the worker can catch exactly that, log it as a poison message, acknowledge it and move
        on rather than let it be redelivered forever.  The raised message names neither the
        principal value nor its contents (SEC-002).
        """
        try:
            run_id = uuid.UUID(fields["run_id"])
            action = RunAction(fields["action"])
        except (KeyError, ValueError) as exc:
            raise ValueError(f"malformed run request: {type(exc).__name__}") from exc
        return cls(
            run_id=run_id,
            action=action,
            enqueued_at=fields.get("enqueued_at", ""),
            principal=_decode_principal(fields.get("principal")),
        )


def _decode_principal(raw: str | None) -> dict[str, Any] | None:
    """Decode the optional JSON principal field, or refuse a non-object.

    Absent or empty means a RESUME with no principal (``None``).  A present value must decode to
    a JSON object; anything else is a malformed message.  The error text names neither the value
    nor its contents (SEC-002).
    """
    if not raw:
        return None
    try:
        decoded = json.loads(raw)
    except ValueError as exc:
        raise ValueError("run request principal is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise ValueError("run request principal is not a JSON object")
    return decoded


async def publish_run_request(redis: Redis, settings: Settings, request: RunRequest) -> str:
    """``XADD`` a run request onto the agent stream, capped at ``max_stream_length``.

    Returns the stream entry id, which the API logs to correlate the enqueue with the run.  The
    length cap is approximate (``MAXLEN ~``) because an exact trim would serialize every writer
    on the stream's tail; the stream is a work queue whose entries are short-lived once
    acknowledged, so a few thousand beyond the cap between trims is harmless.
    """
    message_id = await redis.xadd(
        settings.redis.stream,
        # ``to_fields`` honestly returns ``dict[str, str]``; ``xadd`` types its field map as
        # ``dict[FieldT, EncodableT]`` (str is a member of both unions).  Every value we pass is
        # a valid field, but ``dict`` is invariant in its key and value types, so the assignment
        # needs a cast to bridge the invariance -- it encodes a relationship the type system
        # cannot express, not a claim the checker cannot otherwise verify.
        cast(dict[FieldT, EncodableT], request.to_fields()),
        maxlen=settings.redis.max_stream_length,
        approximate=True,
    )
    return message_id


__all__ = [
    "RunAction",
    "RunRequest",
    "publish_run_request",
]
