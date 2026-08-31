"""Who is acting, and what they are allowed to do (FR-002, SEC-003).

Every service function that makes an authorization decision takes a :class:`Principal`.
It is deliberately a small frozen value object rather than the ORM ``User``:

* It carries the **resolved organization**, so no service has to re-derive the tenant
  from a token or a membership join.  ``organization_id`` is non-optional -- there is no
  such thing as a Cynux operation without a tenant, and making the field required means
  a caller cannot forget it.
* It carries a **role**, not a permission set.  The set is derived on read from
  :data:`~app.db.enums.PERMISSIONS`, so tightening a role's permissions takes effect
  immediately for principals already in flight rather than only for new logins.
* It is **serializable** (:meth:`Principal.to_dict`), because the LangGraph state dict
  has to carry it across a checkpoint and a worker process boundary.  It holds no
  credentials, which is what makes that safe (SEC-002).

The agent gets a principal too, and it is never more privileged than the human who
started the run -- see :meth:`Principal.for_agent`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from typing import Any, Final

from app.core.errors import PermissionDeniedError
from app.db.enums import PERMISSIONS, Permission, Role

# ---------------------------------------------------------------------------
# Actor types
# ---------------------------------------------------------------------------
#
# Plain string constants rather than a StrEnum in ``app.db.enums``: this vocabulary is
# named by exactly two places -- the ``audit_events.actor_type`` check constraint and
# this module -- and it does not grow with the agent's tool set the way the enums there
# do.  ``tests/unit/test_orm_models.py`` records the same reasoning from the other side.

ACTOR_USER: Final = "user"
#: The LangGraph agent acting inside a run. Distinguishing this from ``user`` is what
#: lets an audit review answer "did a person approve this, or did the agent?" (FR-032).
ACTOR_AGENT: Final = "agent"
#: A background worker executing queued work on nobody's behalf in particular.
ACTOR_WORKER: Final = "worker"
#: Cynux itself: scheduled sweeps, approval expiry, retention.
ACTOR_SYSTEM: Final = "system"

ACTOR_TYPES: Final[frozenset[str]] = frozenset(
    {ACTOR_USER, ACTOR_AGENT, ACTOR_WORKER, ACTOR_SYSTEM}
)


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated actor for one operation.

    Frozen because it is passed down through a call chain that must not be able to
    escalate it: a service that could do ``principal.role = Role.OWNER`` would make
    every permission check below it advisory.  Use :meth:`downgraded_to` to derive a
    *less* privileged principal, which is the only direction that is ever legitimate.
    """

    #: ``None`` only for non-human actors (``worker``, ``system``). An ``agent``
    #: principal keeps the initiating user's id so its actions remain attributable.
    user_id: uuid.UUID | None
    organization_id: uuid.UUID
    role: Role
    email: str | None = None
    actor_type: str = ACTOR_USER

    #: Request provenance, copied onto every audit row this principal produces.
    source_ip: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    trace_id: str | None = None

    def __post_init__(self) -> None:
        # Validated here rather than at the database boundary. ``actor_type`` reaches
        # ``audit_events`` through half a dozen services; catching a bad value at
        # construction names the caller, whereas the CHECK constraint fires later and
        # only reports that some audit insert failed.
        if self.actor_type not in ACTOR_TYPES:
            raise ValueError(f"actor_type {self.actor_type!r} is not one of {sorted(ACTOR_TYPES)}")
        if not isinstance(self.role, Role):  # pragma: no cover - defensive
            raise TypeError(f"role must be a Role, got {type(self.role).__name__}")

    # -- authorization -------------------------------------------------------

    @property
    def permissions(self) -> frozenset[Permission]:
        return PERMISSIONS[self.role]

    def has(self, permission: Permission) -> bool:
        return permission in PERMISSIONS[self.role]

    def has_all(self, *permissions: Permission) -> bool:
        return PERMISSIONS[self.role].issuperset(permissions)

    def require(self, *permissions: Permission) -> None:
        """Raise :class:`PermissionDeniedError` unless every permission is held.

        The exception's ``user_message`` names the role but not the missing permission:
        the permission vocabulary is internal, and telling a caller exactly which
        capability would have let the call through is more useful to someone probing
        the API than to the person who hit a genuine wall.  The detail goes in
        ``context``, which reaches the log and the audit row, not the response.
        """
        held = PERMISSIONS[self.role]
        missing = [p for p in permissions if p not in held]
        if missing:
            raise PermissionDeniedError(
                f"{self.role.value} lacks {', '.join(p.value for p in missing)}",
                context={
                    "role": self.role.value,
                    "missing_permissions": [p.value for p in missing],
                    "actor_type": self.actor_type,
                    "user_id": str(self.user_id) if self.user_id else None,
                },
            )

    # -- derivation ----------------------------------------------------------

    @classmethod
    def for_agent(
        cls,
        *,
        organization_id: uuid.UUID,
        on_behalf_of: Principal | None = None,
    ) -> Principal:
        """The principal the LangGraph run executes under.

        It inherits the initiating user's role, so the agent can never do something the
        person who asked for it could not do themselves.  With no initiating principal
        -- a worker resuming an orphaned run whose context was lost -- the role falls
        back to :attr:`Role.VIEWER` rather than to anything useful.  A run that then
        cannot execute its tools fails visibly, which is the correct outcome: the
        alternative is guessing at authority on behalf of an absent human.
        """
        if on_behalf_of is None:
            return cls(
                user_id=None,
                organization_id=organization_id,
                role=Role.VIEWER,
                actor_type=ACTOR_AGENT,
            )
        if on_behalf_of.organization_id != organization_id:
            # Not a recoverable mistake: it means a run is about to execute against one
            # tenant carrying another tenant's authority (SEC-003).
            raise PermissionDeniedError(
                "cannot derive an agent principal for a different organization",
                context={
                    "requested_organization_id": str(organization_id),
                    "principal_organization_id": str(on_behalf_of.organization_id),
                },
            )
        return cls(
            user_id=on_behalf_of.user_id,
            organization_id=organization_id,
            role=on_behalf_of.role,
            email=on_behalf_of.email,
            actor_type=ACTOR_AGENT,
            request_id=on_behalf_of.request_id,
            trace_id=on_behalf_of.trace_id,
        )

    @classmethod
    def for_system(
        cls,
        *,
        organization_id: uuid.UUID,
        request_id: str | None = None,
    ) -> Principal:
        """Cynux acting on its own behalf: expiry sweeps, retention, health probes.

        :attr:`Role.OWNER` because these operations are internal maintenance that no
        human requested; they are never reachable from an HTTP route, and giving them a
        low role would only mean the sweep silently skips rows it is supposed to touch.
        """
        return cls(
            user_id=None,
            organization_id=organization_id,
            role=Role.OWNER,
            actor_type=ACTOR_SYSTEM,
            request_id=request_id,
        )

    @classmethod
    def for_worker(
        cls,
        *,
        organization_id: uuid.UUID,
        role: Role,
        user_id: uuid.UUID | None = None,
        email: str | None = None,
        request_id: str | None = None,
        trace_id: str | None = None,
    ) -> Principal:
        """A worker executing queued work for a known user and role.

        The role is required rather than defaulted: the queue message carries it, and a
        default would quietly decide authorization for work the worker is only relaying.
        """
        return cls(
            user_id=user_id,
            organization_id=organization_id,
            role=role,
            email=email,
            actor_type=ACTOR_WORKER,
            request_id=request_id,
            trace_id=trace_id,
        )

    def downgraded_to(self, role: Role) -> Principal:
        """Derive a principal with a strictly lower-or-equal role.

        Refuses to go up. Escalation is the only thing this method could be misused for,
        and a raise here is much easier to notice than a privileged principal appearing
        halfway down a call stack.
        """
        if role.rank > self.role.rank:
            raise PermissionDeniedError(
                f"cannot escalate {self.role.value} to {role.value}",
                context={"from_role": self.role.value, "to_role": role.value},
            )
        return replace(self, role=role)

    def with_request_context(
        self,
        *,
        source_ip: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        trace_id: str | None = None,
    ) -> Principal:
        """Attach provenance without touching identity or authority."""
        return replace(
            self,
            source_ip=source_ip if source_ip is not None else self.source_ip,
            user_agent=user_agent if user_agent is not None else self.user_agent,
            request_id=request_id if request_id is not None else self.request_id,
            trace_id=trace_id if trace_id is not None else self.trace_id,
        )

    # -- serialization -------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Plain-JSON form for the LangGraph state dict and the queue message.

        UUIDs become strings because the checkpointer serializes state as JSON. Nothing
        here is a credential, which is why a principal may cross a process boundary at
        all -- see :meth:`from_dict` for why it is still re-validated on the way back.
        """
        return {
            "user_id": str(self.user_id) if self.user_id else None,
            "organization_id": str(self.organization_id),
            "role": self.role.value,
            "email": self.email,
            "actor_type": self.actor_type,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Principal:
        """Rebuild from :meth:`to_dict`, validating the parts that grant authority.

        ``Role(...)`` and the ``actor_type`` check in ``__post_init__`` both raise on an
        unrecognized value, so a checkpoint that was hand-edited or written by an older
        build cannot resurrect as a principal with an unknown -- and therefore
        unenforceable -- role.  It is not a substitute for the structural approval check
        in ``app/agent/nodes/scan.py``: a *valid* principal can still be replayed, so
        authority to scan is re-read from the ``approvals`` table rather than trusted
        from state.
        """
        org = raw.get("organization_id")
        if not org:
            raise ValueError("principal state is missing organization_id")
        user_id = raw.get("user_id")
        return cls(
            user_id=uuid.UUID(str(user_id)) if user_id else None,
            organization_id=uuid.UUID(str(org)),
            role=Role(raw["role"]),
            email=raw.get("email"),
            actor_type=str(raw.get("actor_type") or ACTOR_USER),
            request_id=raw.get("request_id"),
            trace_id=raw.get("trace_id"),
        )

    # -- observability -------------------------------------------------------

    def to_log_fields(self) -> dict[str, Any]:
        return {
            "organization_id": str(self.organization_id),
            "user_id": str(self.user_id) if self.user_id else None,
            "role": self.role.value,
            "actor_type": self.actor_type,
        }

    @property
    def is_human(self) -> bool:
        return self.actor_type == ACTOR_USER

    def __str__(self) -> str:
        who = self.email or (str(self.user_id) if self.user_id else self.actor_type)
        return f"{who}@{self.organization_id} as {self.role.value}"


__all__ = [
    "ACTOR_AGENT",
    "ACTOR_SYSTEM",
    "ACTOR_TYPES",
    "ACTOR_USER",
    "ACTOR_WORKER",
    "Principal",
]
