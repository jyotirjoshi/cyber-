"""Safe boolean query language for tenant finding and asset inventories.

The parser produces a tiny typed AST and the compilers map known fields to
SQLAlchemy expressions. User text is always a bound value; it can never become
SQL syntax, a column name, or an operator outside the allowlist below.
"""

from __future__ import annotations

import json
import math
import re
import uuid
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import and_, exists, false, func, not_, or_, select
from sqlalchemy.sql.elements import ColumnElement

from app.core.errors import InvalidConfigurationError
from app.db.base import utcnow
from app.db.models.asset import Asset, AssetTag
from app.db.models.canonical import CanonicalFinding, FindingObservation

Resource = Literal["findings", "assets"]
_MAX_QUERY_CHARS = 1000
_MAX_TOKENS = 100
_MAX_DEPTH = 8
_MAX_PREDICATES = 25
_CUSTOM_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,59}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_TOKEN = re.compile(
    r'\s*(?:(?P<op>>=|<=|!=|=|>|<|:)|(?P<left>\()|(?P<right>\))|'
    r'(?P<quoted>"(?:\\.|[^"\\])*")|(?P<word>[^\s():<>=!]+))'
)

_FINDING_FIELDS = frozenset(
    {
        "severity",
        "status",
        "risk",
        "title",
        "cve",
        "provider",
        "kev",
        "exploit_available",
        "internet_exposed",
        "overdue",
        "assigned",
        "mine",
        "remediation_group",
        "asset_type",
        "asset_criticality",
        "asset_environment",
        "asset_group",
    }
)
_ASSET_FIELDS = frozenset(
    {
        "type",
        "status",
        "criticality",
        "environment",
        "risk",
        "name",
        "service",
        "technology",
        "group",
        "owner_team",
        "internet_exposed",
        "selected",
    }
)


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str
    value: str
    position: int


@dataclass(frozen=True, slots=True)
class Predicate:
    field: str
    operator: str
    value: str


@dataclass(frozen=True, slots=True)
class Unary:
    item: "Node"


@dataclass(frozen=True, slots=True)
class Binary:
    operator: Literal["AND", "OR"]
    left: "Node"
    right: "Node"


Node = Predicate | Unary | Binary


def _error(message: str, position: int | None = None) -> InvalidConfigurationError:
    suffix = f" near character {position + 1}" if position is not None else ""
    return InvalidConfigurationError(
        f"invalid inventory query: {message}{suffix}",
        user_message=f"Query syntax error{suffix}: {message}.",
    )


def _tokenize(query: str) -> list[_Token]:
    text = query.strip()
    if not text:
        raise _error("query cannot be blank")
    if len(text) > _MAX_QUERY_CHARS:
        raise _error(f"query exceeds {_MAX_QUERY_CHARS} characters")
    tokens: list[_Token] = []
    position = 0
    while position < len(text):
        match = _TOKEN.match(text, position)
        if match is None:
            raise _error("unexpected character", position)
        kind = match.lastgroup or ""
        value = match.group(kind)
        token_position = match.start(kind)
        position = match.end()
        if kind == "quoted":
            try:
                value = json.loads(value)
            except (TypeError, ValueError) as exc:
                raise _error("quoted value is invalid", token_position) from exc
            kind = "value"
        elif kind == "word" and value.upper() in {"AND", "OR", "NOT"}:
            kind = value.upper()
            value = value.upper()
        tokens.append(_Token(kind, value, token_position))
        if len(tokens) > _MAX_TOKENS:
            raise _error(f"query exceeds {_MAX_TOKENS} tokens")
    return tokens


class _Parser:
    def __init__(self, tokens: list[_Token]) -> None:
        self.tokens = tokens
        self.index = 0
        self.predicates = 0

    def parse(self) -> Node:
        node = self._or(0)
        if self.index != len(self.tokens):
            token = self.tokens[self.index]
            raise _error(f"unexpected {token.value!r}", token.position)
        return node

    def _peek(self, kind: str) -> bool:
        return self.index < len(self.tokens) and self.tokens[self.index].kind == kind

    def _take(self, kind: str) -> _Token:
        if not self._peek(kind):
            position = self.tokens[self.index].position if self.index < len(self.tokens) else None
            raise _error(f"expected {kind.lower()}", position)
        token = self.tokens[self.index]
        self.index += 1
        return token

    def _or(self, depth: int) -> Node:
        node = self._and(depth)
        while self._peek("OR"):
            self.index += 1
            node = Binary("OR", node, self._and(depth))
        return node

    def _and(self, depth: int) -> Node:
        node = self._unary(depth)
        while self._peek("AND"):
            self.index += 1
            node = Binary("AND", node, self._unary(depth))
        return node

    def _unary(self, depth: int) -> Node:
        if depth > _MAX_DEPTH:
            raise _error(f"query nesting exceeds {_MAX_DEPTH} levels")
        if self._peek("NOT"):
            self.index += 1
            return Unary(self._unary(depth + 1))
        if self._peek("left"):
            self.index += 1
            node = self._or(depth + 1)
            self._take("right")
            return node
        return self._predicate()

    def _predicate(self) -> Predicate:
        field = self._take("word")
        operator = self._take("op")
        if self.index >= len(self.tokens) or self.tokens[self.index].kind not in {"word", "value"}:
            position = self.tokens[self.index].position if self.index < len(self.tokens) else None
            raise _error("expected a field value", position)
        value = self.tokens[self.index]
        self.index += 1
        self.predicates += 1
        if self.predicates > _MAX_PREDICATES:
            raise _error(f"query exceeds {_MAX_PREDICATES} predicates")
        return Predicate(field.value.lower(), operator.value, value.value)


def parse(query: str) -> Node:
    return _Parser(_tokenize(query)).parse()


def _like(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _boolean(value: str) -> bool:
    normalized = value.lower()
    if normalized not in {"true", "false"}:
        raise _error("boolean values must be true or false")
    return normalized == "true"


def _number(value: str, *, minimum: float, maximum: float) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise _error("numeric comparison requires a number") from exc
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise _error(f"number must be between {minimum:g} and {maximum:g}")
    return number


def _compare(column, operator: str, value):
    if operator in {":", "="}:
        return column == value
    if operator == "!=":
        return column != value
    if operator == ">":
        return column > value
    if operator == ">=":
        return column >= value
    if operator == "<":
        return column < value
    if operator == "<=":
        return column <= value
    raise _error(f"unsupported operator {operator!r}")


def _enum(column, predicate: Predicate, allowed: set[str]):
    if predicate.operator not in {":", "=", "!="}:
        raise _error(f"{predicate.field} supports :, =, and !=")
    value = predicate.value.lower()
    if value not in allowed:
        raise _error(f"unsupported {predicate.field} value {predicate.value!r}")
    return _compare(column, predicate.operator, value)


def _text(column, predicate: Predicate):
    if predicate.operator == ":":
        return column.ilike(_like(predicate.value), escape="\\")
    if predicate.operator not in {"=", "!="}:
        raise _error(f"{predicate.field} supports :, =, and !=")
    return _compare(column, predicate.operator, predicate.value)


def _json_boolean(column, predicate: Predicate):
    if predicate.operator not in {":", "=", "!="}:
        raise _error(f"{predicate.field} supports :, =, and !=")
    normalized = func.coalesce(column, "false")
    return _compare(
        normalized,
        predicate.operator,
        "true" if _boolean(predicate.value) else "false",
    )


def _asset_subquery(organization_id: uuid.UUID, expression):
    return CanonicalFinding.asset_id.in_(
        select(Asset.id).where(Asset.organization_id == organization_id, expression)
    )


def _finding_predicate(
    predicate: Predicate,
    *,
    organization_id: uuid.UUID,
    user_id: uuid.UUID | None,
) -> ColumnElement[bool]:
    field = predicate.field
    if field.startswith("custom."):
        key = field.removeprefix("custom.")
        if not _CUSTOM_KEY.fullmatch(key):
            raise _error("custom field keys must be 1-60 safe characters")
        return _text(CanonicalFinding.custom_fields[key].astext, predicate)
    if field not in _FINDING_FIELDS:
        raise _error(f"unknown finding field {field!r}")
    if field == "severity":
        return _enum(
            CanonicalFinding.severity,
            predicate,
            {"critical", "high", "medium", "low", "info"},
        )
    if field == "status":
        return _enum(
            CanonicalFinding.status,
            predicate,
            {"new", "open", "reopened", "mitigated", "accepted_risk", "false_positive", "closed"},
        )
    if field == "risk":
        return _compare(
            CanonicalFinding.risk_score,
            predicate.operator,
            _number(predicate.value, minimum=0, maximum=100),
        )
    if field == "title":
        return _text(CanonicalFinding.title, predicate)
    if field == "cve":
        value = predicate.value.upper()
        if predicate.operator not in {":", "=", "!="} or not _CVE.fullmatch(value):
            raise _error("cve requires an exact CVE identifier")
        present = CanonicalFinding.cve_ids.contains([value])
        return not_(present) if predicate.operator == "!=" else present
    if field == "provider":
        if predicate.operator not in {":", "=", "!="} or not re.fullmatch(
            r"[a-z][a-z0-9_-]{1,39}", predicate.value.lower()
        ):
            raise _error("provider requires a safe provider name")
        present = exists(
            select(FindingObservation.id).where(
                FindingObservation.organization_id == organization_id,
                FindingObservation.canonical_finding_id == CanonicalFinding.id,
                FindingObservation.provider == predicate.value.lower(),
            )
        )
        return not_(present) if predicate.operator == "!=" else present
    if field in {"kev", "exploit_available", "internet_exposed"}:
        key = {"kev": "in_kev"}.get(field, field)
        return _json_boolean(CanonicalFinding.risk_factors["inputs"][key].astext, predicate)
    if field == "overdue":
        if predicate.operator not in {":", "=", "!="}:
            raise _error("overdue supports :, =, and !=")
        overdue = and_(
            CanonicalFinding.due_at < utcnow(),
            CanonicalFinding.status.not_in(("closed", "false_positive", "accepted_risk")),
        )
        expected = _boolean(predicate.value)
        if predicate.operator == "!=":
            expected = not expected
        return overdue.is_(True) if expected else overdue.is_not(True)
    if field in {"assigned", "mine"}:
        if predicate.operator not in {":", "=", "!="}:
            raise _error(f"{field} supports :, =, and !=")
        condition = CanonicalFinding.assignee_user_id.is_not(None)
        if field == "mine":
            condition = (
                CanonicalFinding.assignee_user_id == user_id
                if user_id is not None
                else false()
            )
        expected = _boolean(predicate.value)
        if predicate.operator == "!=":
            expected = not expected
        return condition if expected else not_(condition)
    if field == "remediation_group":
        return _text(CanonicalFinding.remediation_group, predicate)
    asset_columns = {
        "asset_type": Asset.asset_type,
        "asset_criticality": Asset.criticality,
        "asset_environment": Asset.environment,
    }
    if field in asset_columns:
        return _asset_subquery(organization_id, _text(asset_columns[field], predicate))
    if field == "asset_group":
        if predicate.operator not in {":", "=", "!="}:
            raise _error("asset_group supports :, =, and !=")
        member = Asset.groups.contains([predicate.value])
        if predicate.operator == "!=":
            member = not_(member)
        return _asset_subquery(organization_id, member)
    raise _error(f"unsupported finding field {field!r}")


def _asset_predicate(
    predicate: Predicate, *, organization_id: uuid.UUID
) -> ColumnElement[bool]:
    field = predicate.field
    if field.startswith("custom."):
        key = field.removeprefix("custom.")
        if not _CUSTOM_KEY.fullmatch(key):
            raise _error("custom field keys must be 1-60 safe characters")
        return _text(Asset.custom_fields[key].astext, predicate)
    if field.startswith("tag."):
        key = field.removeprefix("tag.")
        if not _CUSTOM_KEY.fullmatch(key) or predicate.operator not in {":", "=", "!="}:
            raise _error("tag queries require tag.<key>:<value>")
        present = exists(
            select(AssetTag.id).where(
                AssetTag.organization_id == organization_id,
                AssetTag.asset_id == Asset.id,
                AssetTag.key == key,
                AssetTag.value == predicate.value,
            )
        )
        return not_(present) if predicate.operator == "!=" else present
    if field not in _ASSET_FIELDS:
        raise _error(f"unknown asset field {field!r}")
    if field == "type":
        return _text(Asset.asset_type, predicate)
    if field == "status":
        return _enum(Asset.status, predicate, {"active", "inactive", "unreachable", "out_of_scope"})
    if field == "criticality":
        return _enum(Asset.criticality, predicate, {"critical", "high", "normal", "low", "unknown"})
    if field == "environment":
        return _enum(Asset.environment, predicate, {"unknown", "production", "staging", "development", "test"})
    if field == "risk":
        return _compare(
            Asset.risk_score,
            predicate.operator,
            _number(predicate.value, minimum=0, maximum=1),
        )
    if field in {"name", "service", "owner_team"}:
        return _text(getattr(Asset, field), predicate)
    if field in {"internet_exposed", "selected"}:
        if predicate.operator not in {":", "=", "!="}:
            raise _error(f"{field} supports :, =, and !=")
        column = Asset.internet_exposed if field == "internet_exposed" else Asset.selected_for_scanning
        return _compare(column, predicate.operator, _boolean(predicate.value))
    if field in {"technology", "group"}:
        if predicate.operator not in {":", "=", "!="}:
            raise _error(f"{field} supports :, =, and !=")
        column = Asset.technology if field == "technology" else Asset.groups
        member = column.contains([predicate.value])
        return not_(member) if predicate.operator == "!=" else member
    raise _error(f"unsupported asset field {field!r}")


def _compile(
    node: Node,
    *,
    resource: Resource,
    organization_id: uuid.UUID,
    user_id: uuid.UUID | None,
) -> ColumnElement[bool]:
    if isinstance(node, Binary):
        left = _compile(
            node.left,
            resource=resource,
            organization_id=organization_id,
            user_id=user_id,
        )
        right = _compile(
            node.right,
            resource=resource,
            organization_id=organization_id,
            user_id=user_id,
        )
        return and_(left, right) if node.operator == "AND" else or_(left, right)
    if isinstance(node, Unary):
        return not_(
            _compile(
                node.item,
                resource=resource,
                organization_id=organization_id,
                user_id=user_id,
            )
        )
    if resource == "findings":
        return _finding_predicate(
            node,
            organization_id=organization_id,
            user_id=user_id,
        )
    return _asset_predicate(node, organization_id=organization_id)


def compile_query(
    query: str,
    *,
    resource: Resource,
    organization_id: uuid.UUID,
    user_id: uuid.UUID | None = None,
) -> ColumnElement[bool]:
    return _compile(
        parse(query),
        resource=resource,
        organization_id=organization_id,
        user_id=user_id,
    )


def validate_saved_query(resource: Resource, query: object) -> None:
    if not isinstance(query, str):
        raise _error("saved query must be text")
    compile_query(
        query,
        resource=resource,
        organization_id=uuid.UUID(int=0),
        user_id=uuid.UUID(int=0),
    )


__all__ = ["compile_query", "parse", "validate_saved_query"]
