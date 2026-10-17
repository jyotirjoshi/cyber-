"""Small, deterministic expression language for no-code automation rules.

The syntax intentionally resembles a useful subset of Python, but it is never
compiled or passed to ``eval``.  A whitelisted AST is interpreted against a flat,
bounded event context.  There are no calls, attributes, indexing, arithmetic, or
comprehensions, so a stored rule is data rather than tenant-supplied code.
"""

from __future__ import annotations

import ast
from functools import lru_cache
from typing import Any

_MAX_EXPRESSION_LENGTH = 1_000
_MAX_NODES = 80
_MAX_DEPTH = 12
_ALLOWED_NAMES = frozenset(
    {
        "severity",
        "risk_score",
        "in_kev",
        "internet_exposed",
        "asset_environment",
        "asset_criticality",
        "asset_groups",
        "asset_type",
        "trigger",
        "source",
        "status",
        "true",
        "false",
        "null",
    }
)
_ALLOWED_NODES = (
    ast.Expression,
    ast.BoolOp,
    ast.And,
    ast.Or,
    ast.UnaryOp,
    ast.Not,
    ast.Compare,
    ast.Eq,
    ast.NotEq,
    ast.Gt,
    ast.GtE,
    ast.Lt,
    ast.LtE,
    ast.In,
    ast.NotIn,
    ast.Name,
    ast.Constant,
    ast.List,
    ast.Tuple,
    ast.Load,
)


def _depth(node: ast.AST) -> int:
    children = list(ast.iter_child_nodes(node))
    return 1 if not children else 1 + max(_depth(child) for child in children)


@lru_cache(maxsize=1_024)
def _parse(expression: str) -> ast.Expression:
    if not isinstance(expression, str) or not expression.strip():
        raise ValueError("automation expression cannot be blank")
    if len(expression) > _MAX_EXPRESSION_LENGTH:
        raise ValueError("automation expression exceeds 1,000 characters")
    try:
        parsed = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise ValueError("automation expression has invalid syntax") from exc
    nodes = list(ast.walk(parsed))
    if len(nodes) > _MAX_NODES or _depth(parsed) > _MAX_DEPTH:
        raise ValueError("automation expression is too complex")
    for node in nodes:
        if not isinstance(node, _ALLOWED_NODES):
            raise ValueError(f"automation expression does not allow {type(node).__name__}")
        if isinstance(node, ast.Name) and node.id not in _ALLOWED_NAMES:
            raise ValueError(f"automation expression field {node.id!r} is not available")
        if isinstance(node, ast.Constant) and not (
            node.value is None or isinstance(node.value, str | int | float | bool)
        ):
            raise ValueError("automation expression contains an unsupported literal")
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) > 500:
            raise ValueError("automation expression string literal is too long")
        if isinstance(node, ast.List | ast.Tuple) and len(node.elts) > 20:
            raise ValueError("automation expression collection is too large")
    return parsed


def validate_expression(expression: str) -> str:
    """Validate and normalize whitespace around one bounded expression."""
    normalized = expression.strip()
    _parse(normalized)
    return normalized


def _value(node: ast.AST, context: dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id == "true":
            return True
        if node.id == "false":
            return False
        if node.id == "null":
            return None
        value = context.get(node.id)
        if isinstance(value, set | tuple):
            return list(value)
        if value is None or isinstance(value, str | int | float | bool | list):
            return value
        raise ValueError(f"automation expression field {node.id!r} has an unsupported value")
    if isinstance(node, ast.List | ast.Tuple):
        return [_value(item, context) for item in node.elts]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not bool(_value(node.operand, context))
    if isinstance(node, ast.BoolOp):
        values = [_value(item, context) for item in node.values]
        return all(bool(value) for value in values) if isinstance(node.op, ast.And) else any(
            bool(value) for value in values
        )
    if isinstance(node, ast.Compare):
        left = _value(node.left, context)
        for operator, comparator_node in zip(node.ops, node.comparators, strict=True):
            right = _value(comparator_node, context)
            try:
                if isinstance(operator, ast.Eq):
                    matched = left == right
                elif isinstance(operator, ast.NotEq):
                    matched = left != right
                elif isinstance(operator, ast.Gt):
                    matched = left > right
                elif isinstance(operator, ast.GtE):
                    matched = left >= right
                elif isinstance(operator, ast.Lt):
                    matched = left < right
                elif isinstance(operator, ast.LtE):
                    matched = left <= right
                elif isinstance(operator, ast.In):
                    matched = left in right
                elif isinstance(operator, ast.NotIn):
                    matched = left not in right
                else:  # pragma: no cover - validation makes this unreachable
                    raise ValueError("unsupported automation comparison")
            except (TypeError, ValueError) as exc:
                raise ValueError("automation expression compared incompatible values") from exc
            if not matched:
                return False
            left = right
        return True
    raise ValueError("unsupported automation expression")


def evaluate_expression(expression: str, context: dict[str, Any]) -> bool:
    parsed = _parse(validate_expression(expression))
    return bool(_value(parsed.body, context))


__all__ = ["evaluate_expression", "validate_expression"]
