"""Bound expanded selection cost before execution, including repeated fragments."""
from graphql import get_operation_ast
from graphql.language import (
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    InlineFragmentNode,
    IntValueNode,
    VariableNode,
)
from strawberry.extensions import SchemaExtension

from app.graphql.errors import PublicGraphQLError


class QueryBudget(SchemaExtension):
    def on_parse(self):
        if len(self.execution_context.query or "") > 65_536:
            raise PublicGraphQLError("QUERY_TOO_LARGE", "GraphQL request is too large.")
        yield

    def on_validate(self):
        self._check_budget()
        yield

    def _check_budget(self):
        execution = self.execution_context
        if execution.pre_execution_errors or execution.graphql_document is None:
            return
        operation = get_operation_ast(execution.graphql_document, execution.operation_name)
        if operation is None:
            return
        fragments = {
            d.name.value: d
            for d in execution.graphql_document.definitions
            if isinstance(d, FragmentDefinitionNode)
        }
        variables = dict(execution.variables or {})
        for definition in operation.variable_definitions or ():
            if isinstance(definition.default_value, IntValueNode):
                variables.setdefault(
                    definition.variable.name.value, int(definition.default_value.value)
                )
        nodes = aliases = cost = 0

        def walk(selection, depth=0, multiplier=1, stack=frozenset()):
            nonlocal nodes, aliases, cost
            if depth > 12:
                raise PublicGraphQLError("QUERY_TOO_DEEP", "GraphQL query is too deep.")
            for field in selection.selections:
                nodes += 1
                if nodes > 1000:
                    raise PublicGraphQLError("QUERY_TOO_COMPLEX", "GraphQL query is too complex.")
                if isinstance(field, FragmentSpreadNode):
                    name = field.name.value
                    if name not in fragments:
                        continue  # Standard validation reports the unknown fragment.
                    if name in stack:
                        raise PublicGraphQLError("QUERY_TOO_COMPLEX", "Cyclic GraphQL fragment.")
                    walk(fragments[name].selection_set, depth, multiplier, stack | {name})
                    continue
                if isinstance(field, InlineFragmentNode):
                    walk(field.selection_set, depth, multiplier, stack)
                    continue
                if not isinstance(field, FieldNode):
                    continue
                if field.name.value in {"__schema", "__type"}:
                    raise PublicGraphQLError(
                        "INTROSPECTION_DISABLED", "Schema introspection is disabled."
                    )
                aliases += int(field.alias is not None)
                cost += multiplier
                if aliases > 50 or cost > 5000:
                    raise PublicGraphQLError("QUERY_TOO_COMPLEX", "GraphQL query is too complex.")
                count = 1
                if field.name.value in {"agentDefinitions", "knowledgeCollections"}:
                    count = 25
                    for argument in field.arguments or ():
                        if argument.name.value == "first":
                            if isinstance(argument.value, IntValueNode):
                                count = int(argument.value.value)
                            elif isinstance(argument.value, VariableNode):
                                count = variables.get(argument.value.name.value, 25)
                    # Invalid values are rejected by coercion/resolvers; they cannot
                    # lower the estimate or explode this arithmetic.
                    count = (
                        min(101, max(1, count))
                        if isinstance(count, int) and not isinstance(count, bool)
                        else 101
                    )
                if field.selection_set:
                    walk(field.selection_set, depth + 1, multiplier * count, stack)

        try:
            walk(operation.selection_set)
        except PublicGraphQLError as exc:
            execution.pre_execution_errors = [exc]
