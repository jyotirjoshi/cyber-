"""Stable public failures; never return database or provider exception strings."""
from graphql import GraphQLError
from strawberry.extensions import SchemaExtension

from app.core.errors import CynuxError


class PublicGraphQLError(GraphQLError):
    def __init__(self, code: str, message: str):
        super().__init__(message, extensions={"code": code, "retryable": False})


class PublicErrors(SchemaExtension):
    def on_operation(self):
        yield
        result = self.execution_context.result
        if result is None or not result.errors:
            return
        context = self.execution_context.context
        request_id = getattr(getattr(context, "principal", None), "request_id", None)
        safe = []
        for error in result.errors:
            original = error if isinstance(error, PublicGraphQLError) else error.original_error
            if isinstance(original, PublicGraphQLError):
                message, extensions = original.message, dict(original.extensions)
            elif isinstance(original, CynuxError):
                message = original.default_user_message
                extensions = {"code": original.code.upper(), "retryable": original.retryable}
            else:
                message = (
                    "Invalid GraphQL request."
                    if original is None
                    else "An unexpected error occurred."
                )
                extensions = {
                    "code": "BAD_REQUEST" if original is None else "INTERNAL_ERROR",
                    "retryable": False,
                }
            extensions["requestId"] = request_id
            safe.append(GraphQLError(message, path=error.path, extensions=extensions))
        result.errors = safe
