"""Public SDK errors shared by synchronous and asynchronous transports."""


class CynuxError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        code: str | None = None,
        retryable: bool = False,
        request_id: str | None = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.retryable = retryable
        self.request_id = request_id
