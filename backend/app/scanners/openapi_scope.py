"""Bound an imported OpenAPI document to one explicitly approved HTTP origin.

Scanner tools may follow ``servers`` and external ``$ref`` values.  The document is
therefore treated as untrusted scan instructions, not merely as descriptive JSON.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit, urlunsplit

from app.core.errors import UnsafeScannerInvocationError

if TYPE_CHECKING:
    from app.scanners.base import ScannerRequest


class OpenAPIScopeError(UnsafeScannerInvocationError):
    """The contract cannot be scanned within the approved origin."""


_MAX_BYTES = 512_000
_MAX_NODES = 50_000
_METHODS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace"})
_FORBIDDEN_KEYS = frozenset({"callbacks", "webhooks", "externalDocs", "example", "examples"})
SPEC_FILENAME = "api-openapi.json"


def _server_url(value: str) -> str:
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise OpenAPIScopeError("API server URL is malformed") from exc
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or "{" in value
        or "}" in value
        or "\\" in value
        or "%" in parts.path
        or ".." in parts.path
        or "//" in parts.path
    ):
        raise OpenAPIScopeError("API server must be an absolute HTTP(S) URL without credentials")
    try:
        port = parts.port
    except ValueError as exc:
        raise OpenAPIScopeError("API server port is invalid") from exc
    host = parts.hostname.lower().rstrip(".")
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme, netloc, path, "", ""))


def normalize_openapi_spec(spec: dict[str, Any], approved_target: str) -> dict[str, Any]:
    """Return a copy with a pinned server or refuse any out-of-scope instruction.

    This does not authorize the scan by itself. The job still requires the normal
    per-assessment human approval and the pre-execution target-policy recheck.
    """
    if not isinstance(spec, dict):
        raise OpenAPIScopeError("OpenAPI document must be a JSON object")
    try:
        encoded = json.dumps(spec, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise OpenAPIScopeError("OpenAPI document must be JSON serializable") from exc
    if len(encoded.encode("utf-8")) > _MAX_BYTES:
        raise OpenAPIScopeError("OpenAPI document exceeds the size limit")
    if not isinstance(spec.get("openapi"), str) or not spec["openapi"].startswith("3."):
        raise OpenAPIScopeError("Only OpenAPI 3 documents are supported")
    if not isinstance(spec.get("info"), dict) or not isinstance(spec.get("paths"), dict):
        raise OpenAPIScopeError("OpenAPI info and paths objects are required")
    if not spec["paths"]:
        raise OpenAPIScopeError("OpenAPI document has no paths")

    approved_server = _server_url(approved_target)
    servers = spec.get("servers")
    if not isinstance(servers, list) or not servers:
        raise OpenAPIScopeError("OpenAPI document needs an explicit server")
    for server in servers:
        if not isinstance(server, dict) or not isinstance(server.get("url"), str):
            raise OpenAPIScopeError("OpenAPI server entry is invalid")
        if set(server) - {"url", "description"}:
            raise OpenAPIScopeError("OpenAPI server variables are not supported")
        if _server_url(server["url"]) != approved_server:
            raise OpenAPIScopeError("OpenAPI server is outside the approved URL")

    operations = 0
    for path, item in spec["paths"].items():
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            raise OpenAPIScopeError("OpenAPI path must be relative to the approved server")
        if (
            "\\" in path or "?" in path or "#" in path or ".." in path or "%" in path
            or any(ord(character) < 32 or ord(character) == 127 for character in path)
        ):
            raise OpenAPIScopeError("OpenAPI path contains an unsafe navigation component")
        if not isinstance(item, dict):
            raise OpenAPIScopeError("OpenAPI path item must be an object")
        operations += sum(key in _METHODS for key in item)
    if not 1 <= operations <= 500:
        raise OpenAPIScopeError("OpenAPI document must contain 1 to 500 operations")

    pending: list[Any] = [spec]
    nodes = 0
    while pending:
        current = pending.pop()
        nodes += 1
        if nodes > _MAX_NODES:
            raise OpenAPIScopeError("OpenAPI document is too complex")
        if isinstance(current, dict):
            for key, value in current.items():
                if key in _FORBIDDEN_KEYS:
                    raise OpenAPIScopeError("OpenAPI document contains unsupported external behavior")
                if key == "servers" and current is not spec:
                    raise OpenAPIScopeError("Nested OpenAPI server overrides are not allowed")
                if key == "$ref" and (not isinstance(value, str) or not value.startswith("#/")):
                    raise OpenAPIScopeError("External OpenAPI references are not allowed")
                if key in {"value", "apiKey", "token", "password", "clientSecret"}:
                    raise OpenAPIScopeError("OpenAPI document must not contain embedded credentials")
                pending.append(value)
        elif isinstance(current, list):
            pending.extend(current)

    normalized = copy.deepcopy(spec)
    normalized["servers"] = [{"url": approved_server}]
    return normalized


def prepare_openapi_spec(request: ScannerRequest) -> bool:
    """Stage a validated API contract for a scanner, never a remote spec URL."""
    raw = request.option("api_spec")
    if raw is None:
        return False
    target = request.option("api_target")
    if target is None and len(request.targets) == 1:
        target = request.targets[0]
    if not isinstance(target, str) or target not in request.targets:
        raise OpenAPIScopeError("API target must be in the approved scanner job")
    spec = normalize_openapi_spec(raw, target)
    (Path(request.workdir) / SPEC_FILENAME).write_text(
        json.dumps(spec, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    return True


__all__ = ["OpenAPIScopeError", "SPEC_FILENAME", "normalize_openapi_spec", "prepare_openapi_spec"]
