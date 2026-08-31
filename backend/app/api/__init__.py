"""Cynux HTTP API package (FR-001..FR-040).

The API is the system's front door *and* the missing producer of agent-run requests:
starting an assessment or granting an approval is what publishes a ``RunRequest`` onto
the Redis stream the worker consumes. Everything here is assembled by
:func:`app.api.app.create_app`; there is deliberately no module-level ``app`` object, so
importing this package has no side effects and the per-file gate can load it.
"""

from __future__ import annotations

#: Product/API version surfaced in health responses and the OpenAPI document. Kept here
#: rather than in ``Settings`` because it is a build constant, not a deployment setting;
#: it matches the ``service.version`` reported by :mod:`app.core.telemetry`.
API_VERSION = "1.1.0"

__all__ = ["API_VERSION"]
