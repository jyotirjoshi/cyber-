"""Websocket routes, collected and mounted *without* the ``/api/v1`` prefix.

REST lives under ``settings.api_prefix``; the live agent stream is a sibling at ``/ws/agent/...``.
Keeping it out of the versioned prefix is deliberate: a websocket is a long-lived transport, not a
versioned resource, and its full path is declared on the route itself. :func:`app.api.app.create_app`
includes this one router with no prefix, mirroring how the health router is mounted.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.ws import agent

ws_router = APIRouter()
ws_router.include_router(agent.router)

__all__ = ["ws_router"]
