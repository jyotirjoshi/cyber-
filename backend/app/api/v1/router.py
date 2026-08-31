"""Versioned API surface: every resource router mounted under ``settings.api_prefix``.

Each resource module owns one :class:`fastapi.APIRouter`; this module is the single place
they are collected, so :func:`app.api.app.create_app` includes exactly one router and the
prefix (``/api/v1``) lives in configuration rather than being repeated per module. Routers
are added here as they are built.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    agent,
    approvals,
    assessments,
    assets,
    audit,
    auth,
    dashboard,
    findings,
    integrations,
    jobs,
    organization,
    reports,
)

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(assessments.router)
api_router.include_router(assets.router)
api_router.include_router(approvals.router)
api_router.include_router(findings.router)
api_router.include_router(jobs.router)
api_router.include_router(reports.router)
api_router.include_router(organization.router)
api_router.include_router(integrations.router)
api_router.include_router(audit.router)
api_router.include_router(agent.router)

__all__ = ["api_router"]
