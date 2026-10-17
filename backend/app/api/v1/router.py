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
    agent_definitions,
    applications,
    approvals,
    asm,
    assessments,
    assets,
    attack_simulations,
    audit,
    auth,
    automation,
    canonical,
    compliance,
    custom_connectors,
    dashboard,
    engagements,
    exposures,
    external_alerts,
    findings,
    integrations,
    jobs,
    knowledge,
    metering,
    notifications,
    organization,
    platform,
    postquantum,
    reports,
    saved_views,
    scan_auth,
    scim,
    threat_intelligence,
    webhooks,
    workflows,
)

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(dashboard.router)
api_router.include_router(engagements.router)
api_router.include_router(assessments.router)
api_router.include_router(assets.router)
api_router.include_router(asm.router)
api_router.include_router(applications.router)
api_router.include_router(approvals.router)
api_router.include_router(findings.router)
api_router.include_router(external_alerts.router)
api_router.include_router(exposures.router)
api_router.include_router(canonical.router)
api_router.include_router(compliance.router)
api_router.include_router(jobs.router)
api_router.include_router(knowledge.router)
api_router.include_router(reports.router)
api_router.include_router(organization.router)
api_router.include_router(integrations.router)
api_router.include_router(audit.router)
api_router.include_router(agent.router)
api_router.include_router(agent_definitions.router)
api_router.include_router(automation.router)
api_router.include_router(attack_simulations.router)
api_router.include_router(platform.router)
api_router.include_router(saved_views.router)
api_router.include_router(webhooks.router)
api_router.include_router(scim.router)
api_router.include_router(postquantum.router)
api_router.include_router(metering.router)
api_router.include_router(notifications.router)
api_router.include_router(threat_intelligence.router)
api_router.include_router(workflows.router)
api_router.include_router(custom_connectors.router)
api_router.include_router(scan_auth.router)

__all__ = ["api_router"]
