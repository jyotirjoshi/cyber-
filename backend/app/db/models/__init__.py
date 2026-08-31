"""All ORM models, re-exported.

Importing this module is what registers every mapper on ``Base.metadata``.  Alembic's
``env.py`` and the test fixtures import it for exactly that reason -- a model that is
not reachable from here silently never gets a migration.
"""

from __future__ import annotations

from app.db.models.agent import AgentMessage, AgentRun, AgentSession, AgentStep
from app.db.models.assessment import (
    Approval,
    Assessment,
    AssessmentTarget,
    AuthorizationRecord,
)
from app.db.models.asset import Asset, AssetTag
from app.db.models.audit import AuditEvent
from app.db.models.finding import Finding, FindingEnrichment, Remediation, TicketLink
from app.db.models.identity import Membership, Organization, PasswordResetToken, User
from app.db.models.integration import Integration, IntegrationCredential
from app.db.models.notification import Notification
from app.db.models.report import Report
from app.db.models.scanner import ScannerArtifact, ScannerJob

__all__ = [
    "AgentMessage",
    "AgentRun",
    "AgentSession",
    "AgentStep",
    "Approval",
    "Assessment",
    "AssessmentTarget",
    "Asset",
    "AssetTag",
    "AuditEvent",
    "AuthorizationRecord",
    "Finding",
    "FindingEnrichment",
    "Integration",
    "IntegrationCredential",
    "Membership",
    "Notification",
    "Organization",
    "PasswordResetToken",
    "Remediation",
    "Report",
    "ScannerArtifact",
    "ScannerJob",
    "TicketLink",
    "User",
]
