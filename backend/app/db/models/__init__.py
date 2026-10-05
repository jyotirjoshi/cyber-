"""All ORM models, re-exported.

Importing this module is what registers every mapper on ``Base.metadata``.  Alembic's
``env.py`` and the test fixtures import it for exactly that reason -- a model that is
not reachable from here silently never gets a migration.
"""

from __future__ import annotations

from app.db.models.agent import (
    AgentAction,
    AgentMessage,
    AgentRun,
    AgentSession,
    AgentStep,
    RunDispatch,
)
from app.db.models.assessment import (
    Approval,
    Assessment,
    AssessmentTarget,
    AuthorizationRecord,
    RecurringScan,
    ScanProfile,
)
from app.db.models.asset import Asset, AssetTag
from app.db.models.audit import AuditEvent
from app.db.models.canonical import CanonicalFinding, FindingHistory, FindingObservation
from app.db.models.external_alert import ExternalSecurityAlert
from app.db.models.finding import Finding, FindingEnrichment, Remediation, TicketLink
from app.db.models.identity import Membership, Organization, PasswordResetToken, User
from app.db.models.integration import Integration, IntegrationCredential
from app.db.models.notification import Notification
from app.db.models.report import Report
from app.db.models.scanner import ScannerArtifact, ScannerJob

__all__ = [
    "AgentMessage",
    "AgentAction",
    "AgentRun",
    "AgentSession",
    "AgentStep",
    "RunDispatch",
    "Approval",
    "Assessment",
    "AssessmentTarget",
    "Asset",
    "AssetTag",
    "CanonicalFinding",
    "AuditEvent",
    "ExternalSecurityAlert",
    "AuthorizationRecord",
    "RecurringScan",
    "ScanProfile",
    "Finding",
    "FindingHistory",
    "FindingObservation",
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
