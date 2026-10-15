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
from app.db.models.agent_definition import (
    AgentDefinition,
    AgentDefinitionVersion,
    AgentEvaluation,
    AgentTemplate,
    AgentVersionCollection,
    AgentVersionTool,
)
from app.db.models.assessment import (
    Approval,
    Assessment,
    AssessmentTarget,
    AuthorizationRecord,
    RecurringScan,
    ScanProfile,
)
from app.db.models.asset import Asset, AssetChange, AssetTag
from app.db.models.audit import AuditEvent
from app.db.models.canonical import (
    AssessmentCanonicalFinding,
    CanonicalFinding,
    FindingHistory,
    FindingObservation,
)
from app.db.models.external_alert import ExternalSecurityAlert
from app.db.models.finding import Finding, FindingEnrichment, Remediation, TicketLink
from app.db.models.graphql import GraphQLMutationReceipt
from app.db.models.identity import Membership, Organization, PasswordResetToken, User
from app.db.models.integration import Integration, IntegrationCredential
from app.db.models.knowledge import (
    AgentMemoryCandidate,
    KnowledgeChunk,
    KnowledgeCollection,
    KnowledgeEmbedding,
    KnowledgeFeedback,
    KnowledgeSource,
    KnowledgeSourceVersion,
)
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
    "AssetChange",
    "AssetTag",
    "CanonicalFinding",
    "AssessmentCanonicalFinding",
    "AuditEvent",
    "ExternalSecurityAlert",
    "AuthorizationRecord",
    "RecurringScan",
    "ScanProfile",
    "Finding",
    "FindingHistory",
    "FindingObservation",
    "GraphQLMutationReceipt",
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
    "AgentDefinition",
    "AgentDefinitionVersion",
    "AgentEvaluation",
    "AgentTemplate",
    "AgentVersionCollection",
    "AgentVersionTool",
    "AgentMemoryCandidate",
    "KnowledgeChunk",
    "KnowledgeCollection",
    "KnowledgeEmbedding",
    "KnowledgeFeedback",
    "KnowledgeSource",
    "KnowledgeSourceVersion",
]
