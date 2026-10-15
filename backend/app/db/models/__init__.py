"""All ORM models, re-exported.

Importing this module is what registers every mapper on ``Base.metadata``.  Alembic's
``env.py`` and the test fixtures import it for exactly that reason -- a model that is
not reachable from here silently never gets a migration.
"""

from __future__ import annotations

from app.db.models.agent import (
    AgentAction,
    AgentDecision,
    AgentMemory,
    AgentMessage,
    AgentRun,
    AgentSession,
    AgentSpecialistTask,
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
from app.db.models.asm import AsmSurface
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
    AttackSimulationCampaign,
    AttackSimulationRun,
    AttackSimulationTechniqueRun,
    AutomationExecution,
    AutomationRule,
    CanonicalFinding,
    FindingCollaborationComment,
    FindingHistory,
    FindingObservation,
    RetestRequest,
    RiskAcceptance,
    SlaEscalation,
)
from app.db.models.compliance import ComplianceControl, ComplianceFindingMapping
from app.db.models.custom_connector import CustomConnector, CustomConnectorRun
from app.db.models.external_alert import ExternalSecurityAlert
from app.db.models.finding import Finding, FindingEnrichment, Remediation, TicketLink
from app.db.models.graphql import GraphQLMutationReceipt
from app.db.models.identity import (
    Membership,
    OidcConnection,
    Organization,
    PasswordResetToken,
    SamlConnection,
    ScimProvisioningToken,
    User,
)
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
from app.db.models.platform import (
    DashboardLayout,
    PlatformApiKey,
    SavedView,
    UsageMeterBucket,
    WebhookSubscription,
)
from app.db.models.report import Report, ReportDistribution, ReportSchedule, ReportShareLink, ReportTemplate
from app.db.models.scan_auth import ScanAuthProfile
from app.db.models.scanner import ScannerArtifact, ScannerJob
from app.db.models.threat_intelligence import (
    RansomwareAssociation,
    ThreatActor,
    ThreatObservation,
    ThreatWatchlist,
    ThreatWatchlistMatch,
    VulnerabilityIntelligence,
)
from app.db.models.workflow import WorkflowDefinition, WorkflowRun, WorkflowStepRun

__all__ = [
    "AsmSurface",
    "AgentMessage",
    "AgentAction",
    "AgentDecision",
    "AgentMemory",
    "AgentRun",
    "AgentSession",
    "AgentSpecialistTask",
    "AgentStep",
    "AgentDefinition",
    "AgentDefinitionVersion",
    "AgentEvaluation",
    "AgentTemplate",
    "AgentVersionCollection",
    "AgentVersionTool",
    "AgentMemoryCandidate",
    "RunDispatch",
    "Approval",
    "Assessment",
    "AssessmentTarget",
    "Asset",
    "AssetChange",
    "AssetTag",
    "AttackSimulationCampaign",
    "AttackSimulationRun",
    "AttackSimulationTechniqueRun",
    "CanonicalFinding",
    "FindingCollaborationComment",
    "ComplianceControl",
    "ComplianceFindingMapping",
    "CustomConnector",
    "CustomConnectorRun",
    "AssessmentCanonicalFinding",
    "AutomationExecution",
    "AutomationRule",
    "AuditEvent",
    "ExternalSecurityAlert",
    "AuthorizationRecord",
    "RecurringScan",
    "ScanProfile",
    "Finding",
    "FindingHistory",
    "FindingObservation",
    "GraphQLMutationReceipt",
    "RetestRequest",
    "RiskAcceptance",
    "PlatformApiKey",
    "DashboardLayout",
    "SavedView",
    "WebhookSubscription",
    "UsageMeterBucket",
    "SlaEscalation",
    "FindingEnrichment",
    "Integration",
    "IntegrationCredential",
    "KnowledgeChunk",
    "KnowledgeCollection",
    "KnowledgeEmbedding",
    "KnowledgeFeedback",
    "KnowledgeSource",
    "KnowledgeSourceVersion",
    "Membership",
    "Notification",
    "OidcConnection",
    "Organization",
    "PasswordResetToken",
    "ScimProvisioningToken",
    "SamlConnection",
    "Remediation",
    "Report",
    "ReportDistribution",
    "ReportSchedule",
    "ReportShareLink",
    "ReportTemplate",
    "ScannerArtifact",
    "ScannerJob",
    "ScanAuthProfile",
    "TicketLink",
    "User",
    "VulnerabilityIntelligence",
    "ThreatObservation",
    "ThreatActor",
    "RansomwareAssociation",
    "ThreatWatchlist",
    "ThreatWatchlistMatch",
    "WorkflowDefinition",
    "WorkflowRun",
    "WorkflowStepRun",
]
