"""Domain enumerations shared by the ORM, the API schemas and the agent.

These are plain ``str`` enums stored as Postgres ``varchar`` with a check
constraint rather than native ``ENUM`` types.  Native enums require a migration to
add a value, and the agent's vocabulary (tool names, event types, stages) grows
often; varchar + check keeps that a one-line migration.
"""

from __future__ import annotations

import enum


class StrEnum(str, enum.Enum):
    def __str__(self) -> str:
        return self.value

    @classmethod
    def values(cls) -> list[str]:
        return [m.value for m in cls]


# ---------------------------------------------------------------------------
# Identity (FR-002)
# ---------------------------------------------------------------------------


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    SECURITY_ENGINEER = "security_engineer"
    DEVELOPER = "developer"
    VIEWER = "viewer"

    @property
    def rank(self) -> int:
        return _ROLE_RANK[self]


_ROLE_RANK = {
    Role.VIEWER: 0,
    Role.DEVELOPER: 1,
    Role.SECURITY_ENGINEER: 2,
    Role.ADMIN: 3,
    Role.OWNER: 4,
}


class Permission(StrEnum):
    """Discrete capabilities. Roles map to sets of these (see PERMISSIONS)."""

    ORG_READ = "org:read"
    ORG_MANAGE = "org:manage"
    MEMBER_MANAGE = "member:manage"
    INTEGRATION_READ = "integration:read"
    INTEGRATION_MANAGE = "integration:manage"
    ENDPOINT_INGEST = "endpoint:ingest"
    ASSESSMENT_READ = "assessment:read"
    ASSESSMENT_CREATE = "assessment:create"
    ASSESSMENT_APPROVE = "assessment:approve"
    ASSESSMENT_CANCEL = "assessment:cancel"
    ASSET_READ = "asset:read"
    ASSET_TAG = "asset:tag"
    FINDING_READ = "finding:read"
    FINDING_ANALYZE = "finding:analyze"
    FINDING_VALIDATE = "finding:validate"
    FINDING_REMEDIATE = "finding:remediate"
    TICKET_CREATE = "ticket:create"
    REPORT_READ = "report:read"
    REPORT_GENERATE = "report:generate"
    AUDIT_READ = "audit:read"
    AGENT_CHAT = "agent:chat"


_READ_ONLY = {
    Permission.ORG_READ,
    Permission.ASSESSMENT_READ,
    Permission.ASSET_READ,
    Permission.FINDING_READ,
    Permission.REPORT_READ,
}

#: Role -> permission set. Deliberately explicit: a reader of this file should be
#: able to answer "can a Developer approve a scan?" without tracing inheritance.
PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset(_READ_ONLY),
    Role.DEVELOPER: frozenset(
        _READ_ONLY
        | {
            Permission.AGENT_CHAT,
            Permission.FINDING_REMEDIATE,
            Permission.TICKET_CREATE,
            Permission.INTEGRATION_READ,
        }
    ),
    Role.SECURITY_ENGINEER: frozenset(
        _READ_ONLY
        | {
            Permission.AGENT_CHAT,
            Permission.ASSESSMENT_CREATE,
            Permission.ASSESSMENT_APPROVE,
            Permission.ASSESSMENT_CANCEL,
            Permission.ASSET_TAG,
            Permission.FINDING_ANALYZE,
            Permission.FINDING_VALIDATE,
            Permission.FINDING_REMEDIATE,
            Permission.TICKET_CREATE,
            Permission.REPORT_GENERATE,
            Permission.INTEGRATION_READ,
            Permission.AUDIT_READ,
        }
    ),
    Role.ADMIN: frozenset(set(Permission) - {Permission.ORG_MANAGE}),
    Role.OWNER: frozenset(set(Permission)),
}


def role_has(role: Role, permission: Permission) -> bool:
    return permission in PERMISSIONS[role]


# ---------------------------------------------------------------------------
# Assessments (FR-007)
# ---------------------------------------------------------------------------


class AssessmentStatus(StrEnum):
    CREATED = "CREATED"
    PLANNING = "PLANNING"
    DISCOVERY = "DISCOVERY"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    SCANNING = "SCANNING"
    ANALYZING = "ANALYZING"
    REMEDIATING = "REMEDIATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLING = "CANCELLING"
    CANCELLED = "CANCELLED"

    @property
    def is_terminal(self) -> bool:
        return self in _TERMINAL_STATUSES


_TERMINAL_STATUSES = frozenset(
    {AssessmentStatus.COMPLETED, AssessmentStatus.FAILED, AssessmentStatus.CANCELLED}
)

#: Legal transitions. The service layer refuses anything not listed, so a race
#: between a cancel request and a worker cannot resurrect a finished assessment.
ALLOWED_TRANSITIONS: dict[AssessmentStatus, frozenset[AssessmentStatus]] = {
    AssessmentStatus.CREATED: frozenset(
        {AssessmentStatus.PLANNING, AssessmentStatus.CANCELLING, AssessmentStatus.FAILED}
    ),
    AssessmentStatus.PLANNING: frozenset(
        {AssessmentStatus.DISCOVERY, AssessmentStatus.CANCELLING, AssessmentStatus.FAILED}
    ),
    AssessmentStatus.DISCOVERY: frozenset(
        {
            AssessmentStatus.WAITING_FOR_APPROVAL,
            AssessmentStatus.SCANNING,
            AssessmentStatus.ANALYZING,
            AssessmentStatus.CANCELLING,
            AssessmentStatus.FAILED,
        }
    ),
    AssessmentStatus.WAITING_FOR_APPROVAL: frozenset(
        {
            AssessmentStatus.SCANNING,
            AssessmentStatus.CANCELLING,
            AssessmentStatus.CANCELLED,
            AssessmentStatus.FAILED,
        }
    ),
    AssessmentStatus.SCANNING: frozenset(
        {AssessmentStatus.ANALYZING, AssessmentStatus.CANCELLING, AssessmentStatus.FAILED}
    ),
    AssessmentStatus.ANALYZING: frozenset(
        {
            AssessmentStatus.REMEDIATING,
            AssessmentStatus.COMPLETED,
            AssessmentStatus.CANCELLING,
            AssessmentStatus.FAILED,
        }
    ),
    AssessmentStatus.REMEDIATING: frozenset(
        {AssessmentStatus.COMPLETED, AssessmentStatus.CANCELLING, AssessmentStatus.FAILED}
    ),
    AssessmentStatus.CANCELLING: frozenset({AssessmentStatus.CANCELLED, AssessmentStatus.FAILED}),
    AssessmentStatus.COMPLETED: frozenset(),
    AssessmentStatus.FAILED: frozenset(),
    AssessmentStatus.CANCELLED: frozenset(),
}


class AssessmentStage(StrEnum):
    """Finer-grained progress used by the UI tracker (FR-038)."""

    QUEUED = "queued"
    UNDERSTANDING = "understanding_request"
    VALIDATING = "validating_target"
    AUTHORIZING = "checking_authorization"
    PLANNING = "planning"
    RECON = "reconnaissance"
    ASSET_ANALYSIS = "asset_analysis"
    APPROVAL = "awaiting_approval"
    SCAN_NMAP = "scanning_nmap"
    SCAN_NUCLEI = "scanning_nuclei"
    SCAN_ZAP = "scanning_zap"
    SCAN_TRIVY_REPO = "scanning_trivy_repo"
    SCAN_SEMGREP_REPO = "scanning_semgrep_repo"
    SCAN_GITLEAKS_REPO = "scanning_gitleaks_repo"
    SCAN_TRIVY_IMAGE = "scanning_trivy_image"
    SCAN_SYFT_IMAGE = "scanning_syft_image"
    SCAN_PROWLER_AWS = "scanning_prowler_aws"
    SCAN_PROWLER_AZURE = "scanning_prowler_azure"
    SCAN_PROWLER_GCP = "scanning_prowler_gcp"
    IMPORT = "importing_findings"
    ENRICH = "threat_intelligence"
    AI_ANALYSIS = "ai_analysis"
    PRIORITIZE = "risk_prioritization"
    REMEDIATION = "remediation"
    ACTIONS = "creating_actions"
    REPORT = "report"
    DONE = "done"


#: Ordered stage list the frontend renders as a checklist.
STAGE_ORDER: tuple[AssessmentStage, ...] = (
    AssessmentStage.UNDERSTANDING,
    AssessmentStage.VALIDATING,
    AssessmentStage.AUTHORIZING,
    AssessmentStage.PLANNING,
    AssessmentStage.RECON,
    AssessmentStage.ASSET_ANALYSIS,
    AssessmentStage.APPROVAL,
    AssessmentStage.SCAN_NMAP,
    AssessmentStage.SCAN_NUCLEI,
    AssessmentStage.SCAN_ZAP,
    AssessmentStage.SCAN_TRIVY_REPO,
    AssessmentStage.SCAN_SEMGREP_REPO,
    AssessmentStage.SCAN_GITLEAKS_REPO,
    AssessmentStage.SCAN_TRIVY_IMAGE,
    AssessmentStage.SCAN_SYFT_IMAGE,
    AssessmentStage.SCAN_PROWLER_AWS,
    AssessmentStage.SCAN_PROWLER_AZURE,
    AssessmentStage.SCAN_PROWLER_GCP,
    AssessmentStage.IMPORT,
    AssessmentStage.ENRICH,
    AssessmentStage.AI_ANALYSIS,
    AssessmentStage.PRIORITIZE,
    AssessmentStage.REMEDIATION,
    AssessmentStage.ACTIONS,
    AssessmentStage.REPORT,
)


class AssessmentDepth(StrEnum):
    PASSIVE = "passive"  # recon only, no active probing
    STANDARD = "standard"  # recon + nmap top ports + nuclei default severity
    DEEP = "deep"  # full port range, all nuclei severities, ZAP active


class EngagementType(StrEnum):
    """The authorized security engagement being performed."""

    WEB_APPLICATION = "web_application"
    API_SECURITY = "api_security"
    MOBILE_APPLICATION = "mobile_application"
    LLM_AGENTIC_APPLICATION = "llm_agentic_application"
    NETWORK_EXTERNAL = "network_external"
    NETWORK_INTERNAL = "network_internal"
    ACTIVE_DIRECTORY = "active_directory"
    CLOUD_SECURITY = "cloud_security"
    CODE_REVIEW = "code_review"
    THREAT_MODELING = "threat_modeling"
    ATTACK_SURFACE_MONITORING = "attack_surface_monitoring"
    DEVSECOPS_PIPELINE = "devsecops_pipeline"
    THREAT_HUNTING = "threat_hunting"
    CODE_REMEDIATION = "code_remediation"
    RED_TEAM = "red_team"
    SUPPLY_CHAIN = "supply_chain"


class PtaasEngagementStatus(StrEnum):
    DRAFT = "draft"
    SCOPING = "scoping"
    ACTIVE = "active"
    RETESTING = "retesting"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class EngagementParticipantRole(StrEnum):
    LEAD_TESTER = "lead_tester"
    TESTER = "tester"
    CLIENT_MANAGER = "client_manager"
    CLIENT_OBSERVER = "client_observer"


class EngagementParticipantStatus(StrEnum):
    INVITED = "invited"
    ACTIVE = "active"
    REMOVED = "removed"


class EngagementMilestoneStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class EngagementDocumentKind(StrEnum):
    SCOPE = "scope"
    AUTHORIZATION = "authorization"
    EVIDENCE = "evidence"
    REPORT = "report"
    DELIVERABLE = "deliverable"
    OTHER = "other"


class EngagementRetestStatus(StrEnum):
    REQUESTED = "requested"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ExecutionMode(StrEnum):
    """How an approved engagement is allowed to execute."""

    SUPERVISED = "supervised"
    BACKGROUND = "background"
    INTERACTIVE = "interactive"


class ValidationStatus(StrEnum):
    """Disposition of a finding after safe, evidence-backed validation."""

    UNVALIDATED = "unvalidated"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    RECHECK_REQUIRED = "recheck_required"


class ExternalAlertTriageStatus(StrEnum):
    """Cynux's local analyst disposition, never a provider status."""

    NEW = "new"
    INVESTIGATING = "investigating"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class Scope(StrEnum):
    EXTERNAL = "external"
    INTERNAL = "internal"
    APPLICATION = "application"
    CODE = "code"


# ---------------------------------------------------------------------------
# Assets (FR-009)
# ---------------------------------------------------------------------------


class AssetStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNREACHABLE = "unreachable"
    OUT_OF_SCOPE = "out_of_scope"


class AssetEnvironment(StrEnum):
    UNKNOWN = "unknown"
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"


class AssetRelationshipType(StrEnum):
    DEPENDS_ON = "depends_on"
    CONTAINS = "contains"
    HOSTS = "hosts"
    CONNECTS_TO = "connects_to"
    OWNED_BY = "owned_by"


class Criticality(StrEnum):
    """FR-022 business context."""

    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"
    UNKNOWN = "unknown"

    @property
    def weight(self) -> float:
        return {"critical": 1.0, "high": 0.75, "normal": 0.5, "low": 0.25, "unknown": 0.4}[
            self.value
        ]


class CriticalitySource(StrEnum):
    """Where an asset's criticality came from. Operator tags always win over
    inference, and the distinction is shown in the UI so nobody mistakes a keyword
    guess for a curated fact."""

    OPERATOR_TAG = "operator_tag"
    CMDB = "cmdb"
    INFERRED_KEYWORD = "inferred_keyword"
    INFERRED_EXPOSURE = "inferred_exposure"
    DEFAULT = "default"


# ---------------------------------------------------------------------------
# Scanners (FR-013)
# ---------------------------------------------------------------------------


class ScannerName(StrEnum):
    RECONFTW = "reconftw"
    NMAP = "nmap"
    NUCLEI = "nuclei"
    ZAP = "zap"
    TRIVY_REPO = "trivy_repo"
    SEMGREP_REPO = "semgrep_repo"
    GITLEAKS_REPO = "gitleaks_repo"
    TRIVY_IMAGE = "trivy_image"
    SYFT_IMAGE = "syft_image"
    PROWLER_AWS = "prowler_aws"
    PROWLER_AZURE = "prowler_azure"
    PROWLER_GCP = "prowler_gcp"


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMEOUT = "TIMEOUT"

    @property
    def is_terminal(self) -> bool:
        return self is not JobStatus.QUEUED and self is not JobStatus.RUNNING


class ArtifactKind(StrEnum):
    RAW_OUTPUT = "raw_output"
    STDOUT = "stdout"
    STDERR = "stderr"
    REPORT = "report"


# ---------------------------------------------------------------------------
# Findings (FR-017)
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Higher is worse. Used for ordering and for the analysis floor."""
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    @classmethod
    def parse(cls, raw: str | None) -> Severity:
        """Map the many spellings scanners and DefectDojo use onto our five levels.

        Unknown values become INFO rather than guessing upward -- inflating severity
        would distort prioritization, and the raw label is preserved separately.
        """
        if not raw:
            return cls.INFO
        key = raw.strip().lower()
        return _SEVERITY_ALIASES.get(key, cls.INFO)


_SEVERITY_ALIASES: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "s0": Severity.CRITICAL,
    "high": Severity.HIGH,
    "s1": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "med": Severity.MEDIUM,
    "s2": Severity.MEDIUM,
    "low": Severity.LOW,
    "s3": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "information": Severity.INFO,
    "none": Severity.INFO,
    "unknown": Severity.INFO,
    "s4": Severity.INFO,
}


class FindingStatus(StrEnum):
    ACTIVE = "active"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    RISK_ACCEPTED = "risk_accepted"
    OUT_OF_SCOPE = "out_of_scope"
    MITIGATED = "mitigated"
    DUPLICATE = "duplicate"


class CanonicalFindingStatus(StrEnum):
    NEW = "new"
    OPEN = "open"
    REOPENED = "reopened"
    MITIGATED = "mitigated"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class AttackSimulationCampaignStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class Priority(StrEnum):
    """FR-023 output. Distinct from severity: severity is the scanner's opinion,
    priority is Cynux's after exposure, exploitation and business context."""

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    P5 = "P5"

    @property
    def rank(self) -> int:
        return int(self.value[1])


class EnrichmentStatus(StrEnum):
    """FR-020: a provider outage is recorded, never papered over."""

    PENDING = "pending"
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"


# ---------------------------------------------------------------------------
# Agent (FR-033 / FR-034)
# ---------------------------------------------------------------------------


class RiskLevel(StrEnum):
    """FR-034 tool risk. ``FORBIDDEN`` tools are registered but never callable in
    MVP, so an attempt is a loud guardrail trip rather than a missing-tool error."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    FORBIDDEN = "forbidden"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "forbidden": 3}[self.value]


class AgentRunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    INTERRUPTED = "interrupted"  # paused on a human-approval interrupt
    COMPLETED = "completed"
    PARTIALLY_COMPLETED = "partially_completed"
    BLOCKED = "blocked"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentTaskStatus(StrEnum):
    PENDING = "pending"
    BLOCKED = "blocked"
    READY = "ready"
    QUEUED = "queued"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    DEGRADED = "degraded"
    SKIPPED = "skipped"
    FAILED = "failed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


class AgentTaskKind(StrEnum):
    AGENT = "agent"
    TOOL = "tool"
    APPROVAL = "approval"
    JOIN = "join"
    DECISION = "decision"
    FINALIZE = "finalize"


class AgentTaskDependencyKind(StrEnum):
    REQUIRED = "required"
    OPTIONAL = "optional"


class AgentTaskAttemptStatus(StrEnum):
    CLAIMED = "claimed"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class AgentWorkspaceStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    CLOSED = "closed"
    EXPIRED = "expired"


class AgentWorkspaceArtifactKind(StrEnum):
    INPUT = "input"
    OUTPUT = "output"
    SCREENSHOT = "screenshot"
    HAR = "har"
    CONSOLE = "console"
    REPORT = "report"
    EVIDENCE = "evidence"
    ARCHIVE = "archive"


class AgentWorkspaceCredentialStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class AgentWorkspaceExecutionKind(StrEnum):
    SHELL = "shell"
    BROWSER = "browser"
    SCANNER = "scanner"


class AgentWorkspaceExecutionStatus(StrEnum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentEvidenceKind(StrEnum):
    OBSERVATION = "observation"
    ARTIFACT = "artifact"
    PROVIDER_RECEIPT = "provider_receipt"
    APPROVAL = "approval"
    REPORT = "report"
    METRIC = "metric"


class AgentBudgetCategory(StrEnum):
    MODEL = "model"
    TOOL = "tool"
    SCANNER = "scanner"
    PIPELINE = "pipeline"
    RUN = "run"


class AgentBudgetReservationStatus(StrEnum):
    RESERVED = "reserved"
    SETTLED = "settled"
    RELEASED = "released"
    FORFEITED = "forfeited"


class StepStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    DEGRADED = "degraded"  # completed without a non-essential dependency


class MessageRole(StrEnum):
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"
    TOOL = "tool"


class AgentActionName(StrEnum):
    """An allow-listed external action the agent may propose, never invent."""

    SYNC_GITHUB_ALERTS = "sync_github_alerts"
    SYNC_GITLAB_ALERTS = "sync_gitlab_alerts"
    SYNC_WAZUH_ALERTS = "sync_wazuh_alerts"
    SYNC_SONARQUBE_ALERTS = "sync_sonarqube_alerts"
    SYNC_SNYK_ISSUES = "sync_snyk_issues"
    SYNC_TENABLE_VULNERABILITIES = "sync_tenable_vulnerabilities"
    SYNC_QUALYS_HOST_DETECTIONS = "sync_qualys_host_detections"
    SYNC_RAPID7_VULNERABILITIES = "sync_rapid7_vulnerabilities"
    SYNC_WIZ_ISSUES = "sync_wiz_issues"
    SYNC_PRISMA_CLOUD_ALERTS = "sync_prisma_cloud_alerts"
    SYNC_CROWDSTRIKE_VULNERABILITIES = "sync_crowdstrike_vulnerabilities"
    SYNC_AWS_SECURITY_HUB_FINDINGS = "sync_aws_security_hub_findings"
    SYNC_AWS_INSPECTOR_FINDINGS = "sync_aws_inspector_findings"
    SYNC_HACKERONE_REPORTS = "sync_hackerone_reports"
    SYNC_BUGCROWD_SUBMISSIONS = "sync_bugcrowd_submissions"
    SYNC_CHECKMARX_RESULTS = "sync_checkmarx_results"
    SYNC_FORTIFY_ISSUES = "sync_fortify_issues"
    SYNC_AZURE_DEFENDER_ALERTS = "sync_azure_defender_alerts"
    SYNC_GCP_SCC_FINDINGS = "sync_gcp_scc_findings"
    SYNC_BURP_DAST_FINDINGS = "sync_burp_dast_findings"
    UPDATE_GITHUB_ALERT = "update_github_alert"
    CREATE_JIRA_TICKET = "create_jira_ticket"
    CREATE_TICKET = "create_ticket"
    REFRESH_TICKET_STATUS = "refresh_ticket_status"
    UPDATE_CANONICAL_WORK = "update_canonical_work"
    BULK_UPDATE_CANONICAL_WORK = "bulk_update_canonical_work"
    REQUEST_RETEST = "request_retest"
    REQUEST_REMEDIATION_GROUP_RETESTS = "request_remediation_group_retests"
    REQUEST_RISK_ACCEPTANCE = "request_risk_acceptance"
    START_ASSESSMENT = "start_assessment"


class AgentActionStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"


class AgentSpecialistRole(StrEnum):
    NETWORK = "network"
    WEB = "web"
    CODE = "code"
    SECRETS = "secrets"
    SUPPLY_CHAIN = "supply_chain"
    CONTAINER = "container"
    CLOUD = "cloud"


class AgentSpecialistStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    DEGRADED = "degraded"
    FAILED = "failed"


class AgentAutonomyMode(StrEnum):
    MANUAL = "manual"
    SUPERVISED = "supervised"
    BOUNDED = "bounded"


class AgentToolApprovalMode(StrEnum):
    NEVER = "never"
    POLICY = "policy"
    ALWAYS = "always"


class AgentEvaluationDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class KnowledgeRetrievalProvider(StrEnum):
    INTERNAL = "internal"
    DIFY = "dify"


class KnowledgeSourceStatus(StrEnum):
    STORING = "storing"
    STORED = "stored"
    EXTRACTING = "extracting"
    CHUNKING = "chunking"
    EMBEDDING = "embedding"
    READY = "ready"
    FAILED = "failed"
    DELETED = "deleted"


class KnowledgeEmbeddingStatus(StrEnum):
    PENDING = "pending"
    READY = "ready"
    FAILED = "failed"


class AgentMemoryCandidateStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ApprovalDecision(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    APPROVED_ALL = "approved_all"
    CUSTOMIZED = "customized"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ApprovalKind(StrEnum):
    SCAN_SCOPE = "scan_scope"
    HIGH_RISK_TOOL = "high_risk_tool"
    REMEDIATION_APPLY = "remediation_apply"
    TICKET_BULK_CREATE = "ticket_bulk_create"


# ---------------------------------------------------------------------------
# Integrations, notifications, audit
# ---------------------------------------------------------------------------


class IntegrationKind(StrEnum):
    LLM = "llm"
    DEFECTDOJO = "defectdojo"
    JIRA = "jira"
    SERVICENOW = "servicenow"
    AZURE_DEVOPS = "azure_devops"
    LINEAR = "linear"
    PAGERDUTY = "pagerduty"
    SPLUNK = "splunk"
    BURP_DAST = "burp_dast"
    SLACK = "slack"
    EMAIL = "email"
    DIFY = "dify"
    MISP = "misp"
    NVD = "nvd"
    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"
    WAZUH = "wazuh"
    SONARQUBE = "sonarqube"
    SNYK = "snyk"
    TENABLE = "tenable"
    QUALYS = "qualys"
    RAPID7 = "rapid7"
    WIZ = "wiz"
    PRISMA_CLOUD = "prisma_cloud"
    CROWDSTRIKE = "crowdstrike"
    AWS_SECURITY_HUB = "aws_security_hub"
    AWS_INSPECTOR = "aws_inspector"
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    CHECKMARX = "checkmarx"
    FORTIFY = "fortify"
    AZURE_DEFENDER = "azure_defender"
    GCP_SCC = "gcp_scc"
    PROWLER_AWS = "prowler_aws"
    PROWLER_AZURE = "prowler_azure"
    PROWLER_GCP = "prowler_gcp"
    ZSCALER = "zscaler"


class IntegrationStatus(StrEnum):
    CONFIGURED = "configured"
    UNVERIFIED = "unverified"
    ERROR = "error"
    DISABLED = "disabled"


class InboundTicketEventStatus(StrEnum):
    RECEIVED = "received"
    PROCESSED = "processed"
    IGNORED = "ignored"


class NotificationEvent(StrEnum):
    ASSESSMENT_STARTED = "assessment_started"
    APPROVAL_REQUIRED = "approval_required"
    CRITICAL_FINDING = "critical_finding"
    ASSESSMENT_COMPLETED = "assessment_completed"
    ASSESSMENT_FAILED = "assessment_failed"
    TICKET_CREATED = "ticket_created"
    TICKET_CLOSED = "ticket_closed"
    NEW_ASSET = "new_asset"
    SLA_BREACH = "sla_breach"
    AUTOMATION_NOTIFICATION = "automation_notification"


class NotificationChannel(StrEnum):
    SLACK = "slack"
    EMAIL = "email"
    WEBSOCKET = "websocket"
    PAGERDUTY = "pagerduty"
    WEBHOOK = "webhook"
    SPLUNK = "splunk"


class NotificationStatus(StrEnum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    SUPPRESSED = "suppressed"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class ReportFormat(StrEnum):
    HTML = "html"
    PDF = "pdf"
    JSON = "json"


class ReportStatus(StrEnum):
    PENDING = "pending"
    GENERATING = "generating"
    READY = "ready"
    FAILED = "failed"


__all__ = [
    "ALLOWED_TRANSITIONS",
    "PERMISSIONS",
    "STAGE_ORDER",
    "AgentRunStatus",
    "AgentTaskStatus",
    "AgentTaskKind",
    "AgentTaskDependencyKind",
    "AgentTaskAttemptStatus",
    "AgentEvidenceKind",
    "AgentBudgetCategory",
    "AgentBudgetReservationStatus",
    "AgentAutonomyMode",
    "AgentEvaluationDecision",
    "AgentMemoryCandidateStatus",
    "AgentToolApprovalMode",
    "AgentWorkspaceArtifactKind",
    "AgentWorkspaceCredentialStatus",
    "AgentWorkspaceExecutionKind",
    "AgentWorkspaceExecutionStatus",
    "AgentWorkspaceStatus",
    "ApprovalDecision",
    "ApprovalKind",
    "ArtifactKind",
    "AttackSimulationCampaignStatus",
    "AssessmentDepth",
    "AssessmentStage",
    "AssessmentStatus",
    "AssetEnvironment",
    "AssetRelationshipType",
    "AssetStatus",
    "AuditOutcome",
    "Criticality",
    "CriticalitySource",
    "EnrichmentStatus",
    "EngagementDocumentKind",
    "EngagementMilestoneStatus",
    "EngagementParticipantRole",
    "EngagementParticipantStatus",
    "EngagementRetestStatus",
    "EngagementType",
    "ExecutionMode",
    "ExternalAlertTriageStatus",
    "FindingStatus",
    "CanonicalFindingStatus",
    "IntegrationKind",
    "IntegrationStatus",
    "InboundTicketEventStatus",
    "JobStatus",
    "KnowledgeEmbeddingStatus",
    "KnowledgeRetrievalProvider",
    "KnowledgeSourceStatus",
    "MessageRole",
    "NotificationChannel",
    "NotificationEvent",
    "NotificationStatus",
    "Permission",
    "Priority",
    "PtaasEngagementStatus",
    "ReportFormat",
    "ReportStatus",
    "RiskLevel",
    "Role",
    "ScannerName",
    "Scope",
    "Severity",
    "StepStatus",
    "StrEnum",
    "ValidationStatus",
    "role_has",
]
