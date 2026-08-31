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
    ASSESSMENT_READ = "assessment:read"
    ASSESSMENT_CREATE = "assessment:create"
    ASSESSMENT_APPROVE = "assessment:approve"
    ASSESSMENT_CANCEL = "assessment:cancel"
    ASSET_READ = "asset:read"
    ASSET_TAG = "asset:tag"
    FINDING_READ = "finding:read"
    FINDING_ANALYZE = "finding:analyze"
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
    FAILED = "failed"
    CANCELLED = "cancelled"


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
    DEFECTDOJO = "defectdojo"
    JIRA = "jira"
    SLACK = "slack"
    EMAIL = "email"
    DIFY = "dify"
    MISP = "misp"
    NVD = "nvd"
    GITHUB = "github"
    GITLAB = "gitlab"


class IntegrationStatus(StrEnum):
    CONFIGURED = "configured"
    UNVERIFIED = "unverified"
    ERROR = "error"
    DISABLED = "disabled"


class NotificationEvent(StrEnum):
    ASSESSMENT_STARTED = "assessment_started"
    APPROVAL_REQUIRED = "approval_required"
    CRITICAL_FINDING = "critical_finding"
    ASSESSMENT_COMPLETED = "assessment_completed"
    ASSESSMENT_FAILED = "assessment_failed"
    TICKET_CREATED = "ticket_created"


class NotificationChannel(StrEnum):
    SLACK = "slack"
    EMAIL = "email"
    WEBSOCKET = "websocket"


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
    "ApprovalDecision",
    "ApprovalKind",
    "ArtifactKind",
    "AssessmentDepth",
    "AssessmentStage",
    "AssessmentStatus",
    "AssetStatus",
    "AuditOutcome",
    "Criticality",
    "CriticalitySource",
    "EnrichmentStatus",
    "FindingStatus",
    "IntegrationKind",
    "IntegrationStatus",
    "JobStatus",
    "MessageRole",
    "NotificationChannel",
    "NotificationEvent",
    "NotificationStatus",
    "Permission",
    "Priority",
    "ReportFormat",
    "ReportStatus",
    "RiskLevel",
    "Role",
    "ScannerName",
    "Scope",
    "Severity",
    "StepStatus",
    "StrEnum",
    "role_has",
]
