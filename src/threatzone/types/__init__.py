"""Type definitions for the Threat.Zone Python SDK."""

from .behaviours import BehaviourEvent, BehaviourOs, BehavioursResponse
from .cdr import CdrResponse, CdrResult
from .common import (
    FileEntrypoint,
    FileInfo,
    FileSource,
    Hashes,
    OperatingSystemPlatform,
    ReportOperatingSystem,
    ReportStatus,
    ReportStatusValue,
    ReportType,
    Tag,
    ThreatLevel,
)
from .config import (
    EnvironmentOption,
    MetafieldOption,
    Metafields,
)
from .downloads import MediaFile
from .eml import (
    EmlAnalysis,
    EmlAnalysisAttachment,
    EmlAnalysisHeaders,
    EmlAnalysisQrResult,
)
from .errors import ApiError, ApiErrorCode
from .indicators import (
    Artifact,
    ArtifactHashes,
    ArtifactsResponse,
    ArtifactType,
    ExtractedConfig,
    ExtractedConfigsResponse,
    Indicator,
    IndicatorAuthor,
    IndicatorLevel,
    IndicatorLevels,
    IndicatorsResponse,
    IoC,
    IoCsResponse,
    IoCType,
    OverviewSummary,
    SummaryIndicatorLevels,
    SummaryIndicators,
    SummaryNetwork,
    YaraRule,
    YaraRuleCategory,
    YaraRulesResponse,
)
from .me import (
    FileLimits,
    LimitsCount,
    ModuleInfo,
    PlanInfo,
    SubmissionLimits,
    UserInfo,
    UserInfoDetails,
    WorkspaceBasicInfo,
)
from .mitre import MitreResponse
from .network import (
    Connection,
    ConnectionPackets,
    ConnectionProtocol,
    DnsQuery,
    DnsRecordType,
    DnsStatus,
    HttpRequest,
    NetworkSummary,
    NetworkThreat,
    NetworkThreatTls,
    ThreatAppProto,
    ThreatProtocol,
    ThreatSeverity,
)
from .processes import (
    Process,
    ProcessesResponse,
    ProcessEventItem,
    ProcessEvents,
    ProcessNetwork,
    ProcessNetworkItem,
    ProcessTreeNode,
    ProcessTreeResponse,
)
from .signature_check import SignatureCheckResponse, SignatureCheckResult
from .static_scan import StaticScanResponse, StaticScanResult
from .submissions import (
    PaginatedSubmissions,
    Submission,
    SubmissionCreated,
    SubmissionIndicatorLevels,
    SubmissionIndicatorsRollup,
    SubmissionLevel,
    SubmissionListItem,
    SubmissionOverview,
    SubmissionOverviewJobs,
    SubmissionReportStatus,
    SubmissionType,
)
from .syscalls import SyscallsResponse
from .url_analysis import (
    UrlAnalysisDnsRecord,
    UrlAnalysisExtractedFile,
    UrlAnalysisGeneralInfo,
    UrlAnalysisIpInfo,
    UrlAnalysisResponse,
    UrlAnalysisScreenshot,
    UrlAnalysisSslCertificate,
    UrlAnalysisThreatAnalysis,
    UrlAnalysisThreatDetailItem,
    UrlAnalysisThreatOverviewItem,
    UrlAnalysisThreatStatus,
    UrlAnalysisWhoisInfo,
)

__all__ = [
    # Common
    "FileEntrypoint",
    "FileInfo",
    "FileSource",
    "Hashes",
    "OperatingSystemPlatform",
    "ReportOperatingSystem",
    "ReportStatus",
    "ReportStatusValue",
    "ReportType",
    "Tag",
    "ThreatLevel",
    # Errors
    "ApiError",
    "ApiErrorCode",
    # Config
    "EnvironmentOption",
    "MetafieldOption",
    "Metafields",
    # Downloads
    "MediaFile",
    # Indicators surface
    "Artifact",
    "ArtifactHashes",
    "ArtifactType",
    "ArtifactsResponse",
    "ExtractedConfig",
    "ExtractedConfigsResponse",
    "Indicator",
    "IndicatorAuthor",
    "IndicatorLevel",
    "IndicatorLevels",
    "IndicatorsResponse",
    "IoC",
    "IoCType",
    "IoCsResponse",
    "OverviewSummary",
    "SummaryIndicatorLevels",
    "SummaryIndicators",
    "SummaryNetwork",
    "YaraRule",
    "YaraRuleCategory",
    "YaraRulesResponse",
    # EML
    "EmlAnalysis",
    "EmlAnalysisAttachment",
    "EmlAnalysisHeaders",
    "EmlAnalysisQrResult",
    # Me
    "FileLimits",
    "LimitsCount",
    "ModuleInfo",
    "PlanInfo",
    "SubmissionLimits",
    "UserInfo",
    "UserInfoDetails",
    "WorkspaceBasicInfo",
    # Mitre
    "MitreResponse",
    # Network
    "Connection",
    "ConnectionPackets",
    "ConnectionProtocol",
    "DnsQuery",
    "DnsRecordType",
    "DnsStatus",
    "HttpRequest",
    "NetworkSummary",
    "NetworkThreat",
    "NetworkThreatTls",
    "ThreatAppProto",
    "ThreatProtocol",
    "ThreatSeverity",
    # Processes
    "Process",
    "ProcessesResponse",
    "ProcessEventItem",
    "ProcessEvents",
    "ProcessNetwork",
    "ProcessNetworkItem",
    "ProcessTreeNode",
    "ProcessTreeResponse",
    # Behaviours
    "BehaviourEvent",
    "BehaviourOs",
    "BehavioursResponse",
    # Syscalls
    "SyscallsResponse",
    # Static scan
    "StaticScanResponse",
    "StaticScanResult",
    # CDR
    "CdrResponse",
    "CdrResult",
    # Signature check
    "SignatureCheckResponse",
    "SignatureCheckResult",
    # URL analysis
    "UrlAnalysisDnsRecord",
    "UrlAnalysisExtractedFile",
    "UrlAnalysisGeneralInfo",
    "UrlAnalysisIpInfo",
    "UrlAnalysisResponse",
    "UrlAnalysisScreenshot",
    "UrlAnalysisSslCertificate",
    "UrlAnalysisThreatAnalysis",
    "UrlAnalysisThreatDetailItem",
    "UrlAnalysisThreatOverviewItem",
    "UrlAnalysisThreatStatus",
    "UrlAnalysisWhoisInfo",
    # Submissions
    "PaginatedSubmissions",
    "Submission",
    "SubmissionCreated",
    "SubmissionIndicatorLevels",
    "SubmissionIndicatorsRollup",
    "SubmissionLevel",
    "SubmissionListItem",
    "SubmissionOverview",
    "SubmissionOverviewJobs",
    "SubmissionReportStatus",
    "SubmissionType",
]
