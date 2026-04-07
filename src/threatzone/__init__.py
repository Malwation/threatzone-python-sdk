"""Threat.Zone Python SDK.

A Python SDK for the Threat.Zone malware analysis platform API.

Example:
    >>> from threatzone import ThreatZone
    >>> client = ThreatZone(api_key="your-api-key")
    >>> submission = client.create_sandbox_submission("malware.exe")
    >>> result = client.wait_for_completion(submission.uuid)
    >>> print(result.level)
"""

from ._async_client import AsyncThreatZone
from ._exceptions import (
    AnalysisTimeoutError,
    APIError,
    AuthenticationError,
    BadRequestError,
    ConnectionError,
    InternalServerError,
    NotFoundError,
    PaymentRequiredError,
    PermissionDeniedError,
    RateLimitError,
    ReportUnavailableError,
    ThreatZoneError,
    TimeoutError,
    YaraRulePendingError,
)
from ._streaming import AsyncDownloadResponse, DownloadResponse
from ._sync_client import ThreatZone
from .types import (
    Artifact,
    ArtifactsResponse,
    BehaviourEvent,
    BehaviourOs,
    BehavioursResponse,
    CdrResponse,
    CdrResult,
    Connection,
    DnsQuery,
    EmlAnalysis,
    EnvironmentOption,
    ExtractedConfig,
    ExtractedConfigsResponse,
    FileInfo,
    FileLimits,
    Hashes,
    HttpRequest,
    Indicator,
    IndicatorsResponse,
    IoC,
    IoCsResponse,
    LimitsCount,
    MediaFile,
    MetafieldOption,
    Metafields,
    MitreResponse,
    ModuleInfo,
    NetworkSummary,
    NetworkThreat,
    OverviewSummary,
    PaginatedSubmissions,
    PlanInfo,
    Process,
    ProcessesResponse,
    ProcessTreeResponse,
    ReportStatus,
    SignatureCheckResponse,
    SignatureCheckResult,
    StaticScanResponse,
    StaticScanResult,
    Submission,
    SubmissionCreated,
    SubmissionLimits,
    SubmissionListItem,
    SyscallsResponse,
    Tag,
    UrlAnalysisResponse,
    UserInfo,
    UserInfoDetails,
    WorkspaceBasicInfo,
    YaraRule,
    YaraRulesResponse,
)

__version__ = "1.0.0"

__all__ = [
    # Clients
    "ThreatZone",
    "AsyncThreatZone",
    # Download responses
    "DownloadResponse",
    "AsyncDownloadResponse",
    # Exceptions
    "ThreatZoneError",
    "APIError",
    "AuthenticationError",
    "PaymentRequiredError",
    "PermissionDeniedError",
    "NotFoundError",
    "BadRequestError",
    "RateLimitError",
    "InternalServerError",
    "TimeoutError",
    "ConnectionError",
    "AnalysisTimeoutError",
    "YaraRulePendingError",
    "ReportUnavailableError",
    # Types - Common
    "Hashes",
    "FileInfo",
    "Tag",
    "ReportStatus",
    # Types - Config
    "MetafieldOption",
    "Metafields",
    "EnvironmentOption",
    # Types - Downloads
    "MediaFile",
    # Types - Indicators
    "Indicator",
    "IndicatorsResponse",
    "IoC",
    "IoCsResponse",
    "YaraRule",
    "YaraRulesResponse",
    "ExtractedConfig",
    "ExtractedConfigsResponse",
    "Artifact",
    "ArtifactsResponse",
    "OverviewSummary",
    # Types - EML
    "EmlAnalysis",
    # Types - Mitre
    "MitreResponse",
    # Types - Me
    "UserInfo",
    "UserInfoDetails",
    "WorkspaceBasicInfo",
    "LimitsCount",
    "PlanInfo",
    "FileLimits",
    "SubmissionLimits",
    "ModuleInfo",
    # Types - Network
    "NetworkSummary",
    "DnsQuery",
    "HttpRequest",
    "Connection",
    "NetworkThreat",
    # Types - Processes
    "Process",
    "ProcessesResponse",
    "ProcessTreeResponse",
    # Types - Behaviours
    "BehaviourEvent",
    "BehaviourOs",
    "BehavioursResponse",
    # Types - Syscalls
    "SyscallsResponse",
    # Types - Static scan / CDR / Signature check
    "StaticScanResponse",
    "StaticScanResult",
    "CdrResponse",
    "CdrResult",
    "SignatureCheckResponse",
    "SignatureCheckResult",
    # Types - URL analysis
    "UrlAnalysisResponse",
    # Types - Submissions
    "SubmissionCreated",
    "SubmissionListItem",
    "PaginatedSubmissions",
    "Submission",
]
