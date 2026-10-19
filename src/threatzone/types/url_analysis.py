"""URL analysis type definitions.

Mirrors the `url-analysis.response.dto.ts` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .common import ReportStatusValue, ThreatLevel

UrlAnalysisNetworkConfigSource = Literal["submit", "admin-default"] | str
UrlScoreIndicatorsState = Literal["available", "pending", "unavailable"] | str
UrlScoreExplanationUnavailableReason = Literal["legacy", "size_limit", "scoring_error"] | str
UrlScoreEvidenceKind = Literal["network", "finding", "intel", "report"] | str
UrlScoreIndicatorAvailability = Literal["measured", "not_measured", "unavailable"] | str
UrlScoreIndicatorConfidence = Literal["high", "heuristic"] | str
UrlScoreIndicatorDisposition = (
    Literal[
        "contributing",
        "informational",
        "suppressed",
        "no_match",
        "not_measured",
        "unavailable",
    ]
    | str
)
UrlScoreVerdict = Literal["unknown", "benign", "suspicious", "malicious"] | str
UrlScorePass = Literal["submit", "final"] | str
UrlScoreCreditScope = Literal["heuristic", "all"] | str
UrlScoreEvidenceState = Literal["available", "unavailable"] | str
UrlAnalysisBrowserSectionName = Literal["overview", "findings", "tls", "network-summary"]


class UrlAnalysisThreatStatus(BaseModel):
    """Verdict bag attached to URL analysis sub-objects (page, IP, file)."""

    model_config = ConfigDict(populate_by_name=True)

    verdict: ThreatLevel
    title: str
    description: str


class UrlAnalysisGeneralInfo(BaseModel):
    """Basic facts about the analysed URL."""

    model_config = ConfigDict(populate_by_name=True)

    url: str
    domain: str
    website_title: str | None = Field(default=None, alias="websiteTitle")


class UrlAnalysisScreenshot(BaseModel):
    """Screenshot availability flag."""

    model_config = ConfigDict(populate_by_name=True)

    available: bool


class UrlAnalysisIpInfo(BaseModel):
    """Resolved IP information for the analysed URL."""

    model_config = ConfigDict(populate_by_name=True)

    ip: str
    asn: str | None = None
    city: str | None = None
    country: str | None = None
    isp: str | None = None
    organization: str | None = None
    threat_status: UrlAnalysisThreatStatus = Field(alias="threatStatus")


class UrlAnalysisDnsRecord(BaseModel):
    """DNS records grouped by record type."""

    model_config = ConfigDict(populate_by_name=True)

    type: str
    records: list[str]


class UrlAnalysisWhoisInfo(BaseModel):
    """WHOIS record for the analysed domain."""

    model_config = ConfigDict(populate_by_name=True)

    domain_name: str | None = Field(default=None, alias="domainName")
    domain_id: str | None = Field(default=None, alias="domainId")
    name_servers: list[str] = Field(alias="nameServers")
    creation_date: str | None = Field(default=None, alias="creationDate")
    updated_date: str | None = Field(default=None, alias="updatedDate")
    expiration_date: str | None = Field(default=None, alias="expirationDate")
    registrar: str | None = None
    registrar_iana_id: str | None = Field(default=None, alias="registrarIanaId")
    email: str | None = None
    phone: str | None = None


class UrlAnalysisSslCertificate(BaseModel):
    """Parsed leaf TLS certificate for the analysed URL."""

    model_config = ConfigDict(populate_by_name=True)

    subject: str
    issuer: str
    renewed_at: int = Field(alias="renewedAt")
    expires_at: int = Field(alias="expiresAt")
    serial_number: str = Field(alias="serialNumber")
    fingerprint: str


class UrlAnalysisExtractedFile(BaseModel):
    """A file the analyser extracted from the page."""

    model_config = ConfigDict(populate_by_name=True)

    uuid: str
    threat_status: UrlAnalysisThreatStatus = Field(alias="threatStatus")


class UrlAnalysisThreatOverviewItem(BaseModel):
    """A per-source verdict in the URL threat analysis overview."""

    model_config = ConfigDict(populate_by_name=True)

    source: str
    title: str
    description: str
    verdict: ThreatLevel


class UrlAnalysisThreatDetailItem(BaseModel):
    """A per-source detail payload in the URL threat analysis."""

    model_config = ConfigDict(populate_by_name=True)

    source: str
    # Free-form: shape varies per intelligence source.
    details: dict[str, Any] | None = None


class UrlAnalysisThreatAnalysis(BaseModel):
    """Aggregated threat intelligence for the analysed URL."""

    model_config = ConfigDict(populate_by_name=True)

    overview: list[UrlAnalysisThreatOverviewItem]
    blacklist: bool
    threat_details: list[UrlAnalysisThreatDetailItem] = Field(alias="threatDetails")


class UrlAnalysisPrivacyFactor(BaseModel):
    """One contributor to the privacy risk score."""

    model_config = ConfigDict(populate_by_name=True)

    factor: str
    label: str
    delta: float
    detail: str | None = None


class UrlAnalysisVerdictProvenance(BaseModel):
    """How the final verdict was produced."""

    model_config = ConfigDict(populate_by_name=True)

    raw_verdict: str = Field(alias="rawVerdict")
    quorum_applied: bool = Field(alias="quorumApplied")
    allowlist_applied: bool = Field(alias="allowlistApplied")
    collection_state: str | None = Field(default=None, alias="collectionState")
    pass_: str = Field(alias="pass")


class UrlAnalysisImpersonationTarget(BaseModel):
    """Brand the analysed page most likely impersonates."""

    model_config = ConfigDict(populate_by_name=True)

    brand_name: str = Field(alias="brandName")
    canonical_domain: str | None = Field(default=None, alias="canonicalDomain")
    signals: list[str] = Field(default_factory=list)
    confidence: str


class UrlAnalysisCompleteness(BaseModel):
    """Which sources produced evidence for the score."""

    model_config = ConfigDict(populate_by_name=True)

    measured_sources: list[str] = Field(default_factory=list, alias="measuredSources")
    skipped_sources: list[str] = Field(default_factory=list, alias="skippedSources")
    unavailable_sources: list[str] = Field(default_factory=list, alias="unavailableSources")
    browser_collection: str | None = Field(default=None, alias="browserCollection")


class UrlAnalysisIntelDetection(BaseModel):
    """One threat-intelligence hit recorded during analysis."""

    model_config = ConfigDict(populate_by_name=True)

    source: str
    detection_type: str = Field(alias="detectionType")
    severity: str
    details: str | None = None


class UrlAnalysisSessionConfig(BaseModel):
    """Device and network selection the interactive session ran with."""

    model_config = ConfigDict(populate_by_name=True)

    device_profile_id: str | None = Field(default=None, alias="deviceProfileId")
    network_config_id: str | None = Field(default=None, alias="networkConfigId")
    network_config_source: UrlAnalysisNetworkConfigSource | None = Field(
        default=None, alias="networkConfigSource"
    )
    network_config_name: str | None = Field(default=None, alias="networkConfigName")
    session_duration_seconds: int | None = Field(default=None, alias="sessionDurationSeconds")
    device_preset_id: str | None = Field(default=None, alias="devicePresetId")
    device_preset_name: str | None = Field(default=None, alias="devicePresetName")


class UrlAnalysisSession(BaseModel):
    """State of the interactive browser session for a URL submission."""

    model_config = ConfigDict(populate_by_name=True)

    state: str
    collection_status: str = Field(alias="collectionStatus")
    recording_status: str = Field(alias="recordingStatus")
    queue_position: int | None = Field(default=None, alias="queuePosition")
    vnc_available: bool = Field(alias="vncAvailable")
    report_available: bool = Field(alias="reportAvailable")
    started_at: int | None = Field(default=None, alias="startedAt")
    ready_at: int | None = Field(default=None, alias="readyAt")
    expires_at: int | None = Field(default=None, alias="expiresAt")
    finished_at: int | None = Field(default=None, alias="finishedAt")
    failure_code: str | None = Field(default=None, alias="failureCode")
    extensions_used: int = Field(default=0, alias="extensionsUsed")
    extensions_max: int = Field(default=0, alias="extensionsMax")
    session_config: UrlAnalysisSessionConfig | None = Field(default=None, alias="sessionConfig")
    link: str | None = None
    expired: bool


class UrlAnalysisResponse(BaseModel):
    """Full URL analysis report payload."""

    model_config = ConfigDict(populate_by_name=True)

    level: ThreatLevel
    status: ReportStatusValue
    job_id: str | None = Field(default=None, alias="jobId")
    general_info: UrlAnalysisGeneralInfo = Field(alias="generalInfo")
    screenshot: UrlAnalysisScreenshot
    ip_info: UrlAnalysisIpInfo | None = Field(default=None, alias="ipInfo")
    dns_records: list[UrlAnalysisDnsRecord] = Field(alias="dnsRecords")
    whois: UrlAnalysisWhoisInfo | None = None
    ssl_certificate: UrlAnalysisSslCertificate | None = Field(default=None, alias="sslCertificate")
    # Free-form: header names are not normalised by the API.
    response_headers: dict[str, Any] | None = Field(default=None, alias="responseHeaders")
    extracted_file: UrlAnalysisExtractedFile | None = Field(default=None, alias="extractedFile")
    threat_analysis: UrlAnalysisThreatAnalysis | None = Field(default=None, alias="threatAnalysis")
    pages: list[str]
    threat_score: float | None = Field(default=None, alias="threatScore")
    risk_level: str | None = Field(default=None, alias="riskLevel")
    privacy_score: float | None = Field(default=None, alias="privacyScore")
    privacy_risk_level: str | None = Field(default=None, alias="privacyRiskLevel")
    privacy_breakdown: list[UrlAnalysisPrivacyFactor] | None = Field(
        default=None, alias="privacyBreakdown"
    )
    verdict_provenance: UrlAnalysisVerdictProvenance | None = Field(
        default=None, alias="verdictProvenance"
    )
    impersonation_target: UrlAnalysisImpersonationTarget | None = Field(
        default=None, alias="impersonationTarget"
    )
    completeness: UrlAnalysisCompleteness | None = None
    intel_detections: list[UrlAnalysisIntelDetection] = Field(
        default_factory=list, alias="intelDetections"
    )
    metafields: dict[str, Any] | None = None
    scored_at: datetime | None = Field(default=None, alias="scoredAt")


class UrlScoreBrowserSnapshot(BaseModel):
    """Browser snapshot that the URL score used."""

    model_config = ConfigDict(populate_by_name=True)

    job_id: str = Field(alias="jobId")
    manifest_hash: str = Field(alias="manifestHash")


class UrlScoreEvidenceRef(BaseModel):
    """Reference to one evidence item of a score indicator."""

    model_config = ConfigDict(populate_by_name=True)

    kind: UrlScoreEvidenceKind
    id: str
    available: bool


class UrlScoreIndicator(BaseModel):
    """One indicator of the URL score explanation.

    ``title`` and ``reason`` are display text and can change between scoring
    versions. Use ``id`` and ``rule_id`` in automation.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str
    rule_id: str = Field(alias="ruleId")
    source: str | None = None
    family: str | None = None
    title: str
    reason: str | None = None
    availability: UrlScoreIndicatorAvailability
    confidence: UrlScoreIndicatorConfidence
    original_rule_score: float = Field(alias="originalRuleScore")
    weighted_points: float = Field(alias="weightedPoints")
    disposition: UrlScoreIndicatorDisposition
    suppressed_by: str | None = Field(default=None, alias="suppressedBy")
    evidence_refs: list[UrlScoreEvidenceRef] = Field(default_factory=list, alias="evidenceRefs")


class UrlScoreReputationCredit(BaseModel):
    """A reputation credit that can reduce the URL score."""

    model_config = ConfigDict(populate_by_name=True)

    rule_id: str = Field(alias="ruleId")
    eligible: bool
    nominal_points: float = Field(alias="nominalPoints")
    reason: str


class UrlScoreAggregation(BaseModel):
    """How the indicator points add up to the URL threat score."""

    model_config = ConfigDict(populate_by_name=True)

    high_points: float = Field(alias="highPoints")
    heuristic_points: float = Field(alias="heuristicPoints")
    reputation_credits: list[UrlScoreReputationCredit] = Field(
        default_factory=list, alias="reputationCredits"
    )
    credit_scope: UrlScoreCreditScope = Field(alias="creditScope")
    effective_credit: float = Field(alias="effectiveCredit")
    score_before_clamp: float = Field(alias="scoreBeforeClamp")
    score_after_clamp: float = Field(alias="scoreAfterClamp")
    rounding_adjustment: float = Field(alias="roundingAdjustment")
    impersonation_floor_adjustment: float = Field(alias="impersonationFloorAdjustment")


class UrlScoreVerdictAdjustment(BaseModel):
    """A rule that changed the URL verdict after scoring."""

    model_config = ConfigDict(populate_by_name=True)

    rule_id: str = Field(alias="ruleId")
    from_: UrlScoreVerdict = Field(alias="from")
    to: UrlScoreVerdict
    reason: str


class UrlScoreExplanation(BaseModel):
    """Stored explanation of the URL threat score of one scoring pass."""

    model_config = ConfigDict(populate_by_name=True)

    schema_version: int = Field(alias="schemaVersion")
    scoring_version: str = Field(alias="scoringVersion")
    job_id: str = Field(alias="jobId")
    pass_: UrlScorePass = Field(alias="pass")
    # The evidence route compares this text exactly, so the SDK keeps the server text.
    scored_at: str = Field(alias="scoredAt")
    browser_snapshot: UrlScoreBrowserSnapshot | None = Field(default=None, alias="browserSnapshot")
    threat_score: float = Field(alias="threatScore")
    verdict: UrlScoreVerdict
    indicators: list[UrlScoreIndicator] = Field(default_factory=list)
    aggregation: UrlScoreAggregation
    verdict_adjustments: list[UrlScoreVerdictAdjustment] = Field(
        default_factory=list, alias="verdictAdjustments"
    )


class UrlAnalysisIndicators(BaseModel):
    """Response of ``GET /submissions/{uuid}/url-analysis/indicators``."""

    model_config = ConfigDict(populate_by_name=True)

    state: UrlScoreIndicatorsState
    unavailable_reason: UrlScoreExplanationUnavailableReason | None = Field(
        default=None, alias="unavailableReason"
    )
    snapshot: UrlScoreExplanation | None = None


class UrlAnalysisIndicatorEvidence(BaseModel):
    """One evidence item of a URL score indicator.

    ``text`` is pretty-printed JSON of 8192 characters or fewer.
    """

    model_config = ConfigDict(populate_by_name=True)

    state: UrlScoreEvidenceState
    text: str | None = None
    truncated: bool = False


class UrlAnalysisBrowserSection(BaseModel):
    """One approved section of the browser snapshot of the current URL run."""

    model_config = ConfigDict(populate_by_name=True)

    section: UrlAnalysisBrowserSectionName | str
    job_id: str = Field(alias="jobId")
    revision: str
    updated_at: int | None = Field(default=None, alias="updatedAt")
    # Free-form: the section data follows the report page and can add fields.
    data: dict[str, Any] = Field(default_factory=dict)
