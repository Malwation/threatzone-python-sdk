"""URL analysis type definitions.

Mirrors the `url-analysis.response.dto.ts` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .common import ReportStatusValue, ThreatLevel

UrlAnalysisNetworkConfigSource = Literal["submit", "admin-default"] | str
UrlAnalysisSessionQueueReason = Literal["workspace_queue", "cluster_capacity"] | str
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
        "other_url",
    ]
    | str
)
UrlScoreIndicatorLevel = Literal["malicious", "suspicious", "benign"] | str
UrlScoreVerdict = Literal["unknown", "benign", "suspicious", "malicious"] | str
UrlScorePass = Literal["submit", "final"] | str
UrlScoreCreditScope = Literal["heuristic", "all"] | str
UrlScoreEvidenceState = Literal["available", "unavailable"] | str
UrlAnalysisBrowserSectionName = Literal["overview", "findings", "tls", "network-summary"]
UrlAnalysisScoreState = Literal["scored", "failed", "not_scored"] | str
UrlResultVia = (
    Literal["submitted", "http_redirect", "browser_redirect", "browser_navigation", "unknown"] | str
)
UrlDownloadedFileState = (
    Literal["completed", "canceled", "too_large", "upload_failed", "incomplete"] | str
)
UrlDownloadInitiator = Literal["navigation", "script", "unknown"] | str
UrlDownloadLimitReason = Literal["too_large", "run_bytes_exceeded", "file_count_exceeded"] | str
UrlScoreEvidenceFactKind = Literal["observed", "would_confirm"] | str
UrlAnalysisPrivacyUnavailableReason = (
    Literal["collection_failed", "no_network", "page_not_loaded"] | str
)
UrlAnalysisConsentState = Literal["no_banner", "before_consent"] | str


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
    threat_status: UrlAnalysisThreatStatus | None = Field(
        default=None,
        alias="threatStatus",
        deprecated=(
            "threat_status is removed from the API in its next release. "
            "Read UrlAnalysisResponse.threat_analysis."
        ),
    )
    """Deprecated: no source writes it. The verdict is always ``unknown``. Read
    ``UrlAnalysisResponse.threat_analysis`` for verdicts."""


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


class UrlAnalysisNavigationSslCertificate(BaseModel):
    """TLS certificate of one checked URL. The times are ISO 8601 UTC text."""

    model_config = ConfigDict(populate_by_name=True)

    subject: str
    issuer: str
    expires_at: str | None = Field(default=None, alias="expiresAt")
    renewed_at: str | None = Field(default=None, alias="renewedAt")
    fingerprint: str | None = None


class UrlAnalysisNavigationContext(BaseModel):
    """DNS, WHOIS and TLS lookups of one checked URL."""

    model_config = ConfigDict(populate_by_name=True)

    url: str
    dns_records: list[UrlAnalysisDnsRecord] = Field(default_factory=list, alias="dnsRecords")
    whois_creation_date: str | None = Field(default=None, alias="whoisCreationDate")
    ssl_certificate: UrlAnalysisNavigationSslCertificate | None = Field(
        default=None, alias="sslCertificate"
    )


class UrlAnalysisUrlResult(BaseModel):
    """One node of the tree of URLs that the analysis checked.

    The node with ``parent_id=None`` is the submitted URL.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str
    parent_id: str | None = Field(default=None, alias="parentId")
    hop: int
    via: UrlResultVia
    redirect_status: int | None = Field(default=None, alias="redirectStatus")
    url: str
    overview: list[UrlAnalysisThreatOverviewItem] = Field(default_factory=list)
    blacklist: bool
    threat_details: list[UrlAnalysisThreatDetailItem] = Field(
        default_factory=list, alias="threatDetails"
    )
    navigation_context: UrlAnalysisNavigationContext | None = Field(
        default=None, alias="navigationContext"
    )


class UrlAnalysisThreatAnalysis(BaseModel):
    """Aggregated threat intelligence for the analysed URL."""

    model_config = ConfigDict(populate_by_name=True)

    overview: list[UrlAnalysisThreatOverviewItem]
    blacklist: bool
    threat_details: list[UrlAnalysisThreatDetailItem] = Field(alias="threatDetails")
    url_results: list[UrlAnalysisUrlResult] = Field(default_factory=list, alias="urlResults")
    """Tree of checked URLs. Empty on older servers."""


class UrlAnalysisDownloadedFile(BaseModel):
    """One file that the browser downloaded while it loaded the page.

    A ``completed`` file has ``artifact_id``, ``sha256`` and ``size``. Pass
    ``artifact_id`` to ``download_artifact()`` or ``analyze_artifact()``. An
    ``incomplete`` file has ``received_bytes`` and no artifact.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: str
    artifact_id: str | None = Field(default=None, alias="artifactId")
    filename: str
    detected_type: str | None = Field(default=None, alias="detectedType")
    mime_type: str | None = Field(default=None, alias="mimeType")
    size: int | None = None
    """Size of the complete file in bytes. ``None`` when the file did not complete."""
    received_bytes: int | None = Field(default=None, alias="receivedBytes")
    """Bytes received before the download stopped. Set for ``incomplete`` files and for
    ``too_large`` files that a limit stopped while they ran."""
    sha256: str | None = None
    source_url: str = Field(alias="sourceUrl")
    initiator: UrlDownloadInitiator
    state: UrlDownloadedFileState
    limit_reason: UrlDownloadLimitReason | None = Field(default=None, alias="limitReason")
    """The limit that stopped a ``too_large`` file. ``None`` for other states."""
    captured_at: datetime = Field(alias="capturedAt")


class UrlAnalysisPrivacyFactor(BaseModel):
    """One contributor to the privacy risk score."""

    model_config = ConfigDict(populate_by_name=True)

    factor: str
    label: str
    delta: float
    detail: str | None = None


class UrlAnalysisPrivacyContext(BaseModel):
    """Measurement context of the privacy score."""

    model_config = ConfigDict(populate_by_name=True)

    region: str | None = None
    """Region of the browser egress that the score was measured from. ``None`` when it is
    not known."""
    consent_state: UrlAnalysisConsentState = Field(alias="consentState")
    """``no_banner``: the page showed no consent banner. ``before_consent``: the score counts
    only what the page did before the analysis accepted a consent banner."""
    excluded_after_consent: int = Field(alias="excludedAfterConsent")
    """Observations first seen after the analysis accepted a consent banner. The score does
    not count them."""


class UrlAnalysisVerdictProvenance(BaseModel):
    """How the final verdict was produced."""

    model_config = ConfigDict(populate_by_name=True)

    raw_verdict: str = Field(alias="rawVerdict")
    quorum_applied: bool = Field(alias="quorumApplied")
    allowlist_applied: bool = Field(alias="allowlistApplied")
    collection_state: str | None = Field(default=None, alias="collectionState")
    pass_: str = Field(alias="pass")


class UrlAnalysisImpersonationEvidence(BaseModel):
    """A finding that ties the analysed host to the impersonated brand."""

    model_config = ConfigDict(populate_by_name=True)

    source: str
    technique: str
    """For example ``homoglyph`` or ``tld-swap``. Treat an unknown value as a generic domain
    resemblance."""
    matched_token: str | None = Field(default=None, alias="matchedToken")
    compared_domain: str | None = Field(default=None, alias="comparedDomain")


class UrlAnalysisImpersonationTarget(BaseModel):
    """Brand the analysed page most likely impersonates."""

    model_config = ConfigDict(populate_by_name=True)

    brand_name: str = Field(alias="brandName")
    display_name: str | None = Field(default=None, alias="displayName")
    """Human-readable name of the brand. ``None`` on older reports and servers."""
    canonical_domain: str | None = Field(default=None, alias="canonicalDomain")
    signals: list[str] = Field(default_factory=list)
    confidence: str
    evidence: list[UrlAnalysisImpersonationEvidence] = Field(default_factory=list)
    """Empty when the report has no structured findings and on older servers."""


class UrlAnalysisCompleteness(BaseModel):
    """Which sources produced evidence for the score."""

    model_config = ConfigDict(populate_by_name=True)

    measured_sources: list[str] = Field(default_factory=list, alias="measuredSources")
    skipped_sources: list[str] = Field(default_factory=list, alias="skippedSources")
    unavailable_sources: list[str] = Field(default_factory=list, alias="unavailableSources")
    browser_collection: str | None = Field(default=None, alias="browserCollection")
    browser_collection_note: str | None = Field(default=None, alias="browserCollectionNote")
    """Plain note on the browser evidence of the run. ``None`` when there is nothing to
    note and on older servers."""


class UrlAnalysisBrowserSnapshot(BaseModel):
    """Browser snapshot of the current URL run."""

    model_config = ConfigDict(populate_by_name=True)

    job_id: str | None = Field(
        default=None,
        alias="jobId",
        deprecated="job_id is removed from the API in its next release.",
    )
    """Deprecated: removed from the API in its next release."""
    revision: str | None = Field(
        default=None,
        deprecated="revision is removed from the API in its next release.",
    )
    """Deprecated: removed from the API in its next release. The same value as
    ``UrlAnalysisBrowserSection.revision``."""
    sections: list[UrlAnalysisBrowserSectionName | str] = Field(default_factory=list)
    """Section names for ``get_url_analysis_browser_section()``."""


class UrlAnalysisIntelDetection(BaseModel):
    """One threat-intelligence hit recorded during analysis."""

    model_config = ConfigDict(populate_by_name=True)

    source: str
    """Source ID, for example ``malware_feed`` (a malware URL feed) or ``phishing_feed``.
    New source IDs can appear."""
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
    """Place in the workspace session queue. Set only while ``state`` is ``queued`` and
    ``queue_reason`` is ``workspace_queue``."""
    queue_reason: UrlAnalysisSessionQueueReason | None = Field(default=None, alias="queueReason")
    """Why a ``queued`` session waits: ``workspace_queue`` (the workspace is at its
    concurrent-session capacity) or ``cluster_capacity`` (the cluster has no room for the
    browser yet). ``None`` in every other state, and on older servers."""
    vnc_available: bool = Field(alias="vncAvailable")
    report_available: bool = Field(alias="reportAvailable")
    started_at: int | None = Field(default=None, alias="startedAt")
    recording_started_at: int | None = Field(default=None, alias="recordingStartedAt")
    """Unix milliseconds of the first frame of the session recording. Subtract it from an
    event time to find the video position of the event. ``None`` when no recording started
    and on older servers."""
    ready_at: int | None = Field(default=None, alias="readyAt")
    expires_at: int | None = Field(default=None, alias="expiresAt")
    finished_at: int | None = Field(default=None, alias="finishedAt")
    failure_code: str | None = Field(default=None, alias="failureCode")
    extensions_used: int = Field(default=0, alias="extensionsUsed")
    extensions_max: int = Field(default=0, alias="extensionsMax")
    stop_requested_at: int | None = Field(default=None, alias="stopRequestedAt")
    """Unix milliseconds when the session was stopped early with
    ``stop_url_analysis_session()``. ``None`` while the session runs to its deadline, and on
    older servers."""
    session_config: UrlAnalysisSessionConfig | None = Field(default=None, alias="sessionConfig")
    link: str | None = None
    expired: bool


class UrlAnalysisSessionStop(BaseModel):
    """Result of a request to stop the interactive browser session now."""

    model_config = ConfigDict(populate_by_name=True)

    message: str
    expires_at: int = Field(alias="expiresAt")
    """Unix milliseconds of the session deadline after the request. Equal to the request time
    when the stop was applied."""
    already_ending: bool = Field(alias="alreadyEnding")
    """``True`` when the session was already ending (natural expiry, finalizing, or an earlier
    stop request), so the call changed nothing."""


class UrlAnalysisResponse(BaseModel):
    """Full URL analysis report payload."""

    model_config = ConfigDict(populate_by_name=True)

    level: ThreatLevel
    status: ReportStatusValue
    job_id: str | None = Field(
        default=None,
        alias="jobId",
        deprecated="job_id is removed from the API in its next release.",
    )
    """Deprecated: removed from the API in its next release."""
    general_info: UrlAnalysisGeneralInfo = Field(alias="generalInfo")
    screenshot: UrlAnalysisScreenshot
    ip_info: UrlAnalysisIpInfo | None = Field(default=None, alias="ipInfo")
    dns_records: list[UrlAnalysisDnsRecord] = Field(alias="dnsRecords")
    whois: UrlAnalysisWhoisInfo | None = None
    ssl_certificate: UrlAnalysisSslCertificate | None = Field(default=None, alias="sslCertificate")
    # Free-form: header names are not normalised by the API.
    response_headers: dict[str, Any] | None = Field(default=None, alias="responseHeaders")
    extracted_file: UrlAnalysisExtractedFile | None = Field(
        default=None,
        alias="extractedFile",
        deprecated=(
            "extracted_file is removed from the API in its next release. Read downloaded_files."
        ),
    )
    """Deprecated: never populated; always None. Use downloaded_files."""
    downloaded_files: list[UrlAnalysisDownloadedFile] = Field(
        default_factory=list, alias="downloadedFiles"
    )
    """Files that the browser downloaded. Empty when it downloaded nothing and on older
    servers."""
    threat_analysis: UrlAnalysisThreatAnalysis | None = Field(default=None, alias="threatAnalysis")
    pages: list[str]
    threat_score: float | None = Field(default=None, alias="threatScore")
    score_state: UrlAnalysisScoreState | None = Field(default=None, alias="scoreState")
    """``scored``, ``failed`` (scoring ran and failed) or ``not_scored``. ``None`` on older
    servers."""
    risk_level: str | None = Field(default=None, alias="riskLevel")
    privacy_score: float | None = Field(default=None, alias="privacyScore")
    privacy_risk_level: str | None = Field(default=None, alias="privacyRiskLevel")
    privacy_breakdown: list[UrlAnalysisPrivacyFactor] | None = Field(
        default=None, alias="privacyBreakdown"
    )
    privacy_unavailable_reason: UrlAnalysisPrivacyUnavailableReason | None = Field(
        default=None, alias="privacyUnavailableReason"
    )
    """Why ``privacy_score`` is ``None``: ``collection_failed``, ``no_network`` or
    ``page_not_loaded``. ``None`` when a score exists and on older reports and servers."""
    privacy_provisional: bool | None = Field(default=None, alias="privacyProvisional")
    """``True`` when the browser collection was partial, so ``privacy_score`` can change on a
    complete capture. ``None`` on older servers."""
    privacy_context: UrlAnalysisPrivacyContext | None = Field(default=None, alias="privacyContext")
    """``None`` when no privacy score was measured and on older reports and servers."""
    verdict_provenance: UrlAnalysisVerdictProvenance | None = Field(
        default=None,
        alias="verdictProvenance",
        deprecated="verdict_provenance is removed from the API in its next release.",
    )
    """Deprecated: removed from the API in its next release."""
    impersonation_target: UrlAnalysisImpersonationTarget | None = Field(
        default=None, alias="impersonationTarget"
    )
    completeness: UrlAnalysisCompleteness | None = None
    browser_snapshot: UrlAnalysisBrowserSnapshot | None = Field(
        default=None, alias="browserSnapshot"
    )
    """``None`` when the current run has no browser snapshot and on older servers."""
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
    label: str | None = None
    """Short display label of the evidence. ``None`` on older explanations and servers."""


class UrlScoreEvidenceFact(BaseModel):
    """One fact that explains a score indicator.

    ``label`` is display text and can change. ``kind`` is ``observed`` (the analysis saw it)
    or ``would_confirm`` (a check that would confirm the indicator).
    """

    model_config = ConfigDict(populate_by_name=True)

    kind: UrlScoreEvidenceFactKind
    label: str
    value: str
    ref: UrlScoreEvidenceRef | None = None
    """Evidence reference of the fact. When ``ref.id`` is also in
    ``UrlScoreIndicator.evidence_refs``, read it with
    ``get_url_analysis_indicator_evidence()``. ``None`` when the fact has no stored evidence."""


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
    original_rule_score: float | None = Field(
        default=None,
        alias="originalRuleScore",
        deprecated="original_rule_score is removed from the API in its next release.",
    )
    """Deprecated: removed from the API in its next release."""
    weighted_points: float | None = Field(
        default=None,
        alias="weightedPoints",
        deprecated="weighted_points is removed from the API in its next release.",
    )
    """Deprecated: removed from the API in its next release."""
    disposition: UrlScoreIndicatorDisposition
    level: UrlScoreIndicatorLevel | None = None
    """``malicious`` or ``suspicious`` when the rule matched, ``benign`` when it was measured
    with no match. ``None`` when the rule was not measured or was unavailable, and on older
    explanations and servers."""
    suppressed_by: str | None = Field(
        default=None,
        alias="suppressedBy",
        deprecated="suppressed_by is removed from the API in its next release.",
    )
    """Deprecated: removed from the API in its next release."""
    artifact_ids: list[str] | None = Field(default=None, alias="artifactIds")
    """Artifact IDs of the downloaded files that the indicator is about. ``None`` on older
    explanations and servers."""
    checked_url: str | None = Field(default=None, alias="checkedUrl")
    """The URL that the indicator checked. Set from explanation schema version 2."""
    evidence_refs: list[UrlScoreEvidenceRef] = Field(default_factory=list, alias="evidenceRefs")
    evidence: list[UrlScoreEvidenceFact] | None = None
    """Facts that explain the indicator (8 or fewer). ``None`` on explanations written before
    this field and on older servers. An empty list means the indicator has no facts."""
    evidence_total: int | None = Field(default=None, alias="evidenceTotal")
    """Number of facts before the cut to 8. ``None`` when ``evidence`` is ``None``."""


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
    band_adjustment: float | None = Field(default=None, alias="bandAdjustment")
    """Points that moved the shown score into the band of the final verdict. ``None`` on
    older explanations and servers."""
    exempt_points: float | None = Field(default=None, alias="exemptPoints")
    """Points that reputation credits never reduce, such as a high-confidence malicious
    download. ``None`` on older explanations and servers."""


class UrlScoreVerdictAdjustment(BaseModel):
    """A rule that changed the URL verdict after scoring."""

    model_config = ConfigDict(populate_by_name=True)

    rule_id: str = Field(alias="ruleId")
    """``quorum``, ``impersonation``, ``allowlist``, ``collection_failure`` or
    ``captcha_gate``. ``captcha_gate`` sets the verdict to ``unknown`` when a CAPTCHA stops
    the analysis and no measured indicator is suspicious or malicious. New rule IDs can appear."""
    from_: UrlScoreVerdict = Field(alias="from")
    to: UrlScoreVerdict
    reason: str


class UrlScoreExplanation(BaseModel):
    """Stored explanation of the URL threat score of one scoring pass."""

    model_config = ConfigDict(populate_by_name=True)

    schema_version: int | None = Field(
        default=None,
        alias="schemaVersion",
        deprecated="schema_version is removed from the API in its next release.",
    )
    """Deprecated: removed from the API in its next release."""
    scoring_version: str | None = Field(
        default=None,
        alias="scoringVersion",
        deprecated="scoring_version is removed from the API in its next release.",
    )
    """Deprecated: removed from the API in its next release."""
    job_id: str = Field(alias="jobId")
    """``get_url_analysis_indicator_evidence()`` sends it to the evidence route."""
    pass_: UrlScorePass | None = Field(
        default=None,
        alias="pass",
        deprecated="pass_ is removed from the API in its next release.",
    )
    """Deprecated: removed from the API in its next release."""
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
