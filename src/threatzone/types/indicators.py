"""Indicator surface type definitions.

Mirrors the `indicators.response.dto.ts` DTO in the Threat.Zone Public API.
Covers: indicators, IoCs, YARA rules, extracted configs, artifacts, artifact jobs, and the
overview /summary endpoint.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .common import ListEnvelopeFields
from .network import NetworkAvailability, NetworkSourceScope

IndicatorLevel = Literal["malicious", "suspicious", "benign"] | str
"""Indicator level. Any other string is also accepted, so a new server value does not fail
the parse."""
IndicatorAuthor = Literal["system", "user"]


class IndicatorLevels(BaseModel):
    """Indicator counts grouped by severity level."""

    model_config = ConfigDict(populate_by_name=True)

    malicious: int
    suspicious: int
    benign: int


class IndicatorRelatedActor(BaseModel):
    """Process that caused a related behaviour event."""

    model_config = ConfigDict(populate_by_name=True)

    image: str
    pid: int | None = None


class IndicatorRelated(BaseModel):
    """A behaviour event related to an indicator row."""

    model_config = ConfigDict(populate_by_name=True)

    event_id: int | None = Field(default=None, alias="eventId")
    """Behaviour event ID. ``None`` when the event has no behaviour event."""
    signal_id: str | None = Field(
        default=None,
        alias="signalId",
        deprecated="signal_id is removed from the API in its next release. Use event_id.",
    )
    """Deprecated: removed from the API in its next release. ``event_id`` is the key of the
    evidence. ``None`` when the server leaves it out."""
    text: str
    t_offset_s: float | None = Field(default=None, alias="tOffsetS")
    """Seconds from the sample start. ``None`` on rows stored before the time was recorded."""
    actor: IndicatorRelatedActor | None = None


class IndicatorActor(BaseModel):
    """Process that did the behaviour of an indicator row."""

    model_config = ConfigDict(populate_by_name=True)

    image: str
    pid: int | None = None
    pid_gen: int | None = Field(default=None, alias="pidGen")
    """PID generation. Use ``pid`` and ``pid_gen`` together to identify one process."""
    lineage: str | None = None


class IndicatorTarget(BaseModel):
    """Object that the behaviour of an indicator row acted on."""

    model_config = ConfigDict(populate_by_name=True)

    kind: str | None = None
    value: str | None = None


IndicatorUrlAnalysisConfidence = Literal["high", "heuristic"] | str


class IndicatorUrlAnalysis(BaseModel):
    """URL analysis fields of an indicator row."""

    model_config = ConfigDict(populate_by_name=True)

    indicator_id: str = Field(alias="indicatorId")
    """``UrlScoreIndicator.id`` of the row in ``get_url_analysis_indicators()``."""
    rule_id: str = Field(alias="ruleId")
    family: str | None = None
    checked_url: str | None = Field(default=None, alias="checkedUrl")
    """URL that the rule checked. ``None`` when the indicator applies to the whole
    analysis."""
    confidence: IndicatorUrlAnalysisConfidence
    evidence_paths: list[str] = Field(default_factory=list, alias="evidencePaths")
    """Path of the evidence route for each evidence reference, relative to the API base
    URL."""


class Indicator(BaseModel):
    """A behavioural indicator emitted by the dynamic report."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    source: str | None = None
    """Engine of the row: ``dynamic_scan`` for every dynamic row, else the engine of an overview
    row (for example ``static_scan`` or ``yara_scanner``). ``None`` when the row does not record
    one and on older servers."""
    name: str
    description: str
    summary: str | None = None
    why_matched: str | None = Field(default=None, alias="whyMatched")
    in_verdict_chain: bool | None = Field(default=None, alias="inVerdictChain")
    category: list[str]
    level: IndicatorLevel
    score: float
    score_maximum: int | None = Field(
        default=None,
        alias="scoreMaximum",
        deprecated="score_maximum is always 100 and is removed from the API in its next release.",
    )
    """Deprecated: every score is on the 0-100 scale, so the value is always ``100``. Removed
    from the API in its next release."""
    pids: list[int]
    attack_codes: list[str] = Field(alias="attackCodes")
    attempted_attack_codes: list[str] | None = Field(default=None, alias="attemptedAttackCodes")
    """Techniques of ``attack_codes`` that the row marks attempted: the evidence is a request
    that the sandbox did not confirm. ``None`` when the row has none and on older servers."""
    event_ids: list[int] = Field(alias="eventIds")
    syscall_line_numbers: list[int] = Field(alias="syscallLineNumbers")
    author: IndicatorAuthor | None = Field(
        default=None,
        deprecated="author is removed from the API in its next release.",
    )
    """Deprecated: ``system`` on every row. Removed from the API in its next release."""
    pid_gens: list[int] | None = Field(default=None, alias="pidGens")
    """PID generation of each entry in ``pids``, in the same order."""
    rule_source: str | None = Field(
        default=None,
        alias="ruleSource",
        deprecated="rule_source is removed from the API in its next release. Join rows by id.",
    )
    """Deprecated: removed from the API in its next release. Join rows by ``id``."""
    what_happened: str | None = Field(default=None, alias="whatHappened")
    why_it_matters: str | None = Field(default=None, alias="whyItMatters")
    why_this_tier: str | None = Field(default=None, alias="whyThisTier")
    not_observed: list[str] | None = Field(default=None, alias="notObserved")
    outcome: str | None = None
    score_note: str | None = Field(default=None, alias="scoreNote")
    """Score note as stored. The text can change; read the ``score_*`` fields for machine use."""
    score_factors: list[str] | None = Field(
        default=None,
        alias="scoreFactors",
        deprecated="score_factors is removed from the API in its next release. Read score.",
    )
    """Deprecated: removed from the API in its next release. Read ``score``."""
    score_result: float | None = Field(
        default=None,
        alias="scoreResult",
        deprecated="score_result is removed from the API in its next release. Read score.",
    )
    """Deprecated: removed from the API in its next release. Read ``score``."""
    score_cap: float | None = Field(
        default=None,
        alias="scoreCap",
        deprecated="score_cap is removed from the API in its next release. Read score.",
    )
    """Deprecated: removed from the API in its next release. Read ``score``."""
    related: list[IndicatorRelated] | None = None
    actor: IndicatorActor | None = None
    target: IndicatorTarget | None = None
    t_offset_s: float | None = Field(default=None, alias="tOffsetS")
    span_s: float | None = Field(default=None, alias="spanS")
    occurrences: int | None = None
    finding_source: str | None = Field(
        default=None,
        alias="findingSource",
        deprecated="finding_source is removed from the API in its next release. Read source.",
    )
    """Deprecated: removed from the API in its next release. Read ``source``."""
    artifacts: list[str] | None = None
    dynamic_indicator_id: str | None = Field(default=None, alias="dynamicIndicatorId")
    url_analysis: IndicatorUrlAnalysis | None = Field(default=None, alias="urlAnalysis")
    """Set only on URL analysis overview rows. ``None`` on every other row and on older
    servers."""


class IndicatorsResponse(ListEnvelopeFields):
    """Paginated indicator list with severity rollup."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[Indicator]
    total: int
    page: int
    limit: int
    total_pages: int = Field(alias="totalPages")
    levels: IndicatorLevels


IoCType = (
    Literal[
        "ip",
        "domain",
        "url",
        "email",
        "sha512",
        "sha256",
        "sha1",
        "md5",
        "registry",
        "path",
        "uuid",
    ]
    | str
)
"""IoC type. Any other string is also accepted, so a new server value does not fail the
parse."""

IoCTier = Literal["ioc", "strings"] | str
"""``ioc`` for an indicator. ``strings`` for a value that only strings found in the files of
the submission hold. A ``strings`` value is not counted as an IoC and is never exported."""

IoCTierFilter = Literal["ioc", "strings", "all"] | str
"""Tier filter of ``get_iocs()``. The server default is ``all``."""


class IoC(BaseModel):
    """An Indicator of Compromise extracted from analysis artifacts."""

    model_config = ConfigDict(populate_by_name=True)

    type: IoCType
    value: str
    artifacts: list[str]
    raw_type: str | None = Field(
        default=None,
        alias="rawType",
        deprecated="raw_type is removed from the API in its next release. Read type.",
    )
    """Deprecated: removed from the API in its next release. Read ``type``."""
    tier: IoCTier | None = None
    """``ioc`` or ``strings``. Every item is ``ioc`` while the platform keeps strings with the
    IoCs, or while the analysis is still running. ``None`` on older servers."""
    ports: list[int] | None = None
    """Ports an IP or domain IoC was contacted on. ``None`` when no port was recorded and on
    older servers."""


class IoCsResponse(ListEnvelopeFields):
    """Paginated IoC list."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[IoC]
    total: int
    page: int
    limit: int
    total_pages: int = Field(alias="totalPages")


YaraRuleCategory = Literal["malicious", "suspicious", "benign"]


class YaraRule(BaseModel):
    """A YARA rule that matched against the submission's artifacts."""

    model_config = ConfigDict(populate_by_name=True)

    rule: str
    category: YaraRuleCategory
    artifacts: list[str]


class YaraRulesResponse(ListEnvelopeFields):
    """Paginated YARA rule matches."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[YaraRule]
    total: int
    page: int
    limit: int
    total_pages: int = Field(alias="totalPages")


class ExtractedConfig(BaseModel):
    """An extracted malware family configuration."""

    model_config = ConfigDict(populate_by_name=True)

    family: str
    # Free-form: shape depends on the malware family.
    config: dict[str, Any]
    c2s: list[str]
    artifacts: list[str]


class ExtractedConfigsResponse(ListEnvelopeFields):
    """Paginated extracted configurations."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[ExtractedConfig]
    total: int


ArtifactType = (
    Literal[
        "sample",
        "compressed_file_entry",
        "malware_config",
        "memory_dump",
        "file_dump",
        "pcap",
        "deobfuscated_code",
        "process_dump",
        "unpacked_file",
        "yara_rule",
        "email_file",
        "email_attachment",
        "embedded_file",
        "unknown",
        "dropped_file",
        "downloaded_file",
        "screenshot",
    ]
    | str
)


ArtifactProcessAttribution = Literal["unknown"] | str

ArtifactSource = (
    Literal[
        "dynamic_report",
        "static_report",
        "url_report",
        "unpacker",
        "config_extractor",
        "yara_generator",
        "user_upload",
        "manual",
    ]
    | str
)

ArtifactAnalysisStatus = Literal["not_analyzed", "analyzing", "analyzed", "failed", "skipped"] | str

ArtifactAnalysisTrigger = Literal["auto", "manual"] | str


class ArtifactHashes(BaseModel):
    """Hash digests for an artifact."""

    model_config = ConfigDict(populate_by_name=True)

    md5: str
    sha1: str
    sha256: str


class Artifact(BaseModel):
    """An artifact extracted during analysis."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    filename: str
    size: int
    type: ArtifactType
    source: ArtifactSource
    hashes: ArtifactHashes
    tags: list[str]
    process_attribution: ArtifactProcessAttribution | None = Field(
        default=None,
        alias="processAttribution",
        deprecated="process_attribution is removed from the API in its next release.",
    )
    """Deprecated: removed from the API in its next release."""
    analysis_status: ArtifactAnalysisStatus | None = Field(default=None, alias="analysisStatus")
    analysis_trigger: ArtifactAnalysisTrigger | None = Field(default=None, alias="analysisTrigger")
    analysis_reason: str | None = Field(default=None, alias="analysisReason")
    download_link: str | None = Field(default=None, alias="downloadLink")
    """Path of the artifact download route. The route needs the ``downloadSample`` permission."""


class ArtifactsResponse(ListEnvelopeFields):
    """Paginated artifact list."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[Artifact]
    total: int


ArtifactJobEngineType = (
    Literal[
        "ioc_extractor",
        "yara_scanner",
        "config_extractor",
        "dynamic_scan",
        "static_scan",
        "signature_checker",
        "cdr",
        "eml_analyzer",
        "url_analysis",
    ]
    | str
)

ArtifactJobStatus = (
    Literal[
        "pending",
        "queued",
        "running",
        "waiting_callback",
        "success",
        "retrying",
        "failed",
        "skipped",
    ]
    | str
)

ArtifactJobErrorCode = Literal["JOB_FAILED", "JOB_DEAD_LETTERED", "JOB_SKIPPED"] | str


class ArtifactJob(BaseModel):
    """One engine analysis job of an artifact."""

    model_config = ConfigDict(populate_by_name=True)

    engine_type: ArtifactJobEngineType = Field(alias="engineType")
    status: ArtifactJobStatus
    error_code: ArtifactJobErrorCode | None = Field(default=None, alias="errorCode")
    """Fixed code for a failed or skipped job. The API never returns the platform error text."""


class SummaryIndicatorLevels(BaseModel):
    """Indicator counts grouped by severity (overview summary variant)."""

    model_config = ConfigDict(populate_by_name=True)

    malicious: int
    suspicious: int
    benign: int


class SummaryIndicators(BaseModel):
    """Indicator counts attached to the overview /summary response."""

    model_config = ConfigDict(populate_by_name=True)

    total: int
    levels: SummaryIndicatorLevels


class SummaryNetwork(BaseModel):
    """Network activity counts attached to the overview /summary response."""

    model_config = ConfigDict(populate_by_name=True)

    dns_count: int = Field(alias="dnsCount")
    http_count: int = Field(alias="httpCount")
    tcp_count: int = Field(alias="tcpCount")
    udp_count: int = Field(alias="udpCount")
    threat_count: int = Field(alias="threatCount")
    counts_available: bool | None = Field(default=None, alias="countsAvailable")
    availability: NetworkAvailability | None = None
    source_scope: NetworkSourceScope | None = Field(default=None, alias="sourceScope")
    exfil_request_count: int | None = Field(default=None, alias="exfilRequestCount")
    """Chat bot and webhook requests. ``None`` on older servers."""
    windows_background_count: int | None = Field(default=None, alias="windowsBackgroundCount")
    """Rows of known Windows background traffic, left out of the counts above. ``None`` on
    older servers."""
    host_app_background_count: int | None = Field(default=None, alias="hostAppBackgroundCount")
    """Rows of the application that opened the sample to its own known services, left out of
    the counts above. ``None`` on older servers."""


class OverviewSummary(BaseModel):
    """Aggregated counts for the submission overview /summary endpoint."""

    model_config = ConfigDict(populate_by_name=True)

    score: float | None = None
    family: str | None = None
    indicators: SummaryIndicators
    behavior_event_count: int = Field(alias="behaviorEventCount")
    behavior_event_count_available: bool | None = Field(
        default=None, alias="behaviorEventCountAvailable"
    )
    """``False`` when the behaviour index of the run is not built yet, so
    ``behavior_event_count`` is 0 and not a real count. A later request gives the count.
    ``None`` on older servers."""
    syscall_count: int = Field(alias="syscallCount")
    ioc_count: int = Field(alias="iocCount")
    yara_rule_count: int = Field(alias="yaraRuleCount")
    config_count: int = Field(alias="configCount")
    artifact_count: int = Field(alias="artifactCount")
    mitre_technique_count: int = Field(alias="mitreTechniqueCount")
    network: SummaryNetwork | None = None
