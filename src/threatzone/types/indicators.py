"""Indicator surface type definitions.

Mirrors the `indicators.response.dto.ts` DTO in the Threat.Zone Public API.
Covers: indicators, IoCs, YARA rules, extracted configs, artifacts, artifact jobs, and the
overview /summary endpoint.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .network import NetworkAvailability, NetworkSourceScope

IndicatorLevel = Literal["malicious", "suspicious", "benign"]
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
    signal_id: str = Field(alias="signalId")
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


class Indicator(BaseModel):
    """A behavioural indicator emitted by the dynamic report."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    description: str
    summary: str | None = None
    why_matched: str | None = Field(default=None, alias="whyMatched")
    in_verdict_chain: bool | None = Field(default=None, alias="inVerdictChain")
    category: list[str]
    level: IndicatorLevel
    score: float
    score_maximum: int | None = Field(default=None, alias="scoreMaximum")
    pids: list[int]
    attack_codes: list[str] = Field(alias="attackCodes")
    event_ids: list[int] = Field(alias="eventIds")
    syscall_line_numbers: list[int] = Field(alias="syscallLineNumbers")
    author: IndicatorAuthor
    pid_gens: list[int] | None = Field(default=None, alias="pidGens")
    """PID generation of each entry in ``pids``, in the same order."""
    rule_source: str | None = Field(default=None, alias="ruleSource")
    what_happened: str | None = Field(default=None, alias="whatHappened")
    why_it_matters: str | None = Field(default=None, alias="whyItMatters")
    why_this_tier: str | None = Field(default=None, alias="whyThisTier")
    not_observed: list[str] | None = Field(default=None, alias="notObserved")
    outcome: str | None = None
    score_note: str | None = Field(default=None, alias="scoreNote")
    """Score note as stored. The text can change; read the ``score_*`` fields for machine use."""
    score_factors: list[str] | None = Field(default=None, alias="scoreFactors")
    score_result: float | None = Field(default=None, alias="scoreResult")
    score_cap: float | None = Field(default=None, alias="scoreCap")
    related: list[IndicatorRelated] | None = None
    actor: IndicatorActor | None = None
    target: IndicatorTarget | None = None
    t_offset_s: float | None = Field(default=None, alias="tOffsetS")
    span_s: float | None = Field(default=None, alias="spanS")
    occurrences: int | None = None
    finding_source: str | None = Field(default=None, alias="findingSource")
    """Analysis job that produced an overview row (a row with an empty ``id``)."""
    artifacts: list[str] | None = None
    dynamic_indicator_id: str | None = Field(default=None, alias="dynamicIndicatorId")


class IndicatorsResponse(BaseModel):
    """Paginated indicator list with severity rollup."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[Indicator]
    total: int
    page: int
    limit: int
    total_pages: int = Field(alias="totalPages")
    levels: IndicatorLevels


IoCType = Literal[
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


class IoC(BaseModel):
    """An Indicator of Compromise extracted from analysis artifacts."""

    model_config = ConfigDict(populate_by_name=True)

    type: IoCType
    value: str
    artifacts: list[str]
    raw_type: str | None = Field(default=None, alias="rawType")
    """Type text as the extractor stored it, before the API maps it to ``type``."""


class IoCsResponse(BaseModel):
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


class YaraRulesResponse(BaseModel):
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


class ExtractedConfigsResponse(BaseModel):
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
        default=None, alias="processAttribution"
    )
    analysis_status: ArtifactAnalysisStatus | None = Field(default=None, alias="analysisStatus")
    analysis_trigger: ArtifactAnalysisTrigger | None = Field(default=None, alias="analysisTrigger")
    analysis_reason: str | None = Field(default=None, alias="analysisReason")
    download_link: str | None = Field(default=None, alias="downloadLink")
    """Path of the artifact download route. The route needs the ``downloadSample`` permission."""


class ArtifactsResponse(BaseModel):
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


class OverviewSummary(BaseModel):
    """Aggregated counts for the submission overview /summary endpoint."""

    model_config = ConfigDict(populate_by_name=True)

    score: float | None = None
    family: str | None = None
    indicators: SummaryIndicators
    behavior_event_count: int = Field(alias="behaviorEventCount")
    syscall_count: int = Field(alias="syscallCount")
    ioc_count: int = Field(alias="iocCount")
    yara_rule_count: int = Field(alias="yaraRuleCount")
    config_count: int = Field(alias="configCount")
    artifact_count: int = Field(alias="artifactCount")
    mitre_technique_count: int = Field(alias="mitreTechniqueCount")
    network: SummaryNetwork | None = None
