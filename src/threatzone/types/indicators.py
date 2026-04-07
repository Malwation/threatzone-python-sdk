"""Indicator surface type definitions.

Mirrors the `indicators.response.dto.ts` DTO in the Threat.Zone Public API.
Covers: indicators, IoCs, YARA rules, extracted configs, artifacts, and the
overview /summary endpoint.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

IndicatorLevel = Literal["malicious", "suspicious", "benign"]
IndicatorAuthor = Literal["system", "user"]


class IndicatorLevels(BaseModel):
    """Indicator counts grouped by severity level."""

    model_config = ConfigDict(populate_by_name=True)

    malicious: int
    suspicious: int
    benign: int


class Indicator(BaseModel):
    """A behavioural indicator emitted by the dynamic report."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    description: str
    category: str
    level: IndicatorLevel
    score: int
    pids: list[int]
    attack_codes: list[str] = Field(alias="attackCodes")
    event_ids: list[int] = Field(alias="eventIds")
    syscall_line_numbers: list[int] = Field(alias="syscallLineNumbers")
    author: IndicatorAuthor


class IndicatorsResponse(BaseModel):
    """Paginated indicator list with severity rollup."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[Indicator]
    total: int
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


class IoCsResponse(BaseModel):
    """Paginated IoC list."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[IoC]
    total: int


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


ArtifactType = Literal[
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
    "unknown",
    "dropped_file",
    "downloaded_file",
    "screenshot",
]


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
    source: str
    hashes: ArtifactHashes
    tags: list[str]


class ArtifactsResponse(BaseModel):
    """Paginated artifact list."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[Artifact]
    total: int


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


class OverviewSummary(BaseModel):
    """Aggregated counts for the submission overview /summary endpoint."""

    model_config = ConfigDict(populate_by_name=True)

    indicators: SummaryIndicators
    behavior_event_count: int = Field(alias="behaviorEventCount")
    syscall_count: int = Field(alias="syscallCount")
    ioc_count: int = Field(alias="iocCount")
    yara_rule_count: int = Field(alias="yaraRuleCount")
    config_count: int = Field(alias="configCount")
    artifact_count: int = Field(alias="artifactCount")
    mitre_technique_count: int = Field(alias="mitreTechniqueCount")
    network: SummaryNetwork | None = None
