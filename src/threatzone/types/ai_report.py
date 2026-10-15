"""AI analyst report type definitions.

Mirrors the `ai-report.response.dto.ts` DTO in the Threat.Zone Public API.
The AI report is advisory: the AI verdict never changes the submission
``score`` or ``level``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AiVerdict = Literal["malicious", "suspicious", "benign", "inconclusive"] | str
AiConfidence = Literal["high", "medium", "low"] | str
AiReportStatus = Literal["completed", "stale", "failed", "skipped_quota", "in_progress"] | str
AiReportPendingStatus = Literal["in_progress", "waiting_for_analysis", "queued"] | str
AiReportProgressStage = Literal["collecting", "screenshots", "writing"] | str
AiFamilyStatus = Literal["confirmed", "proposed", "none"] | str
AiIocStatus = Literal["confirmed", "likely", "noise", "ai_proposed"] | str
AiTechniqueOrigin = Literal["engine", "ai_proposed"] | str
AiFlowNodeKind = Literal["process", "file", "registry", "network", "screenshot", "indicator"] | str
AiKillChainPhase = (
    Literal[
        "delivery",
        "execution",
        "persistence",
        "defense_evasion",
        "credential_access",
        "c2",
        "exfiltration",
        "impact",
        "other",
    ]
    | str
)
AiScreenshotKind = (
    Literal[
        "ransom_note",
        "fake_login",
        "installer",
        "error_dialog",
        "blank",
        "document",
        "other",
    ]
    | str
)
AiRecommendationKind = Literal["containment", "detection", "hunting"] | str
AiIocKind = Literal["domain", "ip", "url", "hash", "email", "other"] | str
AiIocVerdict = Literal["valid", "invalid", "benign", "unverified"] | str
AiIocDecider = Literal["rule", "model"] | str
AiEvidenceSource = (
    Literal[
        "submission",
        "overview_indicator",
        "ioc",
        "yara",
        "config",
        "signature",
        "eml",
        "static",
        "strings",
        "process",
        "dropped_file",
        "memdump",
        "network_dns",
        "network_http",
        "network_tcp",
        "network_udp",
        "network_threat",
        "syscall",
        "dynamic_indicator",
        "screenshot",
        "url_finding",
        "url_redirect",
        "url_intel",
        "analysis_cut_short",
    ]
    | str
)


class AiReportEvidence(BaseModel):
    """Engine evidence that supports one AI statement."""

    model_config = ConfigDict(populate_by_name=True)

    source: AiEvidenceSource | None = None
    ref: str | None = None
    label: str | None = None


class AiReportSummary(BaseModel):
    """Executive summary of the AI report."""

    model_config = ConfigDict(populate_by_name=True)

    verdict: AiVerdict | None = None
    confidence: AiConfidence | None = None
    text: str | None = None
    engine_verdict: str | None = Field(default=None, alias="engineVerdict")
    agrees_with_engine: bool | None = Field(default=None, alias="agreesWithEngine")
    disagreement_reason: str | None = Field(default=None, alias="disagreementReason")


class AiReportFamily(BaseModel):
    """Malware family that the AI report names."""

    model_config = ConfigDict(populate_by_name=True)

    name: str | None = None
    status: AiFamilyStatus | None = None
    evidence: list[AiReportEvidence] | None = None


class AiReportClassification(BaseModel):
    """Family, threat category, and impersonated brand."""

    model_config = ConfigDict(populate_by_name=True)

    family: AiReportFamily | None = None
    category: str | None = None
    impersonated_brand: str | None = Field(default=None, alias="impersonatedBrand")


class AiReportIoc(BaseModel):
    """An IoC with the AI status and reason."""

    model_config = ConfigDict(populate_by_name=True)

    value: str | None = None
    kind: str | None = None
    status: AiIocStatus | None = None
    reason: str | None = None
    evidence: list[AiReportEvidence] | None = None


class AiReportTechnique(BaseModel):
    """A MITRE ATT&CK technique with its origin."""

    model_config = ConfigDict(populate_by_name=True)

    id: str | None = None
    name: str | None = None
    tactic: str | None = None
    origin: AiTechniqueOrigin | None = None
    confidence: AiConfidence | None = None
    evidence: list[AiReportEvidence] | None = None


class AiReportFlowNode(BaseModel):
    """A node of the attack flow graph."""

    model_config = ConfigDict(populate_by_name=True)

    id: str | None = None
    kind: AiFlowNodeKind | None = None
    label: str | None = None
    phase: AiKillChainPhase | None = None
    evidence: AiReportEvidence | None = None


class AiReportFlowEdge(BaseModel):
    """An edge of the attack flow graph. ``from_`` is the ``from`` key."""

    model_config = ConfigDict(populate_by_name=True)

    from_: str | None = Field(default=None, alias="from")
    to: str | None = None
    label: str | None = None


class AiReportAttackFlow(BaseModel):
    """Attack flow graph of the AI report."""

    model_config = ConfigDict(populate_by_name=True)

    nodes: list[AiReportFlowNode] | None = None
    edges: list[AiReportFlowEdge] | None = None


class AiReportNarrative(BaseModel):
    """One kill chain phase of the AI narrative."""

    model_config = ConfigDict(populate_by_name=True)

    phase: AiKillChainPhase | None = None
    text: str | None = None
    evidence: list[AiReportEvidence] | None = None


class AiReportScreenshot(BaseModel):
    """AI observation of one screenshot."""

    model_config = ConfigDict(populate_by_name=True)

    ordinal: int | None = None
    observation: str | None = None
    kind: AiScreenshotKind | None = None
    threat_relevant: bool | None = Field(default=None, alias="threatRelevant")


class AiReportEngineAgreement(BaseModel):
    """Agreement of the AI verdict with one engine."""

    model_config = ConfigDict(populate_by_name=True)

    engine: str | None = None
    reported: str | None = None
    agrees: bool | None = None
    note: str | None = None


class AiReportRecommendation(BaseModel):
    """A recommended analyst action."""

    model_config = ConfigDict(populate_by_name=True)

    kind: AiRecommendationKind | None = None
    text: str | None = None


class AiReportIocCandidate(BaseModel):
    """One IoC engine value and the curation decision."""

    model_config = ConfigDict(populate_by_name=True)

    value: str | None = None
    kind: AiIocKind | None = None
    verdict: AiIocVerdict | None = None
    decided_by: AiIocDecider | None = Field(default=None, alias="decidedBy")
    rule_id: str | None = Field(default=None, alias="ruleId")
    reason: str | None = None
    evidence: list[AiReportEvidence] | None = None


class AiReportIocReviewSummary(BaseModel):
    """Counts of the IoC curation."""

    model_config = ConfigDict(populate_by_name=True)

    total: int | None = None
    valid: int | None = None
    invalid: int | None = None
    benign: int | None = None
    unverified: int | None = None
    reviewed_by_model: int | None = Field(default=None, alias="reviewedByModel")
    truncated: bool | None = None


class AiReportIocReview(BaseModel):
    """IoC curation of every value that the IoC engine extracted.

    The curated list is every candidate with ``verdict == "valid"``.
    """

    model_config = ConfigDict(populate_by_name=True)

    candidates: list[AiReportIocCandidate] | None = None
    summary: AiReportIocReviewSummary | None = None


class AiReportContent(BaseModel):
    """Structured content of a completed or stale AI report."""

    model_config = ConfigDict(populate_by_name=True)

    summary: AiReportSummary | None = None
    classification: AiReportClassification | None = None
    iocs: list[AiReportIoc] | None = None
    techniques: list[AiReportTechnique] | None = None
    attack_flow: AiReportAttackFlow | None = Field(default=None, alias="attackFlow")
    narrative: list[AiReportNarrative] | None = None
    screenshots: list[AiReportScreenshot] | None = None
    engine_agreement: list[AiReportEngineAgreement] | None = Field(
        default=None, alias="engineAgreement"
    )
    recommendations: list[AiReportRecommendation] | None = None
    ioc_review: AiReportIocReview | None = Field(default=None, alias="iocReview")


class AiReport(BaseModel):
    """AI analyst report of a submission (HTTP 200).

    ``report``, ``verdict``, ``confidence``, ``agrees_with_engine``, ``family``,
    and ``family_status`` are set only when ``status`` is ``completed`` or
    ``stale``.
    """

    model_config = ConfigDict(populate_by_name=True)

    status: AiReportStatus
    job_id: str | None = Field(default=None, alias="jobId")
    verdict: AiVerdict | None = None
    confidence: AiConfidence | None = None
    agrees_with_engine: bool | None = Field(default=None, alias="agreesWithEngine")
    family: str | None = None
    family_status: AiFamilyStatus | None = Field(default=None, alias="familyStatus")
    report: AiReportContent | None = None
    updated_at: datetime | None = Field(default=None, alias="updatedAt")


class AiReportPending(BaseModel):
    """AI report that is not ready yet (HTTP 202).

    ``status`` is ``waiting_for_analysis``, ``queued``, or ``in_progress``.
    ``job_id`` and ``stage`` are set only for ``in_progress``. Poll again later.
    """

    model_config = ConfigDict(populate_by_name=True)

    status: AiReportPendingStatus
    job_id: str | None = Field(default=None, alias="jobId")
    stage: AiReportProgressStage | None = None
