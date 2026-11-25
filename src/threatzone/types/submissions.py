"""Submission type definitions."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .common import (
    FileInfo,
    Hashes,
    ListEnvelopeFields,
    ReportStatus,
    ReportStatusValue,
    Tag,
    ThreatLevel,
)
from .verdict import DynamicVerdictBrief

SubmissionLevel = ThreatLevel
SubmissionType = Literal["file", "url"]
SubmissionReportStatus = ReportStatusValue
SubmissionSearchScope = Literal["workspace", "public"]
"""Rows that ``search_by_sha256()`` reads: ``workspace`` (the default) or ``public``."""
ScoreLayer = (
    Literal[
        "indicator_mean",
        "dynamic_verdict",
        "config_floor",
        "url_analysis",
        "submission_level",
        "none",
    ]
    | str
)

DynamicSkippedReason = Literal["no_environment_in_plan"] | str
"""Why the dynamic analysis did not run. A newer server can send another value."""
DynamicSkippedPlatform = Literal["linux", "android", "macos", "windows"] | str
DynamicSkippedArchitecture = Literal["x64", "arm64"] | str


class DynamicSkipped(BaseModel):
    """A sandbox submission that was accepted for static analysis only."""

    model_config = ConfigDict(populate_by_name=True)

    reason: DynamicSkippedReason
    """``no_environment_in_plan``: no sandbox environment of the plan can run the sample."""
    platform: DynamicSkippedPlatform
    """The platform the sample needs a sandbox environment of."""
    architecture: DynamicSkippedArchitecture | None = None
    """The only CPU architecture the sample runs on, for a thin Mach-O binary built for one
    CPU. ``None`` when the sample runs on either architecture."""


class SubmissionCreated(BaseModel):
    """Response from creating a new submission."""

    model_config = ConfigDict(populate_by_name=True)

    uuid: str
    message: str
    sha256: str | None = None
    dynamic_skipped: DynamicSkipped | None = Field(default=None, alias="dynamicSkipped")
    """Set when a sandbox submission was accepted for static analysis only, because no
    environment of the plan can run the sample. ``None`` when the dynamic analysis runs, for
    the other submission kinds and on older servers."""


class UrlDownloadSubmission(SubmissionCreated):
    """Response of ``create_url_download_submission()``: the new submission and the
    fetched file."""

    model_config = ConfigDict(populate_by_name=True)

    sha256: str
    filename: str
    """Filename from ``Content-Disposition``, else the last URL path segment, else the
    first 16 characters of the sha256."""
    detected_type: str | None = Field(default=None, alias="detectedType")
    """Content-detected file extension. ``None`` when detection found none."""
    mimetype: str
    """Content-detected MIME type."""
    size: int
    """Size of the fetched file in bytes."""
    final_url: str = Field(alias="finalUrl")
    """URL after the redirects."""
    tls_error: str | None = Field(default=None, alias="tlsError")
    """Certificate error code of the first TLS hop that failed verification, for example
    ``CERT_HAS_EXPIRED``. ``None`` when every TLS hop verified."""


class SubmissionOverviewJobs(BaseModel):
    """Aggregated analysis job progress."""

    model_config = ConfigDict(populate_by_name=True)

    total: int
    succeeded: int
    failed: int
    skipped: int
    finished: int
    completed: int = Field(
        default=0,
        deprecated="completed is removed from the API in its next release. Read finished.",
    )
    """Deprecated: read ``finished``. Always equal to ``finished``: the value is set from
    ``finished`` after validation, whatever ``completed`` the server sends. Removed from the
    API in its next release.
    """

    @model_validator(mode="after")
    def _mirror_completed_to_finished(self) -> SubmissionOverviewJobs:
        self.completed = self.finished
        return self


class SubmissionOverview(BaseModel):
    """Overall submission analysis status."""

    model_config = ConfigDict(populate_by_name=True)

    status: SubmissionReportStatus
    jobs: SubmissionOverviewJobs | None = None
    duration: float | None = None
    """Longest report run time in seconds (the largest ``reports[].duration``).

    Only ``get_submission()`` sends it. ``None`` when no report has finished and
    on older servers.
    """


class SubmissionIndicatorLevels(BaseModel):
    """Indicator counts grouped by severity."""

    model_config = ConfigDict(populate_by_name=True)

    malicious: int
    suspicious: int
    benign: int


class SubmissionIndicatorsRollup(BaseModel):
    """Indicator rollup attached to submission list/detail responses."""

    model_config = ConfigDict(populate_by_name=True)

    levels: SubmissionIndicatorLevels
    artifact_count: int = Field(alias="artifactCount")


class SubmissionListItem(BaseModel):
    """A submission in a list response."""

    model_config = ConfigDict(populate_by_name=True)

    uuid: str
    filename: str | None = None
    """``None`` for a URL submission."""
    sha256: str | None = None
    """``None`` for a URL submission."""
    url: str | None = None
    """Submitted URL of a URL submission. For a file submission, the URL that the server
    fetched the file from (without its username and password). ``None`` for an upload and
    on older servers."""
    source_url: str | None = Field(default=None, alias="sourceUrl")
    """URL that the server fetched the file from. Only the deprecated v2 list sends it, so
    it is ``None`` on the v1 list that the SDK reads. Read ``url`` instead."""
    level: SubmissionLevel
    type: SubmissionType
    private: bool
    tags: list[Tag]
    reports: list[ReportStatus]
    mimetype: str | None = None
    size: int | None = None
    overview: SubmissionOverview
    indicators: SubmissionIndicatorsRollup
    created_at: datetime = Field(alias="createdAt")


class PaginatedSubmissions(ListEnvelopeFields):
    """Paginated list of submissions."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[SubmissionListItem]
    total: int
    page: int
    limit: int
    total_pages: int = Field(alias="totalPages")


class ScoreContributor(BaseModel):
    """One finding with a large effect on the submission score."""

    model_config = ConfigDict(populate_by_name=True)

    source: str
    indicator_id: str | None = Field(default=None, alias="indicatorId")
    """``Indicator.id`` of the ``get_indicators()`` row of the finding, also for findings of
    other engines (YARA, signature check, configuration). ``None`` when no row stands for the
    finding, and for overview findings on servers before Threat.Zone v3.9.0."""
    title: str
    """Finding title. The text can change between releases; match on ``indicator_id``."""
    points: float
    level: ThreatLevel | str


class ScoreBreakdown(BaseModel):
    """Explanation of the submission score.

    ``contributors[].title`` and ``what_would_change`` are display text. The text
    can change between releases, so do not parse or match on it.
    """

    model_config = ConfigDict(populate_by_name=True)

    deciding_layer: ScoreLayer | None = Field(
        default=None,
        alias="decidingLayer",
        deprecated="deciding_layer is removed from the API in its next release.",
    )
    """Deprecated: removed from the API in its next release."""
    verdict: str
    score: float
    cap: float | None = None
    """Highest finding score in the indicator mean. Set only for ``indicator_mean``."""
    contributors: list[ScoreContributor] = Field(default_factory=list)
    """Findings with the largest effect on the score, largest effect first (at most ten)."""
    what_would_change: list[str] = Field(default_factory=list, alias="whatWouldChange")


class Submission(BaseModel):
    """Full submission details."""

    model_config = ConfigDict(populate_by_name=True)

    uuid: str
    type: SubmissionType
    filename: str | None = None
    url: str | None = None
    hashes: Hashes | None = None
    file: FileInfo | None = None
    level: SubmissionLevel
    score: float | None = None
    """Live threat score (0-100), the same value as the web UI shows.

    A pure URL submission returns ``None`` until the final URL verdict. ``None``
    also when no score is available.
    """
    family: str | None = None
    private: bool
    tags: list[Tag]
    reports: list[ReportStatus]
    overview: SubmissionOverview
    indicators: SubmissionIndicatorsRollup
    mitre_techniques: list[str] = Field(alias="mitreTechniques")
    created_at: datetime = Field(alias="createdAt")
    updated_at: datetime = Field(alias="updatedAt")
    score_breakdown: ScoreBreakdown | None = Field(default=None, alias="scoreBreakdown")
    """Explanation of ``score``. Only ``get_submission()`` sends it.

    ``None`` for a pure URL submission, before the overview exists, when the
    stored score does not come from the current score rule, and on older servers.
    """
    finalized: bool | None = None
    """``True`` after the platform stamps the final score. While ``False``, ``score`` and
    ``level`` can still change, and analysis jobs can still add indicators, IoCs and
    artifacts. The platform stamps only submissions updated in the last 24 hours, so an older
    submission can keep ``False``: poll with a timeout. Only ``get_submission()`` sends it;
    ``None`` on older servers."""
    dynamic_verdict: DynamicVerdictBrief | None = Field(default=None, alias="dynamicVerdict")
    """The verdict of the behaviour run alone, with its tier reason and run notes. ``level``
    and ``score`` keep their meaning as the submission verdict. Only ``get_submission()``
    sends it. ``None`` for a legacy report, until the run of the current analysis attempt is
    published, and on older servers."""
    dynamic_skipped: DynamicSkipped | None = Field(default=None, alias="dynamicSkipped")
    """Set when the sandbox submission was accepted for static analysis only. Only
    ``get_submission()`` sends it. ``None`` when the dynamic analysis ran or was never
    requested, and on older servers."""

    def is_complete(self) -> bool:
        """Check if all reports have completed."""
        terminal_statuses = {"completed", "error"}
        return all(r.status in terminal_statuses for r in self.reports)

    def has_errors(self) -> bool:
        """Check if any report has an error status."""
        return any(r.status == "error" for r in self.reports)
