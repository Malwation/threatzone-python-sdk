"""Submission type definitions."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .common import FileInfo, Hashes, ReportStatus, ReportStatusValue, Tag, ThreatLevel

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


class SubmissionCreated(BaseModel):
    """Response from creating a new submission."""

    model_config = ConfigDict(populate_by_name=True)

    uuid: str
    message: str
    sha256: str | None = None


class SubmissionOverviewJobs(BaseModel):
    """Aggregated analysis job progress."""

    model_config = ConfigDict(populate_by_name=True)

    total: int
    succeeded: int
    failed: int
    skipped: int
    finished: int
    completed: int = 0
    """Deprecated alias of ``finished`` (always equal).

    Kept for backward compatibility with integrations that read
    ``overview.jobs.completed``; new code should use ``finished``. The value is
    forced to mirror ``finished`` after validation regardless of any incoming
    ``completed`` value.
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
    sha256: str | None = None
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


class PaginatedSubmissions(BaseModel):
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
    """Dynamic indicator identifier. ``None`` for findings of other engines."""
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

    deciding_layer: ScoreLayer = Field(alias="decidingLayer")
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

    def is_complete(self) -> bool:
        """Check if all reports have completed."""
        terminal_statuses = {"completed", "error"}
        return all(r.status in terminal_statuses for r in self.reports)

    def has_errors(self) -> bool:
        """Check if any report has an error status."""
        return any(r.status == "error" for r in self.reports)
