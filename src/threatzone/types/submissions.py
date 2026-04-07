"""Submission type definitions."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .common import FileInfo, Hashes, ReportStatus, ReportStatusValue, Tag, ThreatLevel

SubmissionLevel = ThreatLevel
SubmissionType = Literal["file", "url"]
SubmissionReportStatus = ReportStatusValue


class SubmissionCreated(BaseModel):
    """Response from creating a new submission."""

    model_config = ConfigDict(populate_by_name=True)

    uuid: str
    message: str
    sha256: str | None = None


class SubmissionOverviewJobs(BaseModel):
    """Aggregated analysis job progress."""

    model_config = ConfigDict(populate_by_name=True)

    completed: int
    total: int


class SubmissionOverview(BaseModel):
    """Overall submission analysis status."""

    model_config = ConfigDict(populate_by_name=True)

    status: SubmissionReportStatus
    jobs: SubmissionOverviewJobs | None = None


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
    private: bool
    tags: list[Tag]
    reports: list[ReportStatus]
    overview: SubmissionOverview
    indicators: SubmissionIndicatorsRollup
    mitre_techniques: list[str] = Field(alias="mitreTechniques")
    created_at: datetime = Field(alias="createdAt")
    updated_at: datetime = Field(alias="updatedAt")

    def is_complete(self) -> bool:
        """Check if all reports have completed."""
        terminal_statuses = {"completed", "error"}
        return all(r.status in terminal_statuses for r in self.reports)

    def has_errors(self) -> bool:
        """Check if any report has an error status."""
        return any(r.status == "error" for r in self.reports)
