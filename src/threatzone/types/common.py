"""Common type definitions shared across the SDK."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ReportType = Literal["dynamic", "static", "cdr", "url_analysis", "open_in_browser"]
ReportStatusValue = Literal[
    "error", "not_started", "accepted", "in_progress", "clean_up", "completed"
]
ThreatLevel = Literal["unknown", "benign", "suspicious", "malicious"]
OperatingSystemPlatform = Literal["windows", "linux", "android", "macos"]


class Hashes(BaseModel):
    """File hash values."""

    model_config = ConfigDict(populate_by_name=True)

    md5: str
    sha1: str
    sha256: str


class FileEntrypoint(BaseModel):
    """Entrypoint metadata for archive submissions."""

    model_config = ConfigDict(populate_by_name=True)

    filename: str


class FileSource(BaseModel):
    """How a submitted file arrived at the platform."""

    model_config = ConfigDict(populate_by_name=True)

    type: Literal["upload", "url"]
    url: str | None = None


class FileInfo(BaseModel):
    """File metadata for a submission."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    size: int
    extension: str
    mimetype: str
    is_mimetype_checked: bool = Field(alias="isMimetypeChecked")
    entrypoint: FileEntrypoint | None = None
    source: FileSource


class Tag(BaseModel):
    """Submission tag."""

    model_config = ConfigDict(populate_by_name=True)

    type: str
    value: str


class ReportOperatingSystem(BaseModel):
    """Operating system the dynamic report ran on."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    platform: OperatingSystemPlatform


class ReportStatus(BaseModel):
    """Status of an analysis report."""

    model_config = ConfigDict(populate_by_name=True)

    type: ReportType
    status: ReportStatusValue
    level: ThreatLevel | None = None
    score: int | None = None
    format: str | None = None
    operating_system: ReportOperatingSystem | None = Field(default=None, alias="operatingSystem")
