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
TagOrigin = (
    Literal[
        "dynamic",
        "network",
        "static",
        "yara",
        "config_extractor",
        "signature",
        "email",
        "url",
        "import",
    ]
    | str
)
TagAuthor = Literal["system", "user"] | str
MetafieldValue = bool | int | float | str
"""A stored analysis option value with its type."""


class Message(BaseModel):
    """A one-line acknowledgement returned by an action endpoint."""

    model_config = ConfigDict(populate_by_name=True)

    message: str


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


class FileHistory(BaseModel):
    """Other file names of the same sample (same SHA256) on the platform."""

    model_config = ConfigDict(populate_by_name=True)

    filenames: list[str]
    """Every file name of the sample, newest first, without duplicates.

    The list includes names from other workspaces, the same as the web UI.
    """
    last_received_at: int = Field(alias="lastReceivedAt")
    """Unix time in milliseconds of the latest other submission of the sample."""


class FileInfo(BaseModel):
    """File metadata for a submission."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    size: int
    extension: str
    mimetype: str
    is_mimetype_checked: bool = Field(alias="isMimetypeChecked")
    declared_extension: str | None = Field(default=None, alias="declaredExtension")
    real_extension: str | None = Field(default=None, alias="realExtension")
    is_mimetype_mismatched: bool | None = Field(default=None, alias="isMimetypeMismatched")
    entrypoint: FileEntrypoint | None = None
    source: FileSource
    history: FileHistory | None = None
    """Other names of the same sample. Only ``get_submission()`` sends it.

    ``None`` when the sample has one file name, when the server cannot read the
    sample index, and on older servers.
    """


class Tag(BaseModel):
    """Submission tag."""

    model_config = ConfigDict(populate_by_name=True)

    type: str
    value: str
    origin: TagOrigin | None = None
    author: TagAuthor | None = None
    """``system`` for an analysis engine, ``user`` for a workspace member.

    ``None`` on older servers.
    """


class ReportOperatingSystem(BaseModel):
    """Operating system the dynamic report ran on."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    platform: OperatingSystemPlatform | str


class ReportStatus(BaseModel):
    """Status of an analysis report."""

    model_config = ConfigDict(populate_by_name=True)

    type: ReportType
    status: ReportStatusValue
    level: ThreatLevel | None = None
    score: float | None = None
    duration: float | None = None
    format: str | None = None
    operating_system: ReportOperatingSystem | None = Field(default=None, alias="operatingSystem")
    metafields: dict[str, str] | None = None
    """Analysis options of the report, as the web UI shows them.

    The key is the option name and the value is the selected parameter name.
    Only ``get_submission()`` sends it. ``None`` when the report has no options
    and on older servers. This is display text; read ``metafield_values`` in code.
    """
    metafield_values: dict[str, MetafieldValue] | None = Field(
        default=None, alias="metafieldValues"
    )
    """Stored analysis option values with their types, keyed by the metafield key, for
    example ``{"timeout": 120, "internet_connection": True}``. Only ``get_submission()``
    sends it. ``None`` when the report has no options and on older servers."""
    execution_duration_seconds: float | None = Field(default=None, alias="executionDurationSeconds")
    """The ``timeout`` option of a dynamic report in seconds. Only ``get_submission()``
    sends it. ``None`` for other reports and on older servers."""
