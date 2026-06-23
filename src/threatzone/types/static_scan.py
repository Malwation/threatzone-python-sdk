"""Static scan type definitions.

Mirrors the `static-scan.response.dto.ts` DTO in the Threat.Zone Public API.

The `/static-scan` response is a per-format discriminated singleton (not an
items envelope). Common fields are always present; format-specific keys are
inlined at the top level and selected by ``reportFormat``, so the response
model preserves unknown keys (``extra="allow"``) — access them via
``.model_extra``.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class StaticScanFileInfo(BaseModel):
    """File identity and hash information for a static scan report."""

    model_config = ConfigDict(populate_by_name=True)

    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    ssdeep: str | None = None
    mime_type: str | None = None
    file_type: str | None = None
    entropy: float | None = None
    filesize: str | None = None


class StaticScanStrings(BaseModel):
    """Extracted strings summary for a static scan report."""

    model_config = ConfigDict(populate_by_name=True)

    total_count: int = Field(alias="totalCount")


class StaticScanDieResult(BaseModel):
    """A single DetectItEasy detection entry."""

    model_config = ConfigDict(populate_by_name=True)

    name: str | None = None
    string: str | None = None
    type: str | None = None
    version: str | None = None


class StaticScanResponse(BaseModel):
    """Per-submission static analysis report, discriminated by ``reportFormat``.

    ``extra="allow"`` preserves the inlined per-format keys (``peExeSections``,
    ``apkInfo``, ``elfHeader``, ...) which vary by ``reportFormat``; access them
    via ``.model_extra``. This mirrors the live DTO's ``additionalProperties:true``
    behavior for the format-specific sections.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    submission: str
    status: str
    report_format: str = Field(alias="reportFormat")
    level: str
    score: float
    file_info: StaticScanFileInfo | None = Field(default=None, alias="fileInfo")
    strings: StaticScanStrings | None = None
    die_results: list[StaticScanDieResult] = Field(default_factory=list, alias="dieResults")
    analysis_time: str | None = Field(default=None, alias="analysisTime")
    metafields: dict[str, object] | None = None
