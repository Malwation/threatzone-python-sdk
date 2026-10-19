"""Static scan type definitions.

Mirrors the `static-scan.response.dto.ts` DTO in the Threat.Zone Public API.

The `/static-scan` response is a per-format discriminated singleton (not an
items envelope). Common fields are always present; format-specific keys are
inlined at the top level and selected by ``reportFormat``, so the response
model preserves unknown keys (``extra="allow"``) — access them via
``.model_extra``.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

StringObservableKind = (
    Literal[
        "url",
        "domain",
        "ip",
        "email",
        "wallet",
        "bot-token",
        "webhook",
        "command",
        "registry",
        "path",
    ]
    | str
)


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
    real_filename: str | None = Field(default=None, alias="realFilename")
    real_sha256: str | None = Field(default=None, alias="realSha256")


class StaticScanOneNoteEmbeddedFile(BaseModel):
    """A file embedded inside a OneNote document (``oneNoteEmbeddedFiles[]``)."""

    model_config = ConfigDict(populate_by_name=True)

    name: str | None = None
    size: int | None = None
    type: str | None = None
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    artifact_id: str | None = Field(default=None, alias="artifactId")
    download_link: str | None = Field(default=None, alias="downloadLink")
    display_name: str | None = Field(default=None, alias="displayName")
    mime_type: str | None = Field(default=None, alias="mimeType")
    extension: str | None = None
    identity: str | None = None
    filesize: str | None = None
    entropy: float | None = None
    last_modified_time: str | None = Field(default=None, alias="lastModifiedTime")
    embedded_file_name: str | None = Field(default=None, alias="embeddedFileName")
    source_filepath: str | None = Field(default=None, alias="sourceFilepath")


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

    @property
    def one_note_embedded_files(self) -> list[StaticScanOneNoteEmbeddedFile] | None:
        """The typed ``oneNoteEmbeddedFiles`` entries of an ``onenote`` report.

        The raw list stays in ``.model_extra``. The value is None when the
        report has no ``oneNoteEmbeddedFiles`` key.
        """
        raw = (self.model_extra or {}).get("oneNoteEmbeddedFiles")
        if not isinstance(raw, list):
            return None
        return [StaticScanOneNoteEmbeddedFile.model_validate(item) for item in raw]


class StringObservable(BaseModel):
    """An observable found in the extracted strings.

    ``value``, ``display`` and ``source`` always contain the full text. The
    ``secret`` flag is a label for filters only; the SDK does not mask values.
    """

    model_config = ConfigDict(populate_by_name=True)

    kind: StringObservableKind
    value: str
    count: int
    display: str
    host: str | None = None
    detail: str | None = None
    source: str
    secret: bool


class StringFact(BaseModel):
    """A fact that groups extracted strings by purpose. The ``value`` label text can change."""

    model_config = ConfigDict(populate_by_name=True)

    code: str
    value: str
    capability: str | None = None
    matches: list[str] = Field(default_factory=list)
    count: int
    names: list[str] = Field(default_factory=list)


class StringFacts(BaseModel):
    """Response of ``GET /submissions/{uuid}/static-scan/string-facts``."""

    model_config = ConfigDict(populate_by_name=True)

    observables: list[StringObservable] = Field(default_factory=list)
    facts: list[StringFact] = Field(default_factory=list)
    total: int
    truncated: bool


class StringItem(BaseModel):
    """One extracted string of a strings window."""

    model_config = ConfigDict(populate_by_name=True)

    value: str
    from_source: str
    blacklist: bool
    hint: str | None = None


class StringsPage(BaseModel):
    """Response of ``GET /submissions/{uuid}/static-scan/strings/items``."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[StringItem] = Field(default_factory=list)
    items_count: int = Field(alias="itemsCount")
    start: int
    end: int
    download_link: str = Field(alias="downloadLink")
