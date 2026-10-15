"""Run compare type definitions.

Mirrors the `compare.response.dto.ts` DTO in the Threat.Zone Public API. ``added`` items are in
the run of ``submission_uuid`` only; ``removed`` items are in the run of
``other_submission_uuid`` only. Each list holds at most 200 items; the totals count the items
before that cap.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PreviousRun(BaseModel):
    """The latest earlier run of the same sample or URL that the caller can open."""

    model_config = ConfigDict(populate_by_name=True)

    previous_run_uuid: str | None = Field(default=None, alias="previousRunUuid")
    """``None`` when no earlier run matches."""


class CompareDetection(BaseModel):
    """A detection in one run only. Detections compare by title."""

    model_config = ConfigDict(populate_by_name=True)

    title: str
    level: str
    """Highest level of the detection in its run, for example ``malicious``."""


class CompareIoc(BaseModel):
    """An IoC in one run only. IoCs compare by category and lowercase value."""

    model_config = ConfigDict(populate_by_name=True)

    value: str
    category: str
    """IoC category, for example ``ip``, ``domain`` or ``url``."""


class CompareDroppedFile(BaseModel):
    """A dropped file in one run only. Files compare by SHA256, else by lowercase path."""

    model_config = ConfigDict(populate_by_name=True)

    path: str
    sha256: str | None = None
    """Lowercase SHA256. ``None`` when the run did not hash the file."""


class CompareDetectionDiff(BaseModel):
    """Detection difference between two runs."""

    model_config = ConfigDict(populate_by_name=True)

    added: list[CompareDetection]
    removed: list[CompareDetection]
    added_total: int = Field(alias="addedTotal")
    removed_total: int = Field(alias="removedTotal")


class CompareTechniqueDiff(BaseModel):
    """MITRE ATT&CK technique difference between two runs, as uppercase technique IDs."""

    model_config = ConfigDict(populate_by_name=True)

    added: list[str]
    removed: list[str]
    added_total: int = Field(alias="addedTotal")
    removed_total: int = Field(alias="removedTotal")


class CompareIocDiff(BaseModel):
    """IoC difference between two runs."""

    model_config = ConfigDict(populate_by_name=True)

    added: list[CompareIoc]
    removed: list[CompareIoc]
    added_total: int = Field(alias="addedTotal")
    removed_total: int = Field(alias="removedTotal")


class CompareDroppedFileDiff(BaseModel):
    """Dropped file difference between two runs."""

    model_config = ConfigDict(populate_by_name=True)

    added: list[CompareDroppedFile]
    removed: list[CompareDroppedFile]
    added_total: int = Field(alias="addedTotal")
    removed_total: int = Field(alias="removedTotal")


class RunComparison(BaseModel):
    """Difference between two runs.

    ``techniques`` and ``dropped_files`` come from the dynamic analysis. A run without a
    dynamic analysis gives empty lists.
    """

    model_config = ConfigDict(populate_by_name=True)

    submission_uuid: str = Field(alias="submissionUuid")
    other_submission_uuid: str = Field(alias="otherSubmissionUuid")
    detections: CompareDetectionDiff
    techniques: CompareTechniqueDiff
    iocs: CompareIocDiff
    dropped_files: CompareDroppedFileDiff = Field(alias="droppedFiles")
