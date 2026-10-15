"""Download-related type definitions."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

PdfReportStatusValue = (
    Literal["analysis_in_progress", "queued", "generating", "ready", "failed"] | str
)


class MediaFile(BaseModel):
    """A media file from dynamic analysis."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    content_type: str | None = Field(default=None, alias="contentType")
    size: int | None = None
    kind: str | None = None


class PdfReportStatus(BaseModel):
    """Generation state of the PDF report of a submission.

    ``retry_after_seconds`` is set while the status is ``queued`` or
    ``generating``. ``message`` is set for ``analysis_in_progress`` and
    ``failed``.
    """

    model_config = ConfigDict(populate_by_name=True)

    status: PdfReportStatusValue
    message: str | None = None
    retry_after_seconds: float | None = Field(default=None, alias="retryAfterSeconds")
