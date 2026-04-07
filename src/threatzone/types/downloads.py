"""Download-related type definitions."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class MediaFile(BaseModel):
    """A media file from dynamic analysis."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    content_type: str | None = Field(default=None, alias="contentType")
    size: int | None = None
