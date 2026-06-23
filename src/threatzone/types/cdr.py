"""CDR (Content Disarm and Reconstruction) result type definitions.

Mirrors the `cdr.response.dto.ts` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class CdrSanitizedFileInfoDetail(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    name: str | None = None
    action: str | None = None
    data: dict[str, object] | None = None


class CdrSanitizedFileInfo(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    description: str | None = None
    file_type: str | None = Field(default=None, alias="fileType")
    file_size: int | None = Field(default=None, alias="fileSize")
    sha256: str | None = None
    name: str | None = None
    details: list[CdrSanitizedFileInfoDetail] = Field(default_factory=list)


class CdrResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    submission: str
    status: str
    sanitized: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    sanitized_file_info: CdrSanitizedFileInfo | None = Field(
        default=None, alias="sanitizedFileInfo"
    )
    elapsed_time: str | None = Field(default=None, alias="elapsedTime")
    metafields: dict[str, object] | None = None
