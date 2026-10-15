"""CDR (Content Disarm and Reconstruction) result type definitions.

Mirrors the `cdr.response.dto.ts` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

CdrAction = Literal["removed", "sanitized", "skipped"] | str


class CdrSanitizedFileInfoDetail(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    name: str | None = None
    action: CdrAction | None = None
    data: list[str] | dict[str, object] | str | None = None
    count: int | None = None
    sha256: list[str] | None = None
    description: str | None = None
    file_name: str | None = Field(default=None, alias="fileName")
    details: list[CdrSanitizedFileInfoDetail] = Field(default_factory=list)


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
