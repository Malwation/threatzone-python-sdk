"""CDR (Content Disarm and Reconstruction) result type definitions.

Mirrors the `cdr.response.dto.ts` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .common import ReportStatusValue


class CdrResult(BaseModel):
    """A single CDR transformation result for an artifact."""

    model_config = ConfigDict(populate_by_name=True)

    artifact: str
    status: ReportStatusValue
    # Free-form: shape depends on the CDR engine.
    data: dict[str, Any] | None = None
    last_error_message: str | None = Field(default=None, alias="lastErrorMessage")
    engine_version: str | None = Field(default=None, alias="engineVersion")


class CdrResponse(BaseModel):
    """CDR transformation results envelope."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[CdrResult]
    total: int
