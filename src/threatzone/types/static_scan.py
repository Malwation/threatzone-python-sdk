"""Static scan type definitions.

Mirrors the `static-scan.response.dto.ts` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .common import ReportStatusValue


class StaticScanResult(BaseModel):
    """A single static scan result for an artifact."""

    model_config = ConfigDict(populate_by_name=True)

    artifact: str
    status: ReportStatusValue
    # Free-form: shape depends on the analyzer engine.
    data: dict[str, Any] | None = None
    last_error_message: str | None = Field(default=None, alias="lastErrorMessage")
    engine_version: str | None = Field(default=None, alias="engineVersion")


class StaticScanResponse(BaseModel):
    """Static scan results envelope."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[StaticScanResult]
    total: int
