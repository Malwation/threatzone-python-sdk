"""Signature check type definitions.

Mirrors the `signature-check.response.dto.ts` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class SignatureCheckResult(BaseModel):
    """A single signature check result for an artifact."""

    model_config = ConfigDict(populate_by_name=True)

    artifact: str
    # Free-form: shape depends on the signing engine.
    data: dict[str, Any]


class SignatureCheckResponse(BaseModel):
    """Signature check results envelope."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[SignatureCheckResult]
    total: int
