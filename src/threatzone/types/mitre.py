"""MITRE ATT&CK type definitions.

Mirrors the `mitre.response.dto.ts` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class MitreResponse(BaseModel):
    """Matched MITRE ATT&CK technique IDs for a submission."""

    model_config = ConfigDict(populate_by_name=True)

    techniques: list[str]
    total: int
