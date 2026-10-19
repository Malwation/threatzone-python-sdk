"""MITRE ATT&CK type definitions.

Mirrors the `mitre.response.dto.ts` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AttackDomain = Literal["enterprise", "mobile"] | str
"""ATT&CK domain of a report: ``mobile`` for an Android report, ``enterprise`` for the other
platforms."""


class MitreTechniqueUsage(BaseModel):
    """One matched technique that is in the ATT&CK catalog of the platform."""

    model_config = ConfigDict(populate_by_name=True)

    technique_id: str = Field(alias="techniqueId")
    """Technique ID (``T####`` or ``T####.###``)."""
    name: str
    """Technique name from the ATT&CK catalog that ships with the platform."""
    tactic_ids: list[str] = Field(alias="tacticIds")
    """Every tactic ID (``TA####``) of the technique, in ATT&CK matrix order."""
    score: float
    """Highest score (0 to 100) of the indicators that carry the technique."""
    score_maximum: int = Field(alias="scoreMaximum")
    """Top of the ``score`` scale. The value is always ``100``."""
    in_verdict_chain: bool = Field(alias="inVerdictChain")
    """``True`` when an indicator with this technique is part of the finding that set the
    verdict (Windows V2 reports). ``False`` for other reports."""
    attempted: bool | None = None
    """``True`` when every indicator that carries the technique marks it attempted: the
    evidence is a request that the sandbox did not confirm. ``None`` on older servers."""
    indicator_ids: list[str] = Field(alias="indicatorIds")
    """IDs of the dynamic indicators that carry the technique (``Indicator.id``)."""


class MitreResponse(BaseModel):
    """Matched MITRE ATT&CK technique IDs for a submission."""

    model_config = ConfigDict(populate_by_name=True)

    techniques: list[str]
    total: int
    attack_version: str | None = Field(default=None, alias="attackVersion")
    """Version of the ATT&CK catalog, for example ``"20.0"``. ``None`` on older servers."""
    domain: AttackDomain | None = None
    """ATT&CK domain of the report. ``items`` holds only the techniques of this domain.
    ``None`` on older servers."""
    items: list[MitreTechniqueUsage] | None = None
    """One entry for each matched technique that is in the ATT&CK catalog, sorted by
    ``technique_id``. A code that is not in the catalog is in ``techniques`` but not in
    ``items``, so ``items`` can be shorter than ``techniques``. ``None`` when an older
    server omits the field."""
