"""Recipe 12 — cross-reference MITRE techniques with indicators.

Mirrors `docs/RECIPES.md#12-cross-reference-mitre-techniques-with-indicators`.
"""

from __future__ import annotations

from collections import defaultdict

from threatzone import ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import MitreResponse


def test_mitre_techniques_returned(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    """``get_mitre_techniques`` returns the de-duplicated technique list."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    mitre = sync_client.get_mitre_techniques(created.uuid)
    assert isinstance(mitre, MitreResponse)
    assert mitre.total == len(mitre.techniques)
    assert "T1055" in mitre.techniques


def test_build_technique_to_indicator_map(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """Indicators can be grouped by MITRE technique."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    by_technique: dict[str, list[str]] = defaultdict(list)
    response = sync_client.get_indicators(created.uuid, page=1, limit=100)
    for indicator in response.items:
        for code in indicator.attack_codes:
            by_technique[code].append(indicator.name)

    assert by_technique
    assert "T1055" in by_technique


def test_filter_indicators_by_attack_code(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """``attack_code`` filter narrows to only indicators tagged with that technique."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    response = sync_client.get_indicators(created.uuid, attack_code="T1547.001")
    for indicator in response.items:
        assert "T1547.001" in indicator.attack_codes


def test_mitre_total_matches_techniques_length(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """``MitreResponse.total`` equals the length of the ``techniques`` list."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    mitre = sync_client.get_mitre_techniques(created.uuid)
    assert mitre.total == len(mitre.techniques)
    assert mitre.total >= 3
