"""Recipe 03 — fetch malicious indicators with filters.

Mirrors `docs/RECIPES.md#3-get-all-malicious-indicators`.
"""

from __future__ import annotations

from threatzone import ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import IndicatorsResponse


def test_get_all_malicious_indicators(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    """``level='malicious'`` returns only malicious-level indicators."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    response = sync_client.get_indicators(created.uuid, level="malicious")
    assert isinstance(response, IndicatorsResponse)
    assert len(response.items) >= 1
    for indicator in response.items:
        assert indicator.level == "malicious"


def test_filter_by_mitre_attack_code(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    """Filtering by MITRE technique code returns only matching indicators."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    response = sync_client.get_indicators(created.uuid, attack_code="T1055")
    assert response.total >= 1
    for indicator in response.items:
        assert "T1055" in indicator.attack_codes


def test_filter_by_pid(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    """Filtering by ``pid`` returns indicators emitted by that process."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    response = sync_client.get_indicators(created.uuid, pid=1508)
    assert response.total >= 1
    for indicator in response.items:
        assert 1508 in indicator.pids


def test_filter_by_category(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    """Filtering by indicator category narrows the result set."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    response = sync_client.get_indicators(created.uuid, category="default")
    assert response.total >= 1
    for indicator in response.items:
        assert indicator.category == "default"


def test_indicators_response_envelope_shape(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """The indicators response carries ``items``, ``total``, and ``levels``."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    response = sync_client.get_indicators(created.uuid)
    assert hasattr(response, "items")
    assert hasattr(response, "total")
    assert hasattr(response, "levels")
    assert response.levels.malicious >= 0
    assert response.levels.suspicious >= 0
    assert response.levels.benign >= 0
