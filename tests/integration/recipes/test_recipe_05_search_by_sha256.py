"""Recipe 05 — search submissions by SHA-256.

Mirrors `docs/RECIPES.md#5-search-by-sha256`.
"""

from __future__ import annotations

from threatzone import ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import Submission


def test_search_by_sha256_happy_path(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    """A seeded sample is discoverable via ``search_by_sha256``."""
    target_sha = "1" * 64
    scenarios.seed_malicious_pe(fake_api, sha256=target_sha)

    matches = sync_client.search_by_sha256(target_sha)
    assert isinstance(matches, list)
    assert len(matches) >= 1
    for submission in matches:
        assert isinstance(submission, Submission)
        assert submission.hashes is not None
        assert submission.hashes.sha256 == target_sha


def test_search_by_unknown_sha256_returns_empty(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """A SHA-256 with no matches returns an empty list."""
    del fake_api  # nothing seeded
    matches = sync_client.search_by_sha256("9" * 64)
    assert matches == []


def test_search_by_hash_method_deleted() -> None:
    """Regression: the legacy ``search_by_hash`` method was removed."""
    assert not hasattr(ThreatZone, "search_by_hash")
