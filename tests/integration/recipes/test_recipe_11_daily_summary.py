"""Recipe 11 — daily submission digest.

Mirrors `docs/RECIPES.md#11-build-a-daily-report-summary`.
"""

from __future__ import annotations

from threatzone import ThreatZone
from threatzone.testing import FakeThreatZoneAPI
from threatzone.types import UserInfo


def _seed_mixed(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    fake_api.register_sample(sha256="a" * 64, verdict="malicious", advance_after_polls=1)
    sync_client.create_sandbox_submission(b"x")
    fake_api.register_sample(sha256="b" * 64, verdict="benign", advance_after_polls=1)
    sync_client.create_sandbox_submission(b"y")
    fake_api.register_sample(sha256="c" * 64, verdict="suspicious", advance_after_polls=1)
    sync_client.create_sandbox_submission(b"z")


def test_user_info_has_workspace_name(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    """The ``/me`` endpoint returns a workspace name."""
    del fake_api
    me = sync_client.get_user_info()
    assert isinstance(me, UserInfo)
    assert isinstance(me.workspace_name, str)
    assert me.workspace_name


def test_list_groups_by_level(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    """A verdict rollup built from ``list_submissions`` counts all three buckets."""
    _seed_mixed(fake_api, sync_client)

    response = sync_client.list_submissions(page=1, limit=100)
    counts: dict[str, int] = {}
    for item in response.items:
        counts[item.level] = counts.get(item.level, 0) + 1
    assert counts.get("malicious", 0) == 1
    assert counts.get("benign", 0) == 1
    assert counts.get("suspicious", 0) == 1


def test_list_items_expose_indicator_rollup(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """Every list item carries an ``indicators.levels`` rollup."""
    _seed_mixed(fake_api, sync_client)
    response = sync_client.list_submissions(page=1, limit=100)
    for item in response.items:
        assert item.indicators.levels.malicious >= 0
        assert item.indicators.levels.suspicious >= 0
        assert item.indicators.levels.benign >= 0
