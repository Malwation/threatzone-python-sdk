"""Flow — access control and privacy boundaries."""

from __future__ import annotations

import httpx
import pytest

from threatzone import PermissionDeniedError, ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios


def test_private_cross_workspace_submission_is_403(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_private_cross_workspace(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    with pytest.raises(PermissionDeniedError):
        sync_client.get_submission(created.uuid)


def test_private_cross_workspace_blocks_indicator_endpoint(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_private_cross_workspace(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    with pytest.raises(PermissionDeniedError):
        sync_client.get_indicators(created.uuid)


def test_private_cross_workspace_blocks_downloads(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_private_cross_workspace(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    with pytest.raises(PermissionDeniedError), sync_client.download_sample(created.uuid) as _:
        pass


def test_mark_private_after_activation(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    fake_api.mark_private(created.uuid, owning_workspace="other-workspace")
    with pytest.raises(PermissionDeniedError):
        sync_client.get_submission(created.uuid)


def test_missing_bearer_returns_401(fake_api: FakeThreatZoneAPI) -> None:
    raw = httpx.Client(
        transport=fake_api.as_transport(),
        base_url="https://fake.threat.zone/public-api",
    )
    try:
        response = raw.get("/submissions")
        assert response.status_code == 401
        assert response.json()["code"] == "UNAUTHORIZED"
    finally:
        raw.close()


def test_own_private_submission_is_accessible(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """A private submission owned by the caller's workspace IS accessible."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    fake_api.mark_private(created.uuid, owning_workspace="test-workspace")
    submission = sync_client.get_submission(created.uuid)
    assert submission.private is True
