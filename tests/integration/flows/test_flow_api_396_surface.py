"""The v3.9.6 routes of the Public API through the fake API."""

from __future__ import annotations

import pytest

from threatzone import AsyncThreatZone, NotFoundError, ReportUnavailableError, ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios


def test_dynamic_session_follows_the_run(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    before = sync_client.get_dynamic_session(created.uuid)
    assert before.state == "unavailable"
    assert before.vnc_available is False
    assert before.link is None

    assert sync_client.get_submission(created.uuid).overview.status == "in_progress"
    running = sync_client.get_dynamic_session(created.uuid)
    assert running.state == "running"
    assert running.vnc_available is True
    assert running.link is not None
    assert running.link.startswith("wss://")
    assert created.uuid not in running.link
    assert running.expires_at is not None

    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    after = sync_client.get_dynamic_session(created.uuid)
    assert after.state == "unavailable"
    assert after.link is None
    assert after.expires_at is None


def test_dynamic_session_of_a_static_only_submission_is_unavailable(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    sync_client.get_submission(created.uuid)

    session = sync_client.get_dynamic_session(created.uuid)
    assert session.state == "unavailable"
    assert session.link is None


def test_dynamic_session_of_a_url_submission_is_409(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    url = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(url)

    with pytest.raises(ReportUnavailableError) as exc_info:
        sync_client.get_dynamic_session(created.uuid)
    assert exc_info.value.status_code == 409
    assert exc_info.value.code == "DYNAMIC_REPORT_UNAVAILABLE"
    assert "details" not in (exc_info.value.body or {})


def test_dynamic_session_of_a_private_foreign_submission_is_404(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_private_cross_workspace(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    with pytest.raises(NotFoundError):
        sync_client.get_dynamic_session(created.uuid)


async def test_dynamic_session_async(
    fake_api: FakeThreatZoneAPI, async_client: AsyncThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = await async_client.create_sandbox_submission(b"PE")
    await async_client.get_submission(created.uuid)

    session = await async_client.get_dynamic_session(created.uuid)
    assert session.state == "running"
    assert session.link is not None
