"""Flow — access control and privacy boundaries."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest

from threatzone import AsyncThreatZone, NotFoundError, ReportUnavailableError, ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios

_SyncRouteCall = Callable[[ThreatZone, str], object]
_AsyncRouteCall = Callable[[AsyncThreatZone, str], Awaitable[Any]]


def _private_submission(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> str:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    fake_api.mark_private(created.uuid, owning_workspace="other-workspace")
    return created.uuid


def _assert_not_found(error: NotFoundError) -> None:
    assert error.status_code == 404
    assert (error.body or {}).get("code") == "NOT_FOUND"


def test_private_cross_workspace_submission_is_404(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_private_cross_workspace(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    with pytest.raises(NotFoundError) as exc_info:
        sync_client.get_submission(created.uuid)
    _assert_not_found(exc_info.value)


def test_private_and_missing_submissions_get_the_same_response(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_private_cross_workspace(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    with pytest.raises(NotFoundError) as private_error:
        sync_client.get_indicators(created.uuid)
    with pytest.raises(NotFoundError) as missing_error:
        sync_client.get_indicators("00000000-0000-4000-8000-000000000000")
    assert private_error.value.body == missing_error.value.body


def test_private_cross_workspace_blocks_indicator_endpoint(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_private_cross_workspace(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    with pytest.raises(NotFoundError) as exc_info:
        sync_client.get_indicators(created.uuid)
    _assert_not_found(exc_info.value)


def test_private_cross_workspace_blocks_downloads(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_private_cross_workspace(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    with pytest.raises(NotFoundError), sync_client.download_sample(created.uuid) as _:
        pass


def test_mark_private_after_activation(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    fake_api.mark_private(created.uuid, owning_workspace="other-workspace")
    with pytest.raises(NotFoundError) as exc_info:
        sync_client.get_submission(created.uuid)
    _assert_not_found(exc_info.value)


_SYNC_REPORT_ROUTES = [
    pytest.param(lambda client, uuid: client.get_killchain(uuid), id="killchain"),
    pytest.param(lambda client, uuid: client.get_behaviours(uuid, pids=[1508]), id="behaviours"),
    pytest.param(lambda client, uuid: client.get_behaviour_summary(uuid), id="behaviour-summary"),
    pytest.param(
        lambda client, uuid: client.get_behaviour_facets(uuid, "operation"),
        id="behaviour-facets",
    ),
    pytest.param(
        lambda client, uuid: client.get_behaviour_matches(uuid, ["dropped.exe"]),
        id="behaviour-match",
    ),
    pytest.param(
        lambda client, uuid: client.search_syscalls(uuid, query="NtCreateFile"),
        id="syscall-search",
    ),
    pytest.param(lambda client, uuid: client.download_behaviour(uuid), id="download-behaviour"),
    pytest.param(lambda client, uuid: client.download_syscalls(uuid), id="download-syscalls"),
    pytest.param(
        lambda client, uuid: client.download_artifact_yara_rule(uuid, f"art-{uuid[:8]}-1"),
        id="artifact-yara-rule",
    ),
]


@pytest.mark.parametrize("call_route", _SYNC_REPORT_ROUTES)
def test_report_routes_refuse_a_private_submission_of_another_workspace(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone, call_route: _SyncRouteCall
) -> None:
    uuid = _private_submission(fake_api, sync_client)
    with pytest.raises(NotFoundError) as exc_info:
        call_route(sync_client, uuid)
    _assert_not_found(exc_info.value)


_ASYNC_REPORT_ROUTES = [
    pytest.param(lambda client, uuid: client.get_killchain(uuid), id="killchain"),
    pytest.param(lambda client, uuid: client.get_behaviours(uuid, pids=[1508]), id="behaviours"),
    pytest.param(lambda client, uuid: client.get_behaviour_summary(uuid), id="behaviour-summary"),
    pytest.param(
        lambda client, uuid: client.get_behaviour_facets(uuid, "operation"),
        id="behaviour-facets",
    ),
    pytest.param(
        lambda client, uuid: client.get_behaviour_matches(uuid, ["dropped.exe"]),
        id="behaviour-match",
    ),
    pytest.param(
        lambda client, uuid: client.search_syscalls(uuid, query="NtCreateFile"),
        id="syscall-search",
    ),
    pytest.param(lambda client, uuid: client.download_behaviour(uuid), id="download-behaviour"),
    pytest.param(lambda client, uuid: client.download_syscalls(uuid), id="download-syscalls"),
    pytest.param(
        lambda client, uuid: client.download_artifact_yara_rule(uuid, f"art-{uuid[:8]}-1"),
        id="artifact-yara-rule",
    ),
]


@pytest.mark.parametrize("call_route", _ASYNC_REPORT_ROUTES)
async def test_async_report_routes_refuse_a_private_submission_of_another_workspace(
    fake_api: FakeThreatZoneAPI,
    sync_client: ThreatZone,
    async_client: AsyncThreatZone,
    call_route: _AsyncRouteCall,
) -> None:
    uuid = _private_submission(fake_api, sync_client)
    with pytest.raises(NotFoundError) as exc_info:
        await call_route(async_client, uuid)
    _assert_not_found(exc_info.value)


def test_url_evidence_checks_the_access_before_the_parameters(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _private_submission(fake_api, sync_client)
    with pytest.raises(NotFoundError) as exc_info:
        sync_client.get_url_analysis_indicator_evidence(
            uuid, "indicator", "reference", job_id="not-an-id", scored_at="not-a-date"
        )
    _assert_not_found(exc_info.value)


def test_url_evidence_checks_the_report_before_the_parameters(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    with pytest.raises(ReportUnavailableError) as exc_info:
        sync_client.get_url_analysis_indicator_evidence(
            created.uuid, "indicator", "reference", job_id="not-an-id", scored_at="not-a-date"
        )
    assert exc_info.value.code == "URL_ANALYSIS_REPORT_UNAVAILABLE"


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
