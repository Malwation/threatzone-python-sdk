"""Flow — heavy-route rate limit and quota outage responses of the fake API."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from threatzone import (
    AsyncThreatZone,
    InternalServerError,
    NotFoundError,
    PermissionDeniedError,
    QuotaUnavailableError,
    RateLimitError,
    ThreatZone,
)
from threatzone.testing import FakeThreatZoneAPI, scenarios


def _submit(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> str:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    return created.uuid


@pytest.mark.parametrize(
    "call_route",
    [
        pytest.param(lambda client, uuid: client.get_killchain(uuid), id="killchain"),
        pytest.param(
            lambda client, uuid: client.get_behaviours(uuid, types=["file"]), id="behaviours"
        ),
        pytest.param(lambda client, uuid: client.get_behaviour_summary(uuid), id="summary"),
        pytest.param(lambda client, uuid: client.get_behaviour_facets(uuid, "type"), id="facets"),
        pytest.param(
            lambda client, uuid: client.get_behaviour_matches(uuid, "dropped.exe"), id="match"
        ),
        pytest.param(
            lambda client, uuid: client.search_syscalls(uuid, query="NtReadFile"),
            id="syscall-search",
        ),
        pytest.param(lambda client, uuid: client.get_network_endpoints(uuid), id="endpoints"),
        pytest.param(
            lambda client, uuid: client.get_network_host_flows(uuid, "malware-c2.example.com"),
            id="host-flows",
        ),
        pytest.param(lambda client, uuid: client.download_behaviour(uuid), id="raw-behaviour"),
        pytest.param(lambda client, uuid: client.download_syscalls(uuid), id="raw-syscalls"),
    ],
)
def test_heavy_routes_raise_rate_limit_error(
    fake_api: FakeThreatZoneAPI,
    sync_client: ThreatZone,
    call_route: Callable[[ThreatZone, str], object],
) -> None:
    uuid = _submit(fake_api, sync_client)
    fake_api.rate_limit_heavy_routes(retry_after=42)
    with pytest.raises(RateLimitError) as exc_info:
        call_route(sync_client, uuid)
    assert exc_info.value.code == "RATE_LIMIT_EXCEEDED"
    assert exc_info.value.retry_after == 42.0
    assert exc_info.value.response is not None
    assert exc_info.value.response.headers["retry-after"] == "42"


def test_rate_limit_spares_the_light_routes(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    fake_api.rate_limit_heavy_routes()
    assert sync_client.get_behaviours(uuid).total == 2
    assert sync_client.get_behaviours(uuid, event_ids=[1]).total == 1
    assert sync_client.get_indicators(uuid).total > 0
    fake_api.reset()
    uuid = _submit(fake_api, sync_client)
    assert sync_client.get_behaviour_summary(uuid).total_count == 2


def test_rate_limit_comes_after_the_access_and_permission_checks(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    fake_api.rate_limit_heavy_routes()
    fake_api.deny_download_report(uuid)
    with pytest.raises(PermissionDeniedError):
        sync_client.download_behaviour(uuid)
    fake_api.mark_private(uuid)
    with pytest.raises(NotFoundError):
        sync_client.get_behaviour_summary(uuid)


async def test_async_heavy_route_raises_rate_limit_error(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone, async_client: AsyncThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    fake_api.rate_limit_heavy_routes(retry_after=5)
    with pytest.raises(RateLimitError) as exc_info:
        await async_client.get_behaviour_matches(uuid, ["dropped.exe"])
    assert (exc_info.value.code, exc_info.value.retry_after) == ("RATE_LIMIT_EXCEEDED", 5.0)


@pytest.mark.parametrize(
    "create",
    [
        pytest.param(lambda client: client.create_sandbox_submission(b"PE"), id="sandbox"),
        pytest.param(lambda client: client.create_static_submission(b"PE"), id="static"),
        pytest.param(lambda client: client.create_cdr_submission(b"PE"), id="cdr"),
        pytest.param(lambda client: client.create_url_submission("https://example.com"), id="url"),
    ],
)
def test_quota_outage_raises_quota_unavailable_error(
    fake_api: FakeThreatZoneAPI,
    sync_client: ThreatZone,
    create: Callable[[ThreatZone], object],
) -> None:
    fake_api.mark_quota_unavailable(retry_after=30)
    with pytest.raises(QuotaUnavailableError) as exc_info:
        create(sync_client)
    error = exc_info.value
    assert isinstance(error, InternalServerError)
    assert (error.status_code, error.code, error.retry_after) == (503, "QUOTA_UNAVAILABLE", 30.0)


def test_quota_outage_blocks_the_url_analysis_restart(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(target)
    fake_api.mark_quota_unavailable()
    with pytest.raises(QuotaUnavailableError):
        sync_client.restart_url_analysis(created.uuid)
