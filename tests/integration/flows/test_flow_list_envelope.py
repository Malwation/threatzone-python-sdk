"""Flow — the opt-in list envelope against the fake API."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from threatzone import ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios


@pytest.fixture
def envelope_client(fake_api: FakeThreatZoneAPI) -> Iterator[ThreatZone]:
    client = ThreatZone(
        api_key="test-key",
        base_url="https://fake.threat.zone/public-api",
        http_client=fake_api.as_httpx_client(),
        list_envelope=True,
    )
    try:
        yield client
    finally:
        client.close()


def _submit(fake_api: FakeThreatZoneAPI, client: ThreatZone) -> str:
    scenarios.seed_malicious_pe(fake_api, sha256="b" * 64)
    created = client.create_sandbox_submission(b"PE")
    client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    return created.uuid


def test_flat_lists_keep_their_types(
    fake_api: FakeThreatZoneAPI, envelope_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, envelope_client)
    first = envelope_client.get_tcp_connections(uuid, limit=2)
    assert (len(first), first.total_count) == (2, 3)
    assert envelope_client.get_environments()
    assert envelope_client.search_by_sha256("b" * 64).total_count == 1
    sent = [request.url.params.get("envelope") for request in fake_api.request_log]
    assert "1" in sent


def test_paged_lists_carry_next(fake_api: FakeThreatZoneAPI, envelope_client: ThreatZone) -> None:
    for i in range(3):
        fake_api.register_sample(sha256=f"{i:064x}", advance_after_polls=1)
        envelope_client.create_sandbox_submission(b"x")
    page = envelope_client.list_submissions(limit=1)
    assert page.page_size == 1
    assert page.next is not None and "page=2" in page.next
    last = envelope_client.list_submissions(limit=50)
    assert last.next is None


def test_detail_routes_do_not_get_the_parameter(
    fake_api: FakeThreatZoneAPI, envelope_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, envelope_client)
    envelope_client.get_submission(uuid)
    detail = [r for r in fake_api.request_log if r.url.path.endswith(f"/submissions/{uuid}")]
    assert detail and all("envelope" not in r.url.params for r in detail)
