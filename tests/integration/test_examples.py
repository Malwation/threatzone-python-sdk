"""Tests every example script against FakeThreatZoneAPI.

If an example's main() function crashes when invoked with a fake-backed client,
the test fails. This guarantees every example compiles, imports cleanly, and
exercises the SDK end-to-end.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from examples import (
    recipe_01_submit_and_wait,
    recipe_02_url_analysis,
    recipe_03_get_malicious_indicators,
    recipe_04_download_all_artifacts,
    recipe_05_search_by_sha256,
    recipe_06_export_network_iocs,
    recipe_07_handle_report_unavailable,
    recipe_08_paginate_submissions,
    recipe_09_discriminate_errors_by_code,
    recipe_10_async_client,
    recipe_11_daily_summary,
    recipe_12_mitre_cross_reference,
)
from threatzone import AsyncThreatZone, ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import (
    Indicator,
    PaginatedSubmissions,
    ProcessesResponse,
    Submission,
    UrlAnalysisResponse,
)


def _seeded_uuid(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> str:
    """Seed a malicious PE, create the submission, advance to completion."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE-bytes")
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    return created.uuid


def test_recipe_01_submits_malicious_pe(
    fake_api: FakeThreatZoneAPI,
    sync_client: ThreatZone,
    tmp_path: Path,
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"fake bytes")
    result = recipe_01_submit_and_wait.main(sync_client, sample)
    assert isinstance(result, Submission)
    assert result.level == "malicious"


@pytest.mark.parametrize("server_has_tiers", [True, False])
def test_recipe_01_reads_iocs_on_every_server(server_has_tiers: bool) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if "tier" in request.url.params and not server_has_tiers:
            return httpx.Response(
                400,
                json={
                    "statusCode": 400,
                    "message": "property tier should not exist",
                    "code": "INVALID_QUERY_PARAM",
                },
            )
        items = [{"type": "ip", "value": "203.0.113.7", "artifacts": []}]
        page = {"items": items, "total": 1, "page": 1, "limit": 100, "totalPages": 1}
        return httpx.Response(200, json=page)

    client = ThreatZone(
        api_key="test-key",
        base_url="https://fake.threat.zone/public-api",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    iocs = recipe_01_submit_and_wait.get_indicator_iocs(
        client, "00000000-0000-4000-8000-000000000001"
    )
    assert [ioc.value for ioc in iocs] == ["203.0.113.7"]
    assert [request.url.params.get("tier") for request in seen] == (
        ["ioc"] if server_has_tiers else ["ioc", None]
    )


def test_recipe_02_url_analysis(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    result = recipe_02_url_analysis.main(sync_client, target)
    assert isinstance(result, UrlAnalysisResponse)
    assert result.general_info.url == target


def test_recipe_03_malicious_indicators(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _seeded_uuid(fake_api, sync_client)
    result = recipe_03_get_malicious_indicators.main(sync_client, uuid)
    assert isinstance(result, list)
    assert len(result) >= 1
    for indicator in result:
        assert isinstance(indicator, Indicator)
        assert indicator.level == "malicious"


def test_recipe_04_download_artifacts(
    fake_api: FakeThreatZoneAPI,
    sync_client: ThreatZone,
    tmp_path: Path,
) -> None:
    uuid = _seeded_uuid(fake_api, sync_client)
    out_dir = tmp_path / "artifacts"
    saved = recipe_04_download_all_artifacts.main(sync_client, uuid, out_dir)
    assert isinstance(saved, int)
    assert saved >= 0
    if saved > 0:
        assert any(out_dir.iterdir())


def test_recipe_05_search_by_sha256(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    sha = scenarios.seed_malicious_pe(fake_api)
    sync_client.create_sandbox_submission(b"PE-bytes")
    result = recipe_05_search_by_sha256.main(sync_client, sha)
    assert isinstance(result, list)
    assert len(result) >= 1
    for submission in result:
        assert isinstance(submission, Submission)


def test_recipe_06_export_network_iocs(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _seeded_uuid(fake_api, sync_client)
    result = recipe_06_export_network_iocs.main(sync_client, uuid)
    assert isinstance(result, dict)
    assert "domains" in result
    assert "ips" in result
    assert "urls" in result


def test_recipe_07_handle_report_unavailable(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"static-bytes")
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    result = recipe_07_handle_report_unavailable.main(sync_client, created.uuid)
    assert result is None or isinstance(result, ProcessesResponse)


def test_recipe_08_paginate_submissions(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    sync_client.create_sandbox_submission(b"PE-bytes")
    result = recipe_08_paginate_submissions.main(sync_client, page=1, limit=20)
    assert isinstance(result, PaginatedSubmissions)
    assert result.total >= 1


def test_recipe_09_discriminate_errors_by_code(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE-bytes")
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    ok = recipe_09_discriminate_errors_by_code.main(sync_client, created.uuid)
    assert ok == "OK"

    missing = recipe_09_discriminate_errors_by_code.main(
        sync_client, "00000000-0000-0000-0000-000000000000"
    )
    assert (
        missing.startswith("NOT_FOUND")
        or missing.startswith("BAD_REQUEST")
        or missing.startswith("API_ERROR")
    )


async def test_recipe_10_async_client(
    fake_api: FakeThreatZoneAPI,
    async_client: AsyncThreatZone,
    tmp_path: Path,
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"fake bytes")
    result = await recipe_10_async_client.main(async_client, sample)
    assert isinstance(result, Submission)
    assert result.level == "malicious"


def test_recipe_11_daily_summary(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _seeded_uuid(fake_api, sync_client)
    result = recipe_11_daily_summary.main(sync_client, uuid)
    assert isinstance(result, dict)
    assert "indicators_total" in result
    assert isinstance(result["indicators_total"], int)


def test_recipe_12_mitre_cross_reference(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _seeded_uuid(fake_api, sync_client)
    result = recipe_12_mitre_cross_reference.main(sync_client, uuid)
    assert isinstance(result, dict)
    assert "mitre_techniques" in result
    assert "indicator_attack_codes" in result
    assert "intersection" in result
    assert "T1055" in result["intersection"]


@pytest.mark.parametrize(
    ("status", "code", "expected"),
    [
        (402, "WORKSPACE_INACTIVE", "WORKSPACE_INACTIVE:WORKSPACE_INACTIVE"),
        (403, "PLAN_API_ACCESS_DENIED", "PERMISSION_DENIED:PLAN_API_ACCESS_DENIED"),
        (400, "INVALID_QUERY_PARAM", "BAD_REQUEST:INVALID_QUERY_PARAM"),
    ],
)
def test_recipe_09_reads_the_current_codes(status: int, code: str, expected: str) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status, json={"statusCode": status, "message": "Refused", "code": code}
        )

    client = ThreatZone(
        api_key="test-key",
        base_url="https://fake.threat.zone/public-api",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert (
        recipe_09_discriminate_errors_by_code.main(client, "00000000-0000-4000-8000-000000000001")
        == expected
    )
