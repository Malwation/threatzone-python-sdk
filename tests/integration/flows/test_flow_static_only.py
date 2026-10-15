"""Flow — static-only submission lifecycle."""

from __future__ import annotations

from typing import Any

import pytest

from threatzone import AsyncThreatZone, BadRequestError, ReportUnavailableError, ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import (
    SignatureCheckResponse,
    StaticScanResponse,
    StringFacts,
    StringsPage,
    Submission,
)


def test_static_submission_completes(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    final = sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    assert isinstance(final, Submission)
    assert final.is_complete()


def test_static_scan_report_reachable(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    report = sync_client.get_static_scan_results(created.uuid)
    assert isinstance(report, StaticScanResponse)


def test_signature_check_reachable(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    report = sync_client.get_signature_check_results(created.uuid)
    assert isinstance(report, SignatureCheckResponse)


def test_dynamic_gated_endpoints_409(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    with pytest.raises(ReportUnavailableError):
        sync_client.get_processes(created.uuid)
    with pytest.raises(ReportUnavailableError):
        sync_client.get_network_summary(created.uuid)


def test_cdr_gated_endpoint_409(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    with pytest.raises(ReportUnavailableError):
        sync_client.get_cdr_results(created.uuid)


def test_yara_rules_visible_on_static(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    rules = sync_client.get_yara_rules(created.uuid)
    assert rules.total >= 0


def test_static_scan_nsrl_file_info(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    report = sync_client.get_static_scan_results(created.uuid)
    assert report.file_info is not None
    assert report.file_info.real_filename is None
    assert report.file_info.real_sha256 is None


def test_string_facts_return_secrets_in_full(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    facts = sync_client.get_static_scan_string_facts(created.uuid)
    assert isinstance(facts, StringFacts)
    [token] = [row for row in facts.observables if row.secret]
    assert token.kind == "bot-token"
    assert token.value == token.display
    assert "AAFabcdefghijklmnopqrstuvwxyz012345" in token.value
    assert token.value in token.source
    assert {fact.code for fact in facts.facts} == {"anti-debug", "run-key"}
    assert facts.truncated is False


def test_strings_page_window_and_search(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    everything = sync_client.get_static_scan_strings_page(created.uuid)
    assert isinstance(everything, StringsPage)
    assert everything.start == 0
    assert everything.end == 1000
    assert everything.items_count == len(everything.items) == 5
    window = sync_client.get_static_scan_strings_page(created.uuid, start=1, end=3)
    assert [item.value for item in window.items] == ["kernel32.dll", "VirtualAlloc"]
    assert window.items_count == 5
    matched = sync_client.get_static_scan_strings_page(created.uuid, search="  TELEGRAM ")
    assert matched.items_count == 1
    assert "api.telegram.org" in matched.items[0].value
    assert matched.download_link == (f"/public-api/submissions/{created.uuid}/static-scan/strings")
    reversed_window = sync_client.get_static_scan_strings_page(created.uuid, start=3, end=1)
    assert reversed_window.items == []
    assert reversed_window.start == 3
    assert reversed_window.end == 3
    capped = sync_client.get_static_scan_strings_page(created.uuid, end=1500)
    assert capped.start == 0
    assert capped.end == 1000


@pytest.mark.parametrize(
    ("kwargs", "param"),
    [
        ({"start": 0, "end": 1001}, "end"),
        ({"start": -1}, "start"),
        ({"search": "x" * 201}, "search"),
    ],
)
def test_strings_page_rejects_bad_parameters(
    fake_api: FakeThreatZoneAPI,
    sync_client: ThreatZone,
    kwargs: dict[str, Any],
    param: str,
) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    with pytest.raises(BadRequestError) as exc_info:
        sync_client.get_static_scan_strings_page(created.uuid, **kwargs)
    body = exc_info.value.body
    assert body is not None
    assert body["code"] == "INVALID_QUERY_PARAM"
    assert body["details"] == {"param": param}


def test_string_routes_need_the_static_report(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_cdr_document(fake_api)
    created = sync_client.create_cdr_submission(b"DOCX")
    with pytest.raises(ReportUnavailableError):
        sync_client.get_static_scan_string_facts(created.uuid)
    with pytest.raises(ReportUnavailableError):
        sync_client.get_static_scan_strings_page(created.uuid)


async def test_async_string_routes(
    fake_api: FakeThreatZoneAPI, async_client: AsyncThreatZone
) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = await async_client.create_static_submission(b"PE")
    facts = await async_client.get_static_scan_string_facts(created.uuid)
    assert any(row.secret for row in facts.observables)
    page = await async_client.get_static_scan_strings_page(created.uuid, search="kernel32")
    assert [item.value for item in page.items] == ["kernel32.dll"]
