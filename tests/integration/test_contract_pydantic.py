"""Contract tests — validate the fake's JSON shapes against SDK Pydantic models."""

from __future__ import annotations

from threatzone import AsyncThreatZone, ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import (
    AiReport,
    AiReportPending,
    ArtifactsResponse,
    IndicatorsResponse,
    IoCsResponse,
    NetworkExfilRequest,
    NetworkSummary,
    OverviewSummary,
    PaginatedSubmissions,
    PdfReportStatus,
    Submission,
    SubmissionCreated,
    UrlAnalysisResponse,
    UserInfo,
)


def test_user_info_contract(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    del fake_api
    assert isinstance(sync_client.get_user_info(), UserInfo)


def test_submission_created_and_submission_contract(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    assert isinstance(created, SubmissionCreated)
    submission = sync_client.get_submission(created.uuid)
    assert isinstance(submission, Submission)


def test_paginated_submissions_contract(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    sync_client.create_sandbox_submission(b"PE")
    response = sync_client.list_submissions()
    assert isinstance(response, PaginatedSubmissions)


def test_indicator_ioc_artifact_network_contracts(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    assert isinstance(sync_client.get_indicators(created.uuid), IndicatorsResponse)
    assert isinstance(sync_client.get_iocs(created.uuid), IoCsResponse)
    assert isinstance(sync_client.get_artifacts(created.uuid), ArtifactsResponse)
    assert isinstance(sync_client.get_network_summary(created.uuid), NetworkSummary)
    assert isinstance(sync_client.get_overview_summary(created.uuid), OverviewSummary)


def test_url_analysis_contract(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission("https://phishing.example.com")
    assert isinstance(sync_client.get_url_analysis(created.uuid), UrlAnalysisResponse)


def test_network_exfil_requests_contract(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    entries = sync_client.get_network_exfil_requests(created.uuid)
    assert all(isinstance(entry, NetworkExfilRequest) for entry in entries)
    summary = sync_client.get_network_summary(created.uuid)
    assert summary.exfil_request_count == len(entries)
    assert sync_client.get_network_exfil_requests(created.uuid, skip=1) == []


def test_search_by_sha256_pages_the_results(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    target_sha = scenarios.seed_malicious_pe(fake_api)
    sync_client.create_sandbox_submission(b"PE")
    assert len(sync_client.search_by_sha256(target_sha, page=1, limit=1)) == 1
    assert sync_client.search_by_sha256(target_sha, page=2, limit=1) == []


def test_ai_report_contract(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    assert isinstance(sync_client.get_ai_report(created.uuid), AiReportPending)
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    report = sync_client.get_ai_report(created.uuid)
    assert isinstance(report, AiReport)
    assert report.status == "completed"


def test_pdf_and_stix_report_contract(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    assert isinstance(sync_client.get_pdf_report_status(created.uuid), PdfReportStatus)
    pdf = sync_client.download_pdf_report(created.uuid, poll_interval=0, timeout=5)
    assert pdf.read().startswith(b"%PDF")
    stix = sync_client.download_stix_report(created.uuid)
    assert b"bundle" in stix.read()


async def test_async_pdf_report_waits_for_the_render(
    fake_api: FakeThreatZoneAPI, async_client: AsyncThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = await async_client.create_sandbox_submission(b"PE")
    await async_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    pdf = await async_client.download_pdf_report(created.uuid, poll_interval=0, timeout=5)
    assert (await pdf.read()).startswith(b"%PDF")
