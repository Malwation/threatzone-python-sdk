"""Contract tests — validate the fake's JSON shapes against SDK Pydantic models."""

from __future__ import annotations

import pytest

from threatzone import (
    AsyncThreatZone,
    BadRequestError,
    NotFoundError,
    ReportUnavailableError,
    ThreatZone,
)
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import (
    AiReport,
    AiReportPending,
    AiReportRegenerateResult,
    ArtifactJob,
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
    user = sync_client.get_user_info()
    assert isinstance(user, UserInfo)
    assert user.plan_permissions is not None
    assert user.plan_permissions.ai_report is True
    assert user.ai_report_resets_at is not None
    assert user.plan.submission_limits.ai_report_limit == 20


def test_submission_created_and_submission_contract(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    assert isinstance(created, SubmissionCreated)
    submission = sync_client.get_submission(created.uuid)
    assert isinstance(submission, Submission)


def test_submission_detail_fields_contract(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    target_sha = scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    pending = sync_client.get_submission(created.uuid)
    assert pending.score is None
    assert pending.score_breakdown is None
    assert pending.overview.duration is None
    done = sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    assert done.score_breakdown is not None
    assert done.score == done.score_breakdown.score
    assert done.overview.duration is not None
    assert done.file is not None
    assert done.file.history is not None
    assert done.file.history.filenames == ["malware.exe", "invoice.exe"]
    assert done.reports[0].metafields == {
        "Work Path": "Desktop",
        "Enable Memory Dumps": "Enabled",
    }
    assert done.tags[0].author == "system"
    [row] = sync_client.search_by_sha256(target_sha)
    assert row.score_breakdown is None
    assert row.overview.duration is None
    assert row.file is not None
    assert row.file.history is None


def test_pure_url_submission_has_no_live_score(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission("https://phishing.example.com")
    done = sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    assert done.score is None
    assert done.score_breakdown is None


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


def test_indicator_v2_and_ioc_raw_type_contracts(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    indicator = sync_client.get_indicators(created.uuid).items[0]
    assert indicator.pid_gens is not None
    assert len(indicator.pid_gens) == len(indicator.pids)
    assert indicator.rule_source is not None
    assert indicator.actor is not None
    assert indicator.related is not None
    assert indicator.related[0].event_id in indicator.event_ids
    for ioc in sync_client.get_iocs(created.uuid).items:
        assert ioc.raw_type is not None
        assert ioc.type == ioc.raw_type.lower()


def test_artifact_analysis_and_jobs_contract(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    artifact = sync_client.get_artifacts(created.uuid).items[0]
    assert artifact.analysis_status == "analyzed"
    assert artifact.analysis_trigger == "auto"
    assert artifact.download_link is not None
    assert artifact.download_link.endswith(f"/download/artifact/{artifact.id}")
    assert sync_client.get_artifacts(created.uuid, source="dynamic_report").total == 1
    assert sync_client.get_artifacts(created.uuid, source="static_report").items == []
    with pytest.raises(BadRequestError):
        sync_client.get_artifacts(created.uuid, source="no_such_source")
    jobs = sync_client.get_artifact_jobs(created.uuid, artifact.id)
    assert all(isinstance(job, ArtifactJob) for job in jobs)
    assert [job.error_code for job in jobs] == [None, "JOB_SKIPPED"]
    with pytest.raises(NotFoundError):
        sync_client.get_artifact_jobs(created.uuid, "no-such-artifact")


async def test_async_artifact_jobs_contract(
    fake_api: FakeThreatZoneAPI, async_client: AsyncThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = await async_client.create_sandbox_submission(b"PE")
    artifacts = await async_client.get_artifacts(created.uuid, source="dynamic_report")
    jobs = await async_client.get_artifact_jobs(created.uuid, artifacts.items[0].id)
    assert [job.engine_type for job in jobs] == ["static_scan", "config_extractor"]


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
    assert report.reason == "finalized"
    assert report.analysis_finalized is True


def test_ai_report_regenerate_contract(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    with pytest.raises(ReportUnavailableError) as exc_info:
        sync_client.regenerate_ai_report(created.uuid)
    assert exc_info.value.code == "AI_REPORT_NOT_FINALIZED"
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    result = sync_client.regenerate_ai_report(created.uuid)
    assert isinstance(result, AiReportRegenerateResult)
    assert result.status == "queued"
    pending = sync_client.get_ai_report(created.uuid)
    assert isinstance(pending, AiReportPending)
    assert pending.status == "queued"
    report = sync_client.get_ai_report(created.uuid)
    assert isinstance(report, AiReport)
    assert report.reason == "regenerate"


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
