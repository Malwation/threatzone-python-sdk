"""Contract tests — validate the fake's JSON shapes against SDK Pydantic models."""

from __future__ import annotations

from threatzone import ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import (
    ArtifactsResponse,
    IndicatorsResponse,
    IoCsResponse,
    NetworkSummary,
    OverviewSummary,
    PaginatedSubmissions,
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
