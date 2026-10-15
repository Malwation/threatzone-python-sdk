"""Flow — URL score explanation, indicator evidence and browser sections."""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest

from threatzone import (
    APIError,
    AsyncThreatZone,
    BadRequestError,
    NotFoundError,
    ReportUnavailableError,
    ThreatZone,
)
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.testing._responses import FAKE_BROWSER_BODY_TEXT, FAKE_BROWSER_COOKIE_VALUE
from threatzone.types import (
    UrlAnalysisBrowserSection,
    UrlAnalysisIndicatorEvidence,
    UrlAnalysisIndicators,
)


def _error_code(error: APIError) -> object:
    assert isinstance(error.body, dict)
    return error.body.get("code")


def _completed_url(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> str:
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(target)
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    return created.uuid


def test_report_and_explanation_share_the_job_id(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _completed_url(fake_api, sync_client)
    report = sync_client.get_url_analysis(uuid)
    explanation = sync_client.get_url_analysis_indicators(uuid)
    assert isinstance(explanation, UrlAnalysisIndicators)
    assert explanation.state == "available"
    assert explanation.unavailable_reason is None
    assert explanation.snapshot is not None
    assert report.job_id is not None
    assert explanation.snapshot.job_id == report.job_id
    assert explanation.snapshot.verdict == "malicious"
    assert [indicator.id for indicator in explanation.snapshot.indicators] == [
        "domain-age",
        "intel-hit",
    ]


def test_explanation_is_pending_until_the_run_completes(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(target)
    explanation = sync_client.get_url_analysis_indicators(created.uuid)
    assert explanation.state == "pending"
    assert explanation.snapshot is None


def test_evidence_with_the_snapshot_selector(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _completed_url(fake_api, sync_client)
    snapshot = sync_client.get_url_analysis_indicators(uuid).snapshot
    assert snapshot is not None
    evidence = sync_client.get_url_analysis_indicator_evidence(
        uuid, "domain-age", "whois", job_id=snapshot.job_id, scored_at=snapshot.scored_at
    )
    assert isinstance(evidence, UrlAnalysisIndicatorEvidence)
    assert evidence.state == "available"
    assert evidence.truncated is False
    assert evidence.text is not None
    assert json.loads(evidence.text)["registrar"] == "Test Registrar"


def test_evidence_reads_the_selector_when_it_is_not_given(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _completed_url(fake_api, sync_client)
    evidence = sync_client.get_url_analysis_indicator_evidence(uuid, "intel-hit", "intel-urlhaus")
    assert evidence.state == "available"
    assert evidence.text is not None
    assert json.loads(evidence.text)["source"] == "urlhaus"


def test_evidence_with_an_old_selector_is_unavailable(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _completed_url(fake_api, sync_client)
    evidence = sync_client.get_url_analysis_indicator_evidence(
        uuid,
        "domain-age",
        "whois",
        job_id="0123456789abcdef01234567",
        scored_at="2020-01-01T00:00:00.000Z",
    )
    assert evidence.state == "unavailable"
    assert evidence.text is None


def test_evidence_that_is_not_stored_is_unavailable(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _completed_url(fake_api, sync_client)
    evidence = sync_client.get_url_analysis_indicator_evidence(uuid, "intel-hit", "net-0")
    assert evidence.state == "unavailable"


def test_evidence_of_an_unknown_reference_is_not_found(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _completed_url(fake_api, sync_client)
    with pytest.raises(NotFoundError) as exc_info:
        sync_client.get_url_analysis_indicator_evidence(uuid, "domain-age", "other-ref")
    assert _error_code(exc_info.value) == "URL_SCORE_EVIDENCE_NOT_FOUND"


def test_evidence_rejects_a_malformed_job_id(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _completed_url(fake_api, sync_client)
    with pytest.raises(BadRequestError) as exc_info:
        sync_client.get_url_analysis_indicator_evidence(
            uuid, "domain-age", "whois", job_id="not-a-job", scored_at="2020-01-01T00:00:00Z"
        )
    assert _error_code(exc_info.value) == "INVALID_QUERY_PARAM"


def test_evidence_without_a_snapshot_lets_the_api_reject_the_request(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(target)
    with pytest.raises(BadRequestError):
        sync_client.get_url_analysis_indicator_evidence(created.uuid, "domain-age", "whois")


@pytest.mark.parametrize("section", ["overview", "findings", "tls", "network-summary"])
def test_every_approved_browser_section(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone, section: str
) -> None:
    uuid = _completed_url(fake_api, sync_client)
    result = sync_client.get_url_analysis_browser_section(uuid, section)
    assert isinstance(result, UrlAnalysisBrowserSection)
    assert result.section == section
    assert result.job_id == sync_client.get_url_analysis(uuid).job_id
    assert result.revision
    assert result.data


def test_network_summary_never_returns_cookies_or_bodies(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _completed_url(fake_api, sync_client)
    result = sync_client.get_url_analysis_browser_section(uuid, "network-summary")
    assert set(result.data) == {"redirects", "domainTable", "ipTable"}
    serialized = json.dumps(result.data)
    assert FAKE_BROWSER_COOKIE_VALUE not in serialized
    assert FAKE_BROWSER_BODY_TEXT not in serialized


def test_unknown_browser_section_is_not_found(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _completed_url(fake_api, sync_client)
    with pytest.raises(NotFoundError) as exc_info:
        sync_client.get_url_analysis_browser_section(uuid, "cookies")
    assert _error_code(exc_info.value) == "URL_BROWSER_SECTION_NOT_FOUND"


def test_browser_section_of_an_open_run_is_unavailable(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(target)
    with pytest.raises(NotFoundError) as exc_info:
        sync_client.get_url_analysis_browser_section(created.uuid, "tls")
    assert _error_code(exc_info.value) == "URL_BROWSER_SECTION_UNAVAILABLE"


def test_url_routes_reject_a_file_submission(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    with pytest.raises(ReportUnavailableError):
        sync_client.get_url_analysis_indicators(created.uuid)
    with pytest.raises(ReportUnavailableError):
        sync_client.get_url_analysis_browser_section(created.uuid, "tls")


_PrivateUrlRouteCall = Callable[[ThreatZone, str], object]


@pytest.mark.parametrize(
    "call_route",
    [
        pytest.param(
            lambda client, uuid: client.get_url_analysis_indicators(uuid), id="indicators"
        ),
        pytest.param(
            lambda client, uuid: client.get_url_analysis_indicator_evidence(
                uuid,
                "domain-age",
                "whois",
                job_id="0123456789abcdef01234567",
                scored_at="2020-01-01T00:00:00.000Z",
            ),
            id="indicator-evidence",
        ),
        pytest.param(
            lambda client, uuid: client.get_url_analysis_browser_section(uuid, "tls"),
            id="browser-section",
        ),
    ],
)
def test_url_routes_reject_a_private_submission_of_another_workspace(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone, call_route: _PrivateUrlRouteCall
) -> None:
    uuid = _completed_url(fake_api, sync_client)
    fake_api.mark_private(uuid, owning_workspace="other-workspace")
    with pytest.raises(NotFoundError) as exc_info:
        call_route(sync_client, uuid)
    assert _error_code(exc_info.value) == "NOT_FOUND"
    assert isinstance(exc_info.value.body, dict)
    assert {"snapshot", "text", "data"}.isdisjoint(exc_info.value.body)


def test_session_config_names_the_network_config(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = sync_client.create_url_submission(
        target, safe_browsing=True, configurations={"networkConfig": "cfg1"}
    )
    session = sync_client.get_url_analysis_session(created.uuid)
    assert session.session_config is not None
    assert session.session_config.network_config_source == "submit"
    assert session.session_config.network_config_name == "Corp Proxy"


async def test_async_url_score_explanation(
    fake_api: FakeThreatZoneAPI, async_client: AsyncThreatZone
) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = await async_client.create_url_submission(target)
    await async_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    explanation = await async_client.get_url_analysis_indicators(created.uuid)
    assert explanation.state == "available"
    evidence = await async_client.get_url_analysis_indicator_evidence(
        created.uuid, "domain-age", "whois"
    )
    assert evidence.state == "available"
    section = await async_client.get_url_analysis_browser_section(created.uuid, "overview")
    assert section.section == "overview"
