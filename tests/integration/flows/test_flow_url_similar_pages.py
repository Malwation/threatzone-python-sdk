"""Flow — URL analysis similar pages and indicator evidence facts."""

from __future__ import annotations

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
from threatzone.types import UrlSimilarPages

_SIMILAR_URL = "https://login.example.com/signin"


def _error_code(error: APIError) -> object:
    assert isinstance(error.body, dict)
    return error.body.get("code")


def _uuid_of(sync_client: ThreatZone, url: str) -> str:
    created = sync_client.create_url_submission(url)
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    return created.uuid


def _seeded(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> str:
    scenarios.seed_similar_pages(fake_api, url=_SIMILAR_URL)
    return _uuid_of(sync_client, _SIMILAR_URL)


def test_similar_pages_lists_only_readable_submissions(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _seeded(fake_api, sync_client)
    result = sync_client.get_url_analysis_similar_pages(uuid)
    assert isinstance(result, UrlSimilarPages)
    assert result.total == 2
    assert [item.host for item in result.items] == ["login-example.net", "example-login.org"]
    assert [item.verdict for item in result.items] == ["malicious", "suspicious"]
    assert result.items[0].matched_dimensions == ["dom", "favicon", "form"]
    assert all(item.scored_at is not None for item in result.items)
    assert "private-match.example.org" not in result.model_dump_json()


def test_listed_submissions_can_be_read(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _seeded(fake_api, sync_client)
    for item in sync_client.get_url_analysis_similar_pages(uuid).items:
        report = sync_client.get_url_analysis(item.submission_uuid)
        assert report.level == item.verdict


def test_private_submission_of_the_token_workspace_is_listed(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _seeded(fake_api, sync_client)
    own_private = sync_client.get_url_analysis_similar_pages(uuid).items[1].submission_uuid
    fake_api.mark_private(own_private, owning_workspace="test-workspace")
    result = sync_client.get_url_analysis_similar_pages(uuid)
    assert result.total == 2
    assert own_private in [item.submission_uuid for item in result.items]


def test_a_match_that_turns_private_to_another_workspace_leaves_the_list(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _seeded(fake_api, sync_client)
    first = sync_client.get_url_analysis_similar_pages(uuid).items[0].submission_uuid
    fake_api.mark_private(first, owning_workspace="other-workspace")
    result = sync_client.get_url_analysis_similar_pages(uuid)
    assert result.total == 1
    assert first not in [item.submission_uuid for item in result.items]


def test_limit_cuts_items_but_not_total(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _seeded(fake_api, sync_client)
    result = sync_client.get_url_analysis_similar_pages(uuid, limit=1)
    assert result.total == 2
    assert [item.host for item in result.items] == ["login-example.net"]


def test_limit_accepts_the_maximum(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    uuid = _seeded(fake_api, sync_client)
    assert len(sync_client.get_url_analysis_similar_pages(uuid, limit=50).items) == 2


@pytest.mark.parametrize("limit", [0, 51, -1])
def test_limit_out_of_range_is_rejected(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone, limit: int
) -> None:
    uuid = _seeded(fake_api, sync_client)
    with pytest.raises(BadRequestError) as exc_info:
        sync_client.get_url_analysis_similar_pages(uuid, limit=limit)
    assert _error_code(exc_info.value) == "INVALID_QUERY_PARAM"


def test_limit_that_is_not_an_integer_is_rejected(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _seeded(fake_api, sync_client)
    with fake_api.as_httpx_client() as http:
        response = http.get(
            f"https://fake.threat.zone/public-api/submissions/{uuid}/url-analysis/similar-pages",
            params={"limit": "ten"},
            headers={"Authorization": "Bearer test-key"},
        )
    assert response.status_code == 400
    assert response.json()["code"] == "INVALID_QUERY_PARAM"


def test_report_without_matches_returns_an_empty_result(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    uuid = _uuid_of(sync_client, target)
    result = sync_client.get_url_analysis_similar_pages(uuid)
    assert result.total == 0
    assert result.items == []


def test_private_submission_of_another_workspace_is_not_found(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _seeded(fake_api, sync_client)
    fake_api.mark_private(uuid, owning_workspace="other-workspace")
    with pytest.raises(NotFoundError) as exc_info:
        sync_client.get_url_analysis_similar_pages(uuid)
    assert _error_code(exc_info.value) == "NOT_FOUND"


def test_file_submission_has_no_similar_pages(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    with pytest.raises(ReportUnavailableError):
        sync_client.get_url_analysis_similar_pages(created.uuid)


def test_register_similar_page_needs_two_dimensions(fake_api: FakeThreatZoneAPI) -> None:
    scenarios.seed_similar_pages(fake_api, url=_SIMILAR_URL)
    target = scenarios.seed_phishing_url(fake_api)
    with pytest.raises(ValueError):
        fake_api.register_similar_page(
            fake_api._url_to_uuid[_SIMILAR_URL], fake_api._url_to_uuid[target], ["dom"]
        )


def test_indicator_evidence_facts(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    uuid = _uuid_of(sync_client, target)
    snapshot = sync_client.get_url_analysis_indicators(uuid).snapshot
    assert snapshot is not None
    domain_age, intel_hit = snapshot.indicators
    assert domain_age.evidence_refs[0].label == "WHOIS record"
    assert domain_age.evidence is not None
    assert [(fact.kind, fact.label, fact.value) for fact in domain_age.evidence] == [
        ("observed", "Domain age", "3 days")
    ]
    assert domain_age.evidence_total == 1
    assert intel_hit.evidence is not None
    observed, would_confirm = intel_hit.evidence
    assert observed.value == target
    assert observed.ref is not None
    assert observed.ref.id in [ref.id for ref in intel_hit.evidence_refs]
    evidence = sync_client.get_url_analysis_indicator_evidence(uuid, intel_hit.id, observed.ref.id)
    assert evidence.state == "available"
    assert would_confirm.kind == "would_confirm"
    assert would_confirm.ref is None
    assert intel_hit.evidence_total == 2


async def test_async_similar_pages(
    fake_api: FakeThreatZoneAPI, async_client: AsyncThreatZone
) -> None:
    scenarios.seed_similar_pages(fake_api, url=_SIMILAR_URL)
    created = await async_client.create_url_submission(_SIMILAR_URL)
    await async_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    result = await async_client.get_url_analysis_similar_pages(created.uuid, limit=1)
    assert result.total == 2
    assert len(result.items) == 1
    with pytest.raises(BadRequestError):
        await async_client.get_url_analysis_similar_pages(created.uuid, limit=51)
    explanation = await async_client.get_url_analysis_indicators(created.uuid)
    assert explanation.snapshot is not None
    assert explanation.snapshot.indicators[0].evidence_total == 1


async def test_async_similar_pages_empty(
    fake_api: FakeThreatZoneAPI, async_client: AsyncThreatZone
) -> None:
    target = scenarios.seed_phishing_url(fake_api)
    created = await async_client.create_url_submission(target)
    await async_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    result = await async_client.get_url_analysis_similar_pages(created.uuid)
    assert (result.total, result.items) == (0, [])
