"""Recipe 09 — discriminate errors by code.

Mirrors `docs/RECIPES.md#9-discriminate-errors-by-their-code-field`.
"""

from __future__ import annotations

import httpx
import pytest

from threatzone import (
    BadRequestError,
    NotFoundError,
    PermissionDeniedError,
    ReportUnavailableError,
    ThreatZone,
)
from threatzone.testing import FakeThreatZoneAPI, scenarios


def test_missing_bearer_token_returns_401(fake_api: FakeThreatZoneAPI) -> None:
    """A request without an ``Authorization`` header is rejected with 401."""
    del fake_api  # the transport is pulled directly from the fixture-owned fake below

    fake = FakeThreatZoneAPI()
    raw = httpx.Client(
        transport=fake.as_transport(),
        base_url="https://fake.threat.zone/public-api",
    )
    try:
        response = raw.get("/me")
        assert response.status_code == 401
        assert response.json()["code"] == "UNAUTHORIZED"
    finally:
        raw.close()
        fake.reset()


def test_unknown_submission_is_404(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    """An unseeded UUID yields ``NotFoundError``."""
    del fake_api
    with pytest.raises(NotFoundError):
        sync_client.get_submission("00000000-0000-0000-0000-000000000000")


def test_private_cross_workspace_is_403(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """A private submission in another workspace is 403/``SUBMISSION_PRIVATE``."""
    scenarios.seed_private_cross_workspace(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    with pytest.raises(PermissionDeniedError) as exc_info:
        sync_client.get_submission(created.uuid)
    assert (exc_info.value.body or {}).get("code") == "SUBMISSION_PRIVATE"


def test_bad_query_param_is_400(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    """Invalid ``limit`` surfaces as ``BadRequestError`` with an ``INVALID_QUERY_PARAM`` code."""
    del fake_api
    with pytest.raises(BadRequestError) as exc_info:
        sync_client.list_submissions(page=1, limit=500)
    assert (exc_info.value.body or {}).get("code") == "INVALID_QUERY_PARAM"


def test_report_unavailable_code_is_typed(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """``ReportUnavailableError.code`` is populated without reaching into ``body``."""
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")

    with pytest.raises(ReportUnavailableError) as exc_info:
        sync_client.get_processes(created.uuid)
    assert exc_info.value.code == "DYNAMIC_REPORT_UNAVAILABLE"
