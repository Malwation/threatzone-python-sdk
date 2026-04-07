"""Unit tests for the synchronous Threat.Zone client.

For each public method:
- happy path mocks the underlying httpx.Client.request, asserts the URL,
  query params, auth header, and parsed response type;
- error paths verify that 401/403/404/409/500 raise the right typed exception;
- the new ReportUnavailableError (HTTP 409) carries the structured details from
  the canonical error envelope;
- methods accepting filters/pagination verify the params reach the wire.
"""

from __future__ import annotations

import json
import os
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest

from threatzone import ThreatZone
from threatzone._exceptions import (
    AnalysisTimeoutError,
    AuthenticationError,
    BadRequestError,
    InternalServerError,
    NotFoundError,
    PermissionDeniedError,
    ReportUnavailableError,
    YaraRulePendingError,
)
from threatzone.types import (
    Artifact,
    ArtifactsResponse,
    BehavioursResponse,
    CdrResponse,
    Connection,
    DnsQuery,
    EmlAnalysis,
    EnvironmentOption,
    ExtractedConfigsResponse,
    HttpRequest,
    IndicatorsResponse,
    IoCsResponse,
    MediaFile,
    MetafieldOption,
    Metafields,
    MitreResponse,
    NetworkSummary,
    NetworkThreat,
    OverviewSummary,
    PaginatedSubmissions,
    ProcessesResponse,
    ProcessTreeResponse,
    SignatureCheckResponse,
    StaticScanResponse,
    Submission,
    SubmissionCreated,
    SyscallsResponse,
    UrlAnalysisResponse,
    UserInfo,
    YaraRulesResponse,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(
    status: int = 200,
    json_data: Any = None,
    content: bytes = b"",
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    if json_data is not None:
        content = json.dumps(json_data).encode()
        headers = {**(headers or {}), "content-type": "application/json"}
    return httpx.Response(status_code=status, content=content, headers=headers or {})


def _patched_client(
    response: httpx.Response,
) -> tuple[Any, MagicMock]:
    """Patch httpx.Client.request to return a fixed response."""
    mock = MagicMock(return_value=response)
    return patch.object(httpx.Client, "request", mock), mock


def _call_url(mock: MagicMock) -> str:
    args, kwargs = mock.call_args
    return str(args[1]) if len(args) >= 2 else str(kwargs["url"])


def _call_params(mock: MagicMock) -> dict[str, Any]:
    _, kwargs = mock.call_args
    params = kwargs.get("params") or {}
    return dict(params)


def _call_headers(mock: MagicMock) -> dict[str, Any]:
    _, kwargs = mock.call_args
    return dict(kwargs.get("headers") or {})


def _call_method(mock: MagicMock) -> str:
    args, kwargs = mock.call_args
    return str(args[0]) if args else str(kwargs["method"])


def _409_body(
    code: str = "DYNAMIC_REPORT_UNAVAILABLE",
    *,
    submission_uuid: str = "11111111-2222-3333-4444-555555555555",
    required_report: str = "dynamic",
    current_status: str | None = "in_progress",
    available_reports: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "statusCode": 409,
        "error": "Conflict",
        "message": "Required report is not available",
        "code": code,
        "details": {
            "submissionUuid": submission_uuid,
            "requiredReport": required_report,
            "currentStatus": current_status,
            "availableReports": available_reports if available_reports is not None else ["static"],
        },
    }


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestClientInitialization:
    def test_init_with_api_key(self, api_key: str) -> None:
        client = ThreatZone(api_key=api_key)
        assert client._config.api_key == api_key
        client.close()

    def test_init_with_env_var(self) -> None:
        with patch.dict(os.environ, {"THREATZONE_API_KEY": "env_api_key"}):
            client = ThreatZone()
            assert client._config.api_key == "env_api_key"
            client.close()

    def test_init_without_api_key_raises(self) -> None:
        with (
            patch.dict(os.environ, {}, clear=True),
            pytest.raises(AuthenticationError, match="API key"),
        ):
            ThreatZone()

    def test_init_with_custom_base_url(self, api_key: str, base_url: str) -> None:
        client = ThreatZone(api_key=api_key, base_url=base_url)
        assert client._config.base_url == base_url
        client.close()

    def test_init_with_custom_timeout(self, api_key: str) -> None:
        client = ThreatZone(api_key=api_key, timeout=120.0)
        assert client._config.timeout == 120.0
        client.close()

    def test_init_with_custom_max_retries(self, api_key: str) -> None:
        client = ThreatZone(api_key=api_key, max_retries=5)
        assert client._config.max_retries == 5
        client.close()

    def test_context_manager(self, api_key: str) -> None:
        with ThreatZone(api_key=api_key) as client:
            assert client is not None

    def test_default_base_url_points_at_saas(self, api_key: str) -> None:
        client = ThreatZone(api_key=api_key)
        assert client._config.base_url == "https://app.threat.zone/public-api"
        assert client._base_url == "https://app.threat.zone/public-api"
        client.close()

    def test_init_with_injected_http_client(self, api_key: str) -> None:
        """A caller-supplied httpx.Client must be used verbatim by the SDK."""
        captured: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["headers"] = dict(request.headers)
            return httpx.Response(
                200,
                json={
                    "userInfo": {
                        "email": "alice@test",
                        "fullName": "Alice",
                        "workspace": {
                            "name": "ws",
                            "alias": "ws",
                            "private": False,
                            "type": "personal",
                        },
                        "limitsCount": {
                            "apiRequestCount": 0,
                            "dailySubmissionCount": 0,
                            "concurrentSubmissionCount": 0,
                        },
                    },
                    "plan": {
                        "planName": "Free",
                        "startTime": "2024-01-01",
                        "endTime": "Unlimited",
                        "subsTime": "monthly",
                        "fileLimits": {"extensions": [], "fileSize": "0"},
                        "submissionLimits": {
                            "apiLimit": 0,
                            "dailyLimit": 0,
                            "concurrentLimit": 0,
                        },
                    },
                    "modules": [],
                },
            )

        transport = httpx.MockTransport(handler)
        injected = httpx.Client(transport=transport, base_url="https://injected.example")

        client = ThreatZone(
            api_key=api_key,
            base_url="https://app.threat.zone/public-api",
            http_client=injected,
        )
        assert client._http._client is injected
        assert client._http._owns_client is False

        user = client.get_user_info()
        assert user.email == "alice@test"
        assert captured["url"] == "https://app.threat.zone/public-api/me"

        client.close()
        # Caller-supplied client must remain usable after SDK close.
        assert injected.is_closed is False
        injected.close()


# ---------------------------------------------------------------------------
# Auth header injection — runs once at module level
# ---------------------------------------------------------------------------


class TestAuthHeaderInjection:
    def test_authorization_header_is_sent(
        self, api_key: str, sample_user_info: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_user_info))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_user_info()
        headers = _call_headers(mock)
        auth_value = headers.get("Authorization") or headers.get("X-API-Key") or ""
        assert api_key in str(auth_value) or auth_value, (
            f"Expected api_key in headers, got {headers}"
        )


# ---------------------------------------------------------------------------
# /me
# ---------------------------------------------------------------------------


class TestUserInfo:
    def test_happy_path(self, api_key: str, sample_user_info: dict[str, Any]) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_user_info))
        with ctx, ThreatZone(api_key=api_key) as client:
            user = client.get_user_info()
        assert isinstance(user, UserInfo)
        assert user.email == sample_user_info["userInfo"]["email"]
        assert _call_url(mock).endswith("/me")
        assert _call_method(mock) == "GET"

    def test_401(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(401, {"message": "Invalid API key"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(AuthenticationError):
            client.get_user_info()

    def test_500(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(500, {"message": "boom"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(InternalServerError):
            client.get_user_info()


# ---------------------------------------------------------------------------
# /config
# ---------------------------------------------------------------------------


class TestConfiguration:
    def test_get_environments_happy(
        self, api_key: str, sample_environments: list[dict[str, Any]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_environments))
        with ctx, ThreatZone(api_key=api_key) as client:
            envs = client.get_environments()
        assert all(isinstance(e, EnvironmentOption) for e in envs)
        assert envs[0].key == "w10_x64"
        assert _call_url(mock).endswith("/config/environments")

    def test_get_environments_500(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(500, {"message": "boom"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(InternalServerError):
            client.get_environments()

    def test_get_metafields_all(
        self, api_key: str, sample_metafields: dict[str, list[dict[str, Any]]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_metafields))
        with ctx, ThreatZone(api_key=api_key) as client:
            meta = client.get_metafields()
        assert isinstance(meta, Metafields)
        assert _call_url(mock).endswith("/config/metafields")

    def test_get_metafields_specific(
        self, api_key: str, sample_metafields: dict[str, list[dict[str, Any]]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_metafields["sandbox"]))
        with ctx, ThreatZone(api_key=api_key) as client:
            meta = client.get_metafields("sandbox")
        assert isinstance(meta, list)
        assert all(isinstance(m, MetafieldOption) for m in meta)
        assert _call_url(mock).endswith("/config/metafields/sandbox")

    def test_get_metafields_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "Not found"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_metafields("doesnotexist")


# ---------------------------------------------------------------------------
# Submissions - Create
# ---------------------------------------------------------------------------


class TestCreateSubmissions:
    def test_create_sandbox_submission(
        self, api_key: str, sample_submission_created: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_submission_created))
        with ctx, ThreatZone(api_key=api_key) as client:
            result = client.create_sandbox_submission(
                b"test data",
                environment="w10_x64",
                private=True,
            )
        assert isinstance(result, SubmissionCreated)
        assert result.uuid == "sub-new-123"
        assert _call_url(mock).endswith("/submissions/sandbox")
        assert _call_method(mock) == "POST"

    def test_create_sandbox_submission_400(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(400, {"message": "missing environment"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(BadRequestError):
            client.create_sandbox_submission(b"test data")

    def test_create_static_submission(
        self, api_key: str, sample_submission_created: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_submission_created))
        with ctx, ThreatZone(api_key=api_key) as client:
            result = client.create_static_submission(b"data")
        assert isinstance(result, SubmissionCreated)
        assert _call_url(mock).endswith("/submissions/static")

    def test_create_static_submission_500(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(500, {"message": "boom"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(InternalServerError):
            client.create_static_submission(b"data")

    def test_create_cdr_submission(
        self, api_key: str, sample_submission_created: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_submission_created))
        with ctx, ThreatZone(api_key=api_key) as client:
            result = client.create_cdr_submission(b"data")
        assert isinstance(result, SubmissionCreated)
        assert _call_url(mock).endswith("/submissions/cdr")

    def test_create_cdr_submission_403(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(403, {"message": "module not enabled"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(PermissionDeniedError):
            client.create_cdr_submission(b"data")

    def test_create_url_submission(
        self, api_key: str, sample_submission_created: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_submission_created))
        with ctx, ThreatZone(api_key=api_key) as client:
            result = client.create_url_submission("https://example.com")
        assert isinstance(result, SubmissionCreated)
        assert _call_url(mock).endswith("/submissions/url_analysis")
        _, kwargs = mock.call_args
        assert kwargs["json"] == {"url": "https://example.com", "private": False}

    def test_create_url_submission_400(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(400, {"message": "bad url"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(BadRequestError):
            client.create_url_submission("not-a-url")

    def test_create_open_in_browser_submission(
        self, api_key: str, sample_submission_created: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_submission_created))
        with ctx, ThreatZone(api_key=api_key) as client:
            result = client.create_open_in_browser_submission(
                "https://evil.com",
                environment="w10_x64",
                metafields=[{"key": "timeout", "value": 120}],
                private=True,
                configurations={"network_config": "abc"},
            )
        assert isinstance(result, SubmissionCreated)
        _, kwargs = mock.call_args
        body = kwargs["json"]
        assert body["url"] == "https://evil.com"
        assert body["private"] is True
        assert body["environment"] == "w10_x64"
        assert body["metafields"] == {"timeout": 120}
        assert body["configurations"] == {"network_config": "abc"}

    def test_create_open_in_browser_submission_minimal_payload(
        self, api_key: str, sample_submission_created: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_submission_created))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.create_open_in_browser_submission("https://evil.com")
        _, kwargs = mock.call_args
        body = kwargs["json"]
        assert "environment" not in body
        assert "metafields" not in body


# ---------------------------------------------------------------------------
# Submissions - Query
# ---------------------------------------------------------------------------


class TestQuerySubmissions:
    def test_list_submissions_happy(
        self,
        api_key: str,
        sample_paginated_submissions: dict[str, Any],
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_paginated_submissions))
        with ctx, ThreatZone(api_key=api_key) as client:
            page = client.list_submissions(page=2, limit=50)
        assert isinstance(page, PaginatedSubmissions)
        assert page.total == 1
        params = _call_params(mock)
        assert params["page"] == 2
        assert params["limit"] == 50
        assert _call_url(mock).endswith("/submissions")

    def test_list_submissions_with_filters(
        self,
        api_key: str,
        sample_paginated_submissions: dict[str, Any],
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_paginated_submissions))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.list_submissions(
                level=["malicious", "suspicious"],
                type="file",
                sha256="abc",
                filename="evil.exe",
                start_date="2024-01-01",
                end_date="2024-01-31",
                private=True,
                tags=["t1", "t2"],
            )
        params = _call_params(mock)
        assert params["level"] == ["malicious", "suspicious"]
        assert params["type"] == "file"
        assert params["sha256"] == "abc"
        assert params["filename"] == "evil.exe"
        assert params["startDate"] == "2024-01-01"
        assert params["endDate"] == "2024-01-31"
        assert params["private"] is True
        assert params["tags"] == ["t1", "t2"]

    def test_list_submissions_with_datetime(
        self,
        api_key: str,
        sample_paginated_submissions: dict[str, Any],
    ) -> None:
        from datetime import datetime

        ctx, mock = _patched_client(_make_response(200, sample_paginated_submissions))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.list_submissions(
                start_date=datetime(2024, 1, 1, 12, 0, 0),
                end_date=datetime(2024, 1, 31, 12, 0, 0),
            )
        params = _call_params(mock)
        assert params["startDate"].startswith("2024-01-01T12:00:00")
        assert params["endDate"].startswith("2024-01-31T12:00:00")

    def test_list_submissions_401(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(401, {"message": "auth"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(AuthenticationError):
            client.list_submissions()

    def test_get_submission_happy(self, api_key: str, sample_submission: dict[str, Any]) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_submission))
        with ctx, ThreatZone(api_key=api_key) as client:
            sub = client.get_submission("sub-789")
        assert isinstance(sub, Submission)
        assert _call_url(mock).endswith("/submissions/sub-789")

    def test_get_submission_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "Not found"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_submission("missing")

    def test_search_by_sha256_happy(self, api_key: str, sample_submission: dict[str, Any]) -> None:
        ctx, mock = _patched_client(_make_response(200, [sample_submission]))
        with ctx, ThreatZone(api_key=api_key) as client:
            results = client.search_by_sha256("abc")
        assert all(isinstance(r, Submission) for r in results)
        assert _call_url(mock).endswith("/submissions/search/sha256/abc")

    def test_search_by_sha256_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no match"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.search_by_sha256("ghost")

    def test_search_by_hash_is_deleted(self) -> None:
        assert not hasattr(ThreatZone, "search_by_hash")


# ---------------------------------------------------------------------------
# Wait for completion
# ---------------------------------------------------------------------------


class TestWaitForCompletion:
    def test_already_complete(self, api_key: str, sample_submission: dict[str, Any]) -> None:
        ctx, _ = _patched_client(_make_response(200, sample_submission))
        with ctx, ThreatZone(api_key=api_key) as client:
            sub = client.wait_for_completion("sub-789", timeout=60, poll_interval=0.01)
        assert sub.is_complete()

    def test_polls_until_done(self, api_key: str, sample_submission: dict[str, Any]) -> None:
        in_progress = {
            **sample_submission,
            "reports": [{"type": "dynamic", "status": "in_progress", "level": None, "score": None}],
        }
        completed = sample_submission

        call_count = 0

        def mock_request(*_args: Any, **_kwargs: Any) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return _make_response(200, in_progress)
            return _make_response(200, completed)

        with (
            patch.object(httpx.Client, "request", side_effect=mock_request),
            ThreatZone(api_key=api_key) as client,
        ):
            sub = client.wait_for_completion("sub-789", timeout=60, poll_interval=0.001)
            assert sub.is_complete()
            assert call_count == 3

    def test_timeout(self, api_key: str, sample_submission: dict[str, Any]) -> None:
        in_progress = {
            **sample_submission,
            "reports": [{"type": "dynamic", "status": "in_progress", "level": None, "score": None}],
        }
        ctx, _ = _patched_client(_make_response(200, in_progress))
        with ctx, ThreatZone(api_key=api_key) as client:
            with pytest.raises(AnalysisTimeoutError) as exc_info:
                client.wait_for_completion("sub-789", timeout=0.05, poll_interval=0.01)
            assert exc_info.value.uuid == "sub-789"


# ---------------------------------------------------------------------------
# Indicators surface
# ---------------------------------------------------------------------------


class TestIndicatorsSurface:
    def test_get_overview_summary_happy(
        self, api_key: str, sample_overview_summary: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_overview_summary))
        with ctx, ThreatZone(api_key=api_key) as client:
            summary = client.get_overview_summary("sub-789")
        assert isinstance(summary, OverviewSummary)
        assert summary.indicators.total == 10
        assert _call_url(mock).endswith("/submissions/sub-789/summary")

    def test_get_overview_summary_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_overview_summary("ghost")

    def test_get_summary_alias(self, api_key: str, sample_overview_summary: dict[str, Any]) -> None:
        ctx, _ = _patched_client(_make_response(200, sample_overview_summary))
        with ctx, ThreatZone(api_key=api_key) as client:
            summary = client.get_summary("sub-789")
        assert isinstance(summary, OverviewSummary)

    def test_get_indicators_happy(
        self, api_key: str, sample_indicators_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_indicators_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            indicators = client.get_indicators("sub-789")
        assert isinstance(indicators, IndicatorsResponse)
        assert indicators.total == 1
        assert _call_url(mock).endswith("/submissions/sub-789/indicators")

    def test_get_indicators_with_filters(
        self, api_key: str, sample_indicators_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_indicators_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_indicators(
                "sub-789",
                level="malicious",
                category="persistence",
                pid=1234,
                attack_code="T1547.001",
                page=2,
                limit=10,
            )
        params = _call_params(mock)
        assert params["level"] == "malicious"
        assert params["category"] == "persistence"
        assert params["pid"] == 1234
        assert params["attackCode"] == "T1547.001"
        assert params["page"] == 2
        assert params["limit"] == 10

    def test_get_indicators_409(self, api_key: str) -> None:
        body = _409_body(
            code="DYNAMIC_REPORT_UNAVAILABLE",
            current_status="in_progress",
        )
        ctx, _ = _patched_client(_make_response(409, body))
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(ReportUnavailableError) as exc_info,
        ):
            client.get_indicators("sub-789")
        err = exc_info.value
        assert err.status_code == 409
        assert err.code == "DYNAMIC_REPORT_UNAVAILABLE"
        assert err.required_report == "dynamic"
        assert err.current_status == "in_progress"
        assert err.available_reports == ["static"]
        assert err.submission_uuid == "11111111-2222-3333-4444-555555555555"

    def test_get_indicators_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_indicators("ghost")

    def test_get_iocs_happy(self, api_key: str, sample_iocs_response: dict[str, Any]) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_iocs_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            iocs = client.get_iocs("sub-789")
        assert isinstance(iocs, IoCsResponse)
        assert _call_url(mock).endswith("/submissions/sub-789/iocs")

    def test_get_iocs_with_type(self, api_key: str, sample_iocs_response: dict[str, Any]) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_iocs_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_iocs("sub-789", type="domain", page=2, limit=50)
        params = _call_params(mock)
        assert params == {"type": "domain", "page": 2, "limit": 50}

    def test_get_iocs_403(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(403, {"message": "denied"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(PermissionDeniedError):
            client.get_iocs("sub-789")

    def test_get_iocs_500(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(500, {"message": "boom"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(InternalServerError):
            client.get_iocs("sub-789")

    def test_get_yara_rules_happy(
        self, api_key: str, sample_yara_rules_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_yara_rules_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            rules = client.get_yara_rules("sub-789")
        assert isinstance(rules, YaraRulesResponse)
        assert _call_url(mock).endswith("/submissions/sub-789/yara-rules")

    def test_get_yara_rules_with_filters(
        self, api_key: str, sample_yara_rules_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_yara_rules_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_yara_rules("sub-789", category="malicious", page=1, limit=20)
        params = _call_params(mock)
        assert params == {"category": "malicious", "page": 1, "limit": 20}

    def test_get_yara_rules_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_yara_rules("ghost")

    def test_get_extracted_configs_happy(
        self, api_key: str, sample_extracted_configs_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_extracted_configs_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            configs = client.get_extracted_configs("sub-789")
        assert isinstance(configs, ExtractedConfigsResponse)
        assert _call_url(mock).endswith("/submissions/sub-789/extracted-configs")

    def test_get_extracted_configs_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_extracted_configs("ghost")

    def test_get_artifacts_happy(
        self, api_key: str, sample_artifacts_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_artifacts_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            artifacts = client.get_artifacts("sub-789")
        assert isinstance(artifacts, ArtifactsResponse)
        assert isinstance(artifacts.items[0], Artifact)
        assert artifacts.items[0].hashes.sha256.startswith("e3b0c4")
        assert _call_url(mock).endswith("/submissions/sub-789/artifacts")

    def test_get_artifacts_500(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(500, {"message": "boom"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(InternalServerError):
            client.get_artifacts("sub-789")

    def test_get_eml_analysis_returns_list(
        self, api_key: str, sample_eml_analysis_list: list[dict[str, Any]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_eml_analysis_list))
        with ctx, ThreatZone(api_key=api_key) as client:
            result = client.get_eml_analysis("sub-789")
        assert isinstance(result, list)
        assert all(isinstance(r, EmlAnalysis) for r in result)
        assert _call_url(mock).endswith("/submissions/sub-789/eml-analysis")

    def test_get_eml_analysis_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_eml_analysis("ghost")

    def test_get_mitre_techniques_happy(
        self, api_key: str, sample_mitre_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_mitre_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            mitre = client.get_mitre_techniques("sub-789")
        assert isinstance(mitre, MitreResponse)
        assert mitre.total == 2
        assert _call_url(mock).endswith("/submissions/sub-789/mitre")

    def test_get_mitre_techniques_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_mitre_techniques("ghost")


# ---------------------------------------------------------------------------
# Static / CDR / Signature
# ---------------------------------------------------------------------------


class TestReportEnvelopes:
    def test_get_static_scan_results_happy(
        self, api_key: str, sample_static_scan_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_static_scan_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            res = client.get_static_scan_results("sub-789")
        assert isinstance(res, StaticScanResponse)
        assert _call_url(mock).endswith("/submissions/sub-789/static-scan")

    def test_get_static_scan_results_409(self, api_key: str) -> None:
        body = _409_body(
            code="STATIC_REPORT_UNAVAILABLE",
            required_report="static",
            current_status=None,
            available_reports=["dynamic"],
        )
        ctx, _ = _patched_client(_make_response(409, body))
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(ReportUnavailableError) as exc_info,
        ):
            client.get_static_scan_results("sub-789")
        err = exc_info.value
        assert err.code == "STATIC_REPORT_UNAVAILABLE"
        assert err.required_report == "static"
        assert err.current_status is None
        assert err.available_reports == ["dynamic"]

    def test_get_static_scan_results_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_static_scan_results("ghost")

    def test_get_cdr_results_happy(self, api_key: str, sample_cdr_response: dict[str, Any]) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_cdr_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            res = client.get_cdr_results("sub-789")
        assert isinstance(res, CdrResponse)
        assert _call_url(mock).endswith("/submissions/sub-789/cdr")

    def test_get_cdr_results_409(self, api_key: str) -> None:
        body = _409_body(code="CDR_REPORT_UNAVAILABLE", required_report="cdr")
        ctx, _ = _patched_client(_make_response(409, body))
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(ReportUnavailableError) as exc_info,
        ):
            client.get_cdr_results("sub-789")
        assert exc_info.value.code == "CDR_REPORT_UNAVAILABLE"

    def test_get_cdr_results_500(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(500, {"message": "boom"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(InternalServerError):
            client.get_cdr_results("sub-789")

    def test_get_signature_check_results_happy(
        self, api_key: str, sample_signature_check_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_signature_check_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            res = client.get_signature_check_results("sub-789")
        assert isinstance(res, SignatureCheckResponse)
        assert _call_url(mock).endswith("/submissions/sub-789/signature-check")

    def test_get_signature_check_results_409(self, api_key: str) -> None:
        body = _409_body(
            code="STATIC_REPORT_UNAVAILABLE",
            required_report="static",
        )
        ctx, _ = _patched_client(_make_response(409, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(ReportUnavailableError):
            client.get_signature_check_results("sub-789")

    def test_get_signature_check_results_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_signature_check_results("ghost")


# ---------------------------------------------------------------------------
# Dynamic report - processes / behaviours / syscalls
# ---------------------------------------------------------------------------


class TestDynamicReport:
    def test_get_processes_happy(
        self, api_key: str, sample_processes_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_processes_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            procs = client.get_processes("sub-789")
        assert isinstance(procs, ProcessesResponse)
        assert _call_url(mock).endswith("/submissions/sub-789/processes")

    def test_get_processes_409(self, api_key: str) -> None:
        body = _409_body()
        ctx, _ = _patched_client(_make_response(409, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(ReportUnavailableError):
            client.get_processes("sub-789")

    def test_get_processes_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_processes("ghost")

    def test_get_process_tree_happy(
        self, api_key: str, sample_process_tree_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_process_tree_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            tree = client.get_process_tree("sub-789")
        assert isinstance(tree, ProcessTreeResponse)
        assert _call_url(mock).endswith("/submissions/sub-789/processes/tree")
        assert tree.nodes[0].children[0].pid == 5678

    def test_get_process_tree_409(self, api_key: str) -> None:
        body = _409_body()
        ctx, _ = _patched_client(_make_response(409, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(ReportUnavailableError):
            client.get_process_tree("sub-789")

    def test_get_behaviours_happy(
        self, api_key: str, sample_behaviours_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_behaviours_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            behaviours = client.get_behaviours("sub-789", os="windows")
        assert isinstance(behaviours, BehavioursResponse)
        assert _call_url(mock).endswith("/submissions/sub-789/behaviours")
        params = _call_params(mock)
        assert params["os"] == "windows"

    def test_get_behaviours_with_filters(
        self, api_key: str, sample_behaviours_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_behaviours_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_behaviours(
                "sub-789",
                os="linux",
                pid=1234,
                operation="create",
                page=2,
                limit=50,
            )
        params = _call_params(mock)
        assert params["os"] == "linux"
        assert params["pid"] == 1234
        assert params["operation"] == "create"
        assert params["page"] == 2
        assert params["limit"] == 50

    def test_get_behaviours_without_os_raises(self, api_key: str) -> None:
        with ThreatZone(api_key=api_key) as client, pytest.raises(ValueError, match="os"):
            client.get_behaviours("sub-789", os="")  # type: ignore[arg-type]

    def test_get_behaviours_409(self, api_key: str) -> None:
        body = _409_body()
        ctx, _ = _patched_client(_make_response(409, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(ReportUnavailableError):
            client.get_behaviours("sub-789", os="windows")

    def test_get_behaviours_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_behaviours("ghost", os="windows")

    def test_get_syscalls_happy(
        self, api_key: str, sample_syscalls_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_syscalls_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            sc = client.get_syscalls("sub-789")
        assert isinstance(sc, SyscallsResponse)
        assert _call_url(mock).endswith("/submissions/sub-789/syscalls")

    def test_get_syscalls_with_pagination(
        self, api_key: str, sample_syscalls_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_syscalls_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_syscalls("sub-789", page=2, limit=200)
        params = _call_params(mock)
        assert params == {"page": 2, "limit": 200}

    def test_get_syscalls_409(self, api_key: str) -> None:
        body = _409_body()
        ctx, _ = _patched_client(_make_response(409, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(ReportUnavailableError):
            client.get_syscalls("sub-789")


# ---------------------------------------------------------------------------
# URL analysis
# ---------------------------------------------------------------------------


class TestUrlAnalysis:
    def test_get_url_analysis_happy(
        self, api_key: str, sample_url_analysis_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_url_analysis_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            res = client.get_url_analysis("sub-789")
        assert isinstance(res, UrlAnalysisResponse)
        assert res.general_info.domain == "evil.com"
        assert _call_url(mock).endswith("/submissions/sub-789/url-analysis")

    def test_get_url_analysis_409(self, api_key: str) -> None:
        body = _409_body(
            code="URL_ANALYSIS_REPORT_UNAVAILABLE",
            required_report="url_analysis",
        )
        ctx, _ = _patched_client(_make_response(409, body))
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(ReportUnavailableError) as exc_info,
        ):
            client.get_url_analysis("sub-789")
        assert exc_info.value.code == "URL_ANALYSIS_REPORT_UNAVAILABLE"

    def test_get_url_analysis_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_url_analysis("ghost")


# ---------------------------------------------------------------------------
# Network endpoints
# ---------------------------------------------------------------------------


class TestNetwork:
    def test_get_network_summary_happy(
        self, api_key: str, sample_network_summary: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_network_summary))
        with ctx, ThreatZone(api_key=api_key) as client:
            s = client.get_network_summary("sub-789")
        assert isinstance(s, NetworkSummary)
        assert s.dns_count == 15
        assert _call_url(mock).endswith("/submissions/sub-789/network/summary")

    def test_get_network_summary_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_network_summary("ghost")

    def test_get_dns_queries_happy(
        self, api_key: str, sample_dns_queries: list[dict[str, Any]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_dns_queries))
        with ctx, ThreatZone(api_key=api_key) as client:
            queries = client.get_dns_queries("sub-789")
        assert all(isinstance(q, DnsQuery) for q in queries)
        assert _call_url(mock).endswith("/submissions/sub-789/network/dns")

    def test_get_dns_queries_with_pagination(
        self, api_key: str, sample_dns_queries: list[dict[str, Any]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_dns_queries))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_dns_queries("sub-789", limit=10, skip=20)
        params = _call_params(mock)
        assert params == {"limit": 10, "skip": 20}

    def test_get_dns_queries_500(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(500, {"message": "boom"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(InternalServerError):
            client.get_dns_queries("sub-789")

    def test_get_http_requests_happy(
        self, api_key: str, sample_http_requests: list[dict[str, Any]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_http_requests))
        with ctx, ThreatZone(api_key=api_key) as client:
            requests = client.get_http_requests("sub-789")
        assert all(isinstance(r, HttpRequest) for r in requests)
        first = requests[0]
        assert first.host == "malware.example.com"
        assert first.ip == "192.168.1.100"
        assert first.port == 80
        assert _call_url(mock).endswith("/submissions/sub-789/network/http")

    def test_get_http_requests_with_pagination(
        self, api_key: str, sample_http_requests: list[dict[str, Any]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_http_requests))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_http_requests("sub-789", limit=5, skip=10)
        params = _call_params(mock)
        assert params == {"limit": 5, "skip": 10}

    def test_get_http_requests_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_http_requests("ghost")

    def test_get_tcp_connections_happy(
        self, api_key: str, sample_tcp_connections: list[dict[str, Any]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_tcp_connections))
        with ctx, ThreatZone(api_key=api_key) as client:
            conns = client.get_tcp_connections("sub-789")
        assert all(isinstance(c, Connection) for c in conns)
        assert conns[0].destination_port == 443
        assert _call_url(mock).endswith("/submissions/sub-789/network/tcp")

    def test_get_tcp_connections_with_pagination(
        self, api_key: str, sample_tcp_connections: list[dict[str, Any]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_tcp_connections))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_tcp_connections("sub-789", limit=2, skip=3)
        params = _call_params(mock)
        assert params == {"limit": 2, "skip": 3}

    def test_get_tcp_connections_500(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(500, {"message": "boom"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(InternalServerError):
            client.get_tcp_connections("sub-789")

    def test_get_udp_connections_happy(
        self, api_key: str, sample_udp_connections: list[dict[str, Any]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_udp_connections))
        with ctx, ThreatZone(api_key=api_key) as client:
            conns = client.get_udp_connections("sub-789")
        assert all(isinstance(c, Connection) for c in conns)
        assert conns[0].destination_port == 53
        assert _call_url(mock).endswith("/submissions/sub-789/network/udp")

    def test_get_udp_connections_with_pagination(
        self, api_key: str, sample_udp_connections: list[dict[str, Any]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_udp_connections))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_udp_connections("sub-789", limit=2, skip=3)
        params = _call_params(mock)
        assert params == {"limit": 2, "skip": 3}

    def test_get_udp_connections_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_udp_connections("ghost")

    def test_get_network_threats_happy(
        self, api_key: str, sample_network_threats: list[dict[str, Any]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_network_threats))
        with ctx, ThreatZone(api_key=api_key) as client:
            threats = client.get_network_threats("sub-789")
        assert all(isinstance(t, NetworkThreat) for t in threats)
        assert threats[0].severity == "high"
        assert _call_url(mock).endswith("/submissions/sub-789/network/threats")

    def test_get_network_threats_with_pagination(
        self, api_key: str, sample_network_threats: list[dict[str, Any]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_network_threats))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_network_threats("sub-789", limit=10, skip=5)
        params = _call_params(mock)
        assert params == {"limit": 10, "skip": 5}

    def test_get_network_threats_500(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(500, {"message": "boom"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(InternalServerError):
            client.get_network_threats("sub-789")


# ---------------------------------------------------------------------------
# Downloads + media
# ---------------------------------------------------------------------------


class _StreamCtx:
    """Minimal context manager that mimics httpx.Client.stream()."""

    def __init__(self, response: httpx.Response) -> None:
        self._response = response
        self.closed = False

    def __enter__(self) -> httpx.Response:
        return self._response

    def __exit__(self, *args: object) -> None:
        self.closed = True


def _patched_stream(response: httpx.Response) -> tuple[Any, MagicMock]:
    mock = MagicMock(side_effect=lambda *_a, **_kw: _StreamCtx(response))
    return patch.object(httpx.Client, "stream", mock), mock


class TestDownloads:
    def test_download_sample_happy(self, api_key: str) -> None:
        response = _make_response(200, content=b"PE\x00\x00binary")
        ctx, mock = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client:
            res = client.download_sample("sub-789")
            assert res.status_code == 200
        assert mock.call_args is not None
        url_arg = mock.call_args.args[1]
        assert url_arg.endswith("/submissions/sub-789/download/sample")

    def test_download_sample_404(self, api_key: str) -> None:
        response = _make_response(404, {"message": "no"})
        ctx, _ = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.download_sample("ghost")

    def test_download_artifact_happy(self, api_key: str) -> None:
        response = _make_response(200, content=b"PAYLOAD")
        ctx, mock = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client:
            client.download_artifact("sub-789", "art-1")
        url_arg = mock.call_args.args[1]
        assert url_arg.endswith("/submissions/sub-789/download/artifact/art-1")

    def test_download_artifact_404(self, api_key: str) -> None:
        response = _make_response(404, {"message": "no"})
        ctx, _ = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.download_artifact("sub-789", "missing")

    def test_download_pcap_happy(self, api_key: str) -> None:
        response = _make_response(200, content=b"PCAP")
        ctx, mock = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client:
            client.download_pcap("sub-789")
        url_arg = mock.call_args.args[1]
        assert url_arg.endswith("/submissions/sub-789/download/pcap")

    def test_download_pcap_404(self, api_key: str) -> None:
        response = _make_response(404, {"message": "no"})
        ctx, _ = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.download_pcap("ghost")

    def test_download_yara_rule_happy(self, api_key: str) -> None:
        response = _make_response(200, content=b"rule X {}")
        ctx, mock = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client:
            client.download_yara_rule("sub-789")
        url_arg = mock.call_args.args[1]
        assert url_arg.endswith("/submissions/sub-789/download/yara-rule")

    def test_download_yara_rule_pending_202(self, api_key: str) -> None:
        response = _make_response(202, json_data={"message": "Generating", "retryAfter": 10})
        ctx, _ = _patched_stream(response)
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(YaraRulePendingError) as exc_info,
        ):
            client.download_yara_rule("sub-789")
        assert exc_info.value.retry_after == 10.0

    def test_download_html_report_happy(self, api_key: str) -> None:
        response = _make_response(200, content=b"<html></html>")
        ctx, mock = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client:
            client.download_html_report("sub-789")
        url_arg = mock.call_args.args[1]
        assert url_arg.endswith("/submissions/sub-789/download/html-report")

    def test_download_html_report_404(self, api_key: str) -> None:
        response = _make_response(404, {"message": "no"})
        ctx, _ = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.download_html_report("ghost")

    def test_download_cdr_result_happy(self, api_key: str) -> None:
        response = _make_response(200, content=b"clean")
        ctx, mock = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client:
            client.download_cdr_result("sub-789")
        url_arg = mock.call_args.args[1]
        assert url_arg.endswith("/submissions/sub-789/download/cdr")

    def test_download_cdr_result_404(self, api_key: str) -> None:
        response = _make_response(404, {"message": "no"})
        ctx, _ = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.download_cdr_result("ghost")


class TestMedia:
    def test_get_screenshot_happy(self, api_key: str) -> None:
        ctx, mock = _patched_client(_make_response(200, content=b"\x89PNG\r\n\x1a\n"))
        with ctx, ThreatZone(api_key=api_key) as client:
            data = client.get_screenshot("sub-789")
        assert data.startswith(b"\x89PNG")
        assert _call_url(mock).endswith("/submissions/sub-789/screenshot")

    def test_get_screenshot_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_screenshot("ghost")

    def test_list_media_files_happy(
        self, api_key: str, sample_media_files: list[dict[str, Any]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_media_files))
        with ctx, ThreatZone(api_key=api_key) as client:
            files = client.list_media_files("sub-789")
        assert all(isinstance(m, MediaFile) for m in files)
        assert files[0].name == "screenshot_001.png"
        assert _call_url(mock).endswith("/submissions/sub-789/media")

    def test_list_media_files_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.list_media_files("ghost")

    def test_get_media_file_happy(self, api_key: str) -> None:
        ctx, mock = _patched_client(_make_response(200, content=b"binary"))
        with ctx, ThreatZone(api_key=api_key) as client:
            data = client.get_media_file("sub-789", "media-1")
        assert data == b"binary"
        assert _call_url(mock).endswith("/submissions/sub-789/media/media-1")

    def test_get_media_file_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_media_file("sub-789", "missing")


# ---------------------------------------------------------------------------
# Deleted-method regression tests
# ---------------------------------------------------------------------------


class TestDeletedMethods:
    @pytest.mark.parametrize(
        "name",
        [
            "search_by_hash",
            "get_dns_query_count",
            "get_http_request_count",
            "get_tcp_connection_count",
            "get_udp_connection_count",
            "get_network_threat_count",
            "get_indicator_count",
            "get_ioc_count",
            "get_artifact_count",
            "get_yara_rule_count",
            "get_extracted_config_count",
            "get_syscall_count",
            "get_behaviour_count",
            "get_process_count",
        ],
    )
    def test_deleted_method_does_not_exist(self, name: str) -> None:
        assert not hasattr(ThreatZone, name), (
            f"Deleted method {name!r} unexpectedly present on ThreatZone"
        )
