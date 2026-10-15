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
from typing import Any, Literal
from unittest.mock import MagicMock, patch

import httpx
import pytest

from threatzone import ThreatZone
from threatzone._exceptions import (
    AnalysisTimeoutError,
    AuthenticationError,
    BadRequestError,
    BehaviourIndexingError,
    BehaviourTooLargeError,
    BehaviourUnreadableError,
    InternalServerError,
    NotFoundError,
    PdfReportPendingError,
    PermissionDeniedError,
    RateLimitError,
    ReportUnavailableError,
    YaraRulePendingError,
)
from threatzone.types import (
    AiReport,
    AiReportPending,
    AiReportRegenerateResult,
    Annotations,
    Artifact,
    ArtifactJob,
    ArtifactsResponse,
    BehaviourFacets,
    BehavioursResponse,
    BehaviourSummary,
    CdrResponse,
    Connection,
    DevicePresetOption,
    DnsQuery,
    EmlAnalysis,
    EnvironmentOption,
    ExtractedConfigsResponse,
    HttpRequest,
    IndicatorsResponse,
    IoCsResponse,
    Killchain,
    MediaFile,
    Message,
    MetafieldOption,
    Metafields,
    MitreResponse,
    NetworkConfigListItem,
    NetworkEndpoints,
    NetworkExfilRequest,
    NetworkFlowPackets,
    NetworkHostFlows,
    NetworkHttpPackets,
    NetworkSummary,
    NetworkThreat,
    OverviewSummary,
    PaginatedSubmissions,
    PdfReportStatus,
    PreviousRun,
    ProcessesResponse,
    ProcessTreeResponse,
    RunComparison,
    RunNotes,
    SignatureCheckResponse,
    StaticScanResponse,
    StringFacts,
    StringsPage,
    Submission,
    SubmissionCreated,
    SyscallSearchResult,
    SyscallsResponse,
    TotalCountList,
    UrlAnalysisBrowserSection,
    UrlAnalysisIndicatorEvidence,
    UrlAnalysisIndicators,
    UrlAnalysisResponse,
    UrlAnalysisSession,
    UserInfo,
    Verdict,
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
        assert user.plan_permissions is not None
        assert user.plan_permissions.stix_report is False
        assert user.ai_report_resets_at is not None

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

    def test_list_network_configs_happy(
        self, api_key: str, sample_network_config: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, {"items": [sample_network_config]}))
        with ctx, ThreatZone(api_key=api_key) as client:
            configs = client.list_network_configs()
        assert all(isinstance(c, NetworkConfigListItem) for c in configs)
        assert configs[0].id == "cfg1"
        assert configs[0].has_config_file is False
        assert _call_url(mock).endswith("/v1/network-configs")

    def test_list_network_configs_empty(self, api_key: str) -> None:
        ctx, mock = _patched_client(_make_response(200, {"items": []}))
        with ctx, ThreatZone(api_key=api_key) as client:
            configs = client.list_network_configs()
        assert configs == []
        assert _call_url(mock).endswith("/v1/network-configs")

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


class TestDevicePresets:
    def test_get_device_presets(
        self, api_key: str, device_presets_payload: list[dict[str, Any]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, device_presets_payload))
        with ctx, ThreatZone(api_key=api_key) as client:
            presets = client.get_device_presets()
        assert all(isinstance(p, DevicePresetOption) for p in presets)
        assert [p.id for p in presets] == [
            "68b0000000000000000000a2",
            "68b0000000000000000000a1",
        ]
        assert presets[0].default is True
        assert presets[1].base_key == "iphone-15-pro"
        assert _call_url(mock).endswith("/config/device-presets")

    def test_get_device_presets_403(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(403, {"message": "no plan"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(PermissionDeniedError):
            client.get_device_presets()


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
        assert kwargs["json"] == {
            "url": "https://example.com",
            "private": False,
            "safeBrowsing": False,
        }

    def test_create_url_submission_400(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(400, {"message": "bad url"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(BadRequestError):
            client.create_url_submission("not-a-url")

    def test_create_url_submission_sends_safe_browsing(
        self, api_key: str, sample_submission_created: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_submission_created))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.create_url_submission("https://example.com", private=True, safe_browsing=True)
        _, kwargs = mock.call_args
        assert kwargs["json"] == {
            "url": "https://example.com",
            "private": True,
            "safeBrowsing": True,
        }

    def test_create_url_submission_safe_browsing_defaults_false(
        self, api_key: str, sample_submission_created: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_submission_created))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.create_url_submission("https://example.com")
        _, kwargs = mock.call_args
        assert kwargs["json"]["safeBrowsing"] is False

    def test_create_url_submission_sends_metafields_and_configurations(
        self, api_key: str, sample_submission_created: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_submission_created))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.create_url_submission(
                "https://example.com",
                metafields={"timeout": 240, "device_preset": "68b0000000000000000000a1"},
                configurations={
                    "networkConfig": "68b0000000000000000000bb",
                    "sessionDurationSeconds": 240,
                },
            )
        _, kwargs = mock.call_args
        assert kwargs["json"]["metafields"] == {
            "timeout": 240,
            "device_preset": "68b0000000000000000000a1",
        }
        assert kwargs["json"]["configurations"]["sessionDurationSeconds"] == 240
        assert kwargs["json"]["configurations"]["networkConfig"] == "68b0000000000000000000bb"

    def test_create_url_submission_omits_absent_option_blocks(
        self, api_key: str, sample_submission_created: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_submission_created))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.create_url_submission("https://example.com")
        _, kwargs = mock.call_args
        assert "metafields" not in kwargs["json"]
        assert "configurations" not in kwargs["json"]

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

    def test_create_sandbox_submission_sends_auto_select_environment_when_true(
        self, api_key: str, sample_submission_created: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_submission_created))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.create_sandbox_submission(
                b"fake-bytes",
                auto_select_environment=True,
            )
        _, kwargs = mock.call_args
        data = kwargs.get("data") or {}
        assert data.get("autoSelectEnvironment") == "true"

    def test_create_sandbox_submission_omits_auto_select_when_false(
        self, api_key: str, sample_submission_created: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_submission_created))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.create_sandbox_submission(b"fake-bytes")
        _, kwargs = mock.call_args
        data = kwargs.get("data") or {}
        assert "autoSelectEnvironment" not in data

    def test_create_open_in_browser_submission_sends_auto_select_environment(
        self, api_key: str, sample_submission_created: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_submission_created))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.create_open_in_browser_submission(
                "https://example.com",
                auto_select_environment=True,
            )
        _, kwargs = mock.call_args
        body = kwargs["json"]
        assert body.get("autoSelectEnvironment") is True


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

    def test_list_submissions_sends_sort_order(
        self,
        api_key: str,
        sample_paginated_submissions: dict[str, Any],
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_paginated_submissions))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.list_submissions(sort="createdAt", order="asc")
        params = _call_params(mock)
        assert params["sort"] == "createdAt"
        assert params["order"] == "asc"

    def test_list_submissions_omits_sort_order_when_none(
        self,
        api_key: str,
        sample_paginated_submissions: dict[str, Any],
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_paginated_submissions))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.list_submissions()
        params = _call_params(mock)
        assert "sort" not in params
        assert "order" not in params

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

    def test_get_submission_detail_fields(
        self, api_key: str, sample_submission_detail: dict[str, Any]
    ) -> None:
        ctx, _ = _patched_client(_make_response(200, sample_submission_detail))
        with ctx, ThreatZone(api_key=api_key) as client:
            sub = client.get_submission("sub-789")
        assert sub.score_breakdown is not None
        assert sub.score_breakdown.deciding_layer == "indicator_mean"
        assert sub.overview.duration == 42.7
        assert sub.file is not None
        assert sub.file.history is not None
        assert sub.reports[0].metafields is not None
        assert sub.tags[0].author == "system"

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

    def test_get_artifacts_sends_no_source_by_default(
        self, api_key: str, sample_artifacts_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_artifacts_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_artifacts("sub-789")
        assert _call_params(mock) == {}

    def test_get_artifacts_with_source(
        self, api_key: str, sample_artifact_v2: dict[str, Any]
    ) -> None:
        body = {"items": [sample_artifact_v2], "total": 1}
        ctx, mock = _patched_client(_make_response(200, body))
        with ctx, ThreatZone(api_key=api_key) as client:
            artifacts = client.get_artifacts("sub-789", source="dynamic_report")
        assert _call_params(mock) == {"source": "dynamic_report"}
        assert artifacts.items[0].analysis_status == "skipped"
        assert artifacts.items[0].download_link is not None

    def test_get_artifacts_unknown_source_400(self, api_key: str) -> None:
        body = {
            "statusCode": 400,
            "error": "Bad Request",
            "message": "source must be one of the following values",
            "code": "INVALID_QUERY_PARAM",
        }
        ctx, _ = _patched_client(_make_response(400, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(BadRequestError):
            client.get_artifacts("sub-789", source="nope")

    def test_get_artifact_jobs_happy(
        self, api_key: str, sample_artifact_jobs_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_artifact_jobs_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            jobs = client.get_artifact_jobs("sub-789", "507f1f77bcf86cd799439015")
        assert all(isinstance(job, ArtifactJob) for job in jobs)
        assert [job.error_code for job in jobs] == [None, "JOB_DEAD_LETTERED", "JOB_SKIPPED"]
        assert _call_method(mock) == "GET"
        assert _call_url(mock).endswith(
            "/submissions/sub-789/artifacts/507f1f77bcf86cd799439015/jobs"
        )

    def test_get_artifact_jobs_empty(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(200, {"items": []}))
        with ctx, ThreatZone(api_key=api_key) as client:
            assert client.get_artifact_jobs("sub-789", "507f1f77bcf86cd799439015") == []

    def test_get_artifact_jobs_404(self, api_key: str) -> None:
        body = {
            "statusCode": 404,
            "error": "Not Found",
            "message": "Artifact not found for the given submission.",
            "code": "ARTIFACT_NOT_FOUND",
        }
        ctx, _ = _patched_client(_make_response(404, body))
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(NotFoundError) as exc_info,
        ):
            client.get_artifact_jobs("sub-789", "507f1f77bcf86cd799439015")
        assert exc_info.value.body is not None
        assert exc_info.value.body["code"] == "ARTIFACT_NOT_FOUND"

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

    def test_get_mitre_techniques_items(
        self, api_key: str, sample_mitre_response_with_items: dict[str, Any]
    ) -> None:
        ctx, _ = _patched_client(_make_response(200, sample_mitre_response_with_items))
        with ctx, ThreatZone(api_key=api_key) as client:
            mitre = client.get_mitre_techniques("sub-789")
        assert mitre.items is not None
        assert [item.technique_id for item in mitre.items] == ["T1055", "T1547.001"]
        assert mitre.items[0].indicator_ids == [
            "665f1c2e9b1d4a0012ab34cd",
            "665f1c2e9b1d4a0012ab34ce",
        ]

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
        assert res.report_format == "exe"
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

    def test_get_cdr_results_nested_details(
        self, api_key: str, sample_cdr_nested_response: dict[str, Any]
    ) -> None:
        ctx, _ = _patched_client(_make_response(200, sample_cdr_nested_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            res = client.get_cdr_results("sub-789")
        assert res.sanitized_file_info is not None
        [member] = res.sanitized_file_info.details
        assert member.file_name == "invoice.docx"
        assert member.details[0].name == "Macros"

    def test_get_static_scan_string_facts_happy(
        self, api_key: str, sample_string_facts: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_string_facts))
        with ctx, ThreatZone(api_key=api_key) as client:
            res = client.get_static_scan_string_facts("sub-789")
        assert isinstance(res, StringFacts)
        assert res.observables[0].secret is True
        assert res.observables[0].display == sample_string_facts["observables"][0]["value"]
        assert _call_url(mock).endswith("/submissions/sub-789/static-scan/string-facts")

    def test_get_static_scan_string_facts_409(self, api_key: str) -> None:
        body = _409_body(code="STATIC_REPORT_UNAVAILABLE", required_report="static")
        ctx, _ = _patched_client(_make_response(409, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(ReportUnavailableError):
            client.get_static_scan_string_facts("sub-789")

    def test_get_static_scan_string_facts_429(self, api_key: str) -> None:
        ctx, _ = _patched_client(
            _make_response(429, {"message": "Too Many Requests"}, headers={"Retry-After": "12"})
        )
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(RateLimitError):
            client.get_static_scan_string_facts("sub-789")

    def test_get_static_scan_strings_page_params(
        self, api_key: str, sample_strings_page: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_strings_page))
        with ctx, ThreatZone(api_key=api_key) as client:
            res = client.get_static_scan_strings_page("sub-789", start=0, end=2, search="kernel")
        assert isinstance(res, StringsPage)
        assert res.items_count == 1423
        assert res.items[0].from_source == "ascii"
        assert _call_url(mock).endswith("/submissions/sub-789/static-scan/strings/items")
        assert _call_params(mock) == {"start": 0, "end": 2, "search": "kernel"}

    def test_get_static_scan_strings_page_defaults(
        self, api_key: str, sample_strings_page: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_strings_page))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_static_scan_strings_page("sub-789")
        assert _call_params(mock) == {}

    def test_get_static_scan_strings_page_400(self, api_key: str) -> None:
        ctx, _ = _patched_client(
            _make_response(400, {"message": "bad window", "code": "INVALID_QUERY_PARAM"})
        )
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(BadRequestError):
            client.get_static_scan_strings_page("sub-789", start=0, end=5000)

    def test_get_static_scan_strings_page_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no", "code": "NOT_FOUND"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_static_scan_strings_page("sub-789")

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

    def test_get_killchain_happy(self, api_key: str, sample_killchain: dict[str, Any]) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_killchain))
        with ctx, ThreatZone(api_key=api_key) as client:
            killchain = client.get_killchain("sub-789")
        assert isinstance(killchain, Killchain)
        assert _call_url(mock).endswith("/submissions/sub-789/killchain")
        assert killchain.dropped_files[0].files[0].artifact_id == "65f0aa000000000000000001"
        assert killchain.mem_dumps[0].regions[0].dumps[0].file_size == 4096

    def test_get_killchain_409(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(409, _409_body()))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(ReportUnavailableError):
            client.get_killchain("sub-789")

    def test_get_killchain_rate_limited(self, api_key: str) -> None:
        response = _make_response(
            429,
            {"statusCode": 429, "message": "Heavy route rate limit exceeded", "retryAfter": 12},
            headers={"Retry-After": "12"},
        )
        ctx, _ = _patched_client(response)
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(RateLimitError) as exc_info,
        ):
            client.get_killchain("sub-789")
        assert exc_info.value.retry_after == 12.0

    def test_get_behaviours_happy(
        self, api_key: str, sample_behaviours_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_behaviours_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            behaviours = client.get_behaviours("sub-789")
        assert isinstance(behaviours, BehavioursResponse)
        assert _call_url(mock).endswith("/submissions/sub-789/behaviours")
        params = _call_params(mock)
        assert "os" not in params

    def test_get_behaviours_with_filters(
        self, api_key: str, sample_behaviours_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_behaviours_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_behaviours(
                "sub-789",
                pid=1234,
                operation="create",
                page=2,
                limit=50,
            )
        params = _call_params(mock)
        assert "os" not in params
        assert params["pid"] == 1234
        assert params["operation"] == "create"
        assert params["page"] == 2
        assert params["limit"] == 50

    def test_get_behaviours_sends_type_and_process_name(
        self, api_key: str, sample_behaviours_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_behaviours_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_behaviours(
                "sub-789",
                type="registry",
                process_name="cmd.exe",
            )
        params = _call_params(mock)
        assert "os" not in params
        assert params["type"] == "registry"
        assert params["processName"] == "cmd.exe"

    def test_get_behaviours_omits_type_and_process_name_when_none(
        self, api_key: str, sample_behaviours_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_behaviours_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_behaviours("sub-789")
        params = _call_params(mock)
        assert "os" not in params
        assert "type" not in params
        assert "processName" not in params

    def test_get_behaviours_409(self, api_key: str) -> None:
        body = _409_body()
        ctx, _ = _patched_client(_make_response(409, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(ReportUnavailableError):
            client.get_behaviours("sub-789")

    def test_get_behaviours_404(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(404, {"message": "no"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_behaviours("ghost")

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


class TestBehaviourIndexAndSyscallSearch:
    def test_get_behaviours_sends_a_single_text_filter_unchanged(
        self, api_key: str, sample_indexed_behaviours_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_indexed_behaviours_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_behaviours("sub-789", types="file", operations=["RegSetValue"])
        assert _call_params(mock) == {"types": "file", "operations": "RegSetValue"}

    def test_get_behaviours_refuses_an_empty_list_filter(self, api_key: str) -> None:
        ctx, mock = _patched_client(_make_response(200, {}))
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(ValueError, match="event_ids must not be empty"),
        ):
            client.get_behaviours("sub-789", event_ids=[])
        mock.assert_not_called()

    def test_get_behaviours_refuses_an_empty_string_filter(self, api_key: str) -> None:
        ctx, mock = _patched_client(_make_response(200, {}))
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(ValueError, match="types must not be empty"),
        ):
            client.get_behaviours("sub-789", types="")
        mock.assert_not_called()

    def test_get_behaviours_sends_every_index_filter(
        self, api_key: str, sample_indexed_behaviours_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_indexed_behaviours_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            resp = client.get_behaviours(
                "sub-789",
                event_ids=[1024, 1025],
                pids=[1508, 2044],
                parent_pids=[800],
                types=["file", "registry"],
                operations=["writefile", "RegSetValue"],
                statuses=["success"],
                process_name_contains="payload",
                from_timestamp=1712345678.5,
                to_timestamp=1712345690,
                syscall_line_from=15000,
                syscall_line_to=16000,
                text="payload.dll",
                fields={"path": "temp", "key": ["run", "runonce"]},
                sort="time",
            )
        assert _call_url(mock).endswith("/submissions/sub-789/behaviours")
        assert _call_params(mock) == {
            "eventIds": "1024,1025",
            "pids": "1508,2044",
            "parentPids": "800",
            "types": "file,registry",
            "operations": "writefile,RegSetValue",
            "statuses": "success",
            "processNameContains": "payload",
            "fromTimestamp": 1712345678.5,
            "toTimestamp": 1712345690,
            "syscallLineFrom": 15000,
            "syscallLineTo": 16000,
            "text": "payload.dll",
            "field.path": "temp",
            "field.key": ["run", "runonce"],
            "sort": "time",
        }
        assert resp.sorted_by == "time"
        assert resp.items[0].subject == "C:\\evil.dll"

    def test_get_behaviours_omits_unset_index_filters(
        self, api_key: str, sample_behaviours_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_behaviours_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_behaviours("sub-789", page=1)
        assert _call_params(mock) == {"page": 1}

    def test_get_behaviours_indexing_409(self, api_key: str) -> None:
        body = {
            "statusCode": 409,
            "error": "Conflict",
            "message": "The behaviour index of this submission is not ready.",
            "code": "BEHAVIOUR_INDEXING",
            "details": {"retryAfterSeconds": 60},
        }
        ctx, _ = _patched_client(_make_response(409, body))
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(BehaviourIndexingError) as exc_info,
        ):
            client.get_behaviours("sub-789", pids=[1508])
        assert exc_info.value.retry_after == 60.0

    def test_get_behaviours_too_large_413(self, api_key: str) -> None:
        body = {
            "statusCode": 413,
            "error": "Payload Too Large",
            "message": "The behaviour file is too large.",
            "code": "BEHAVIOUR_TOO_LARGE",
            "details": {"sizeBytes": 98566144, "maxBytes": 67108864},
        }
        ctx, _ = _patched_client(_make_response(413, body))
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(BehaviourTooLargeError) as exc_info,
        ):
            client.get_behaviours("sub-789")
        assert exc_info.value.size_bytes == 98566144

    def test_get_behaviours_unreadable_502(self, api_key: str) -> None:
        body = {"statusCode": 502, "message": "not valid", "code": "BEHAVIOUR_UNREADABLE"}
        ctx, _ = _patched_client(_make_response(502, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(BehaviourUnreadableError):
            client.get_behaviours("sub-789")

    def test_get_behaviour_summary(
        self, api_key: str, sample_behaviour_summary_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_behaviour_summary_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            summary = client.get_behaviour_summary("sub-789")
        assert isinstance(summary, BehaviourSummary)
        assert summary.total_count == 1337
        assert _call_url(mock).endswith("/submissions/sub-789/behaviours/summary")

    def test_get_behaviour_summary_rate_limited(self, api_key: str) -> None:
        response = _make_response(
            429,
            {"statusCode": 429, "message": "Heavy route rate limit exceeded", "retryAfter": 12},
            headers={"Retry-After": "12"},
        )
        ctx, _ = _patched_client(response)
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(RateLimitError) as exc_info,
        ):
            client.get_behaviour_summary("sub-789")
        assert exc_info.value.retry_after == 12.0

    def test_get_behaviour_facets(
        self, api_key: str, sample_behaviour_facets_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_behaviour_facets_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            facets = client.get_behaviour_facets(
                "sub-789", "operation", contains="reg", first=50, pids=[1508]
            )
        assert isinstance(facets, BehaviourFacets)
        assert facets.complete is False
        assert _call_url(mock).endswith("/submissions/sub-789/behaviours/facets")
        assert _call_params(mock) == {
            "field": "operation",
            "contains": "reg",
            "first": 50,
            "pids": "1508",
        }

    def test_get_behaviour_facets_sends_only_the_field(
        self, api_key: str, sample_behaviour_facets_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_behaviour_facets_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_behaviour_facets("sub-789", "processName")
        assert _call_params(mock) == {"field": "processName"}

    def test_get_syscalls_reads_first_line(
        self, api_key: str, sample_syscalls_response: dict[str, Any]
    ) -> None:
        payload = {**sample_syscalls_response, "firstLine": 501}
        ctx, _ = _patched_client(_make_response(200, payload))
        with ctx, ThreatZone(api_key=api_key) as client:
            syscalls = client.get_syscalls("sub-789", page=2)
        assert syscalls.first_line == 501

    def test_search_syscalls(
        self, api_key: str, sample_syscall_search_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_syscall_search_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            result = client.search_syscalls(
                "sub-789",
                query="NtCreateFile",
                pids=[3568, 4128],
                failed_only=True,
                apis=["NtCreateFile", "ntdll!NtWriteFile"],
                after_line=0,
                limit=50,
            )
        assert isinstance(result, SyscallSearchResult)
        assert result.lines[0].line == 3000
        assert _call_url(mock).endswith("/submissions/sub-789/syscalls/search")
        assert _call_params(mock) == {
            "query": "NtCreateFile",
            "pids": "3568,4128",
            "failedOnly": "true",
            "apis": "NtCreateFile,ntdll!NtWriteFile",
            "afterLine": 0,
            "limit": 50,
        }

    def test_search_syscalls_sends_only_the_query(
        self, api_key: str, sample_syscall_search_response: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_syscall_search_response))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.search_syscalls("sub-789", query="NtCreateFile", failed_only=False)
        assert _call_params(mock) == {"query": "NtCreateFile", "failedOnly": "false"}


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

    def test_get_url_analysis_session(
        self,
        api_key: str,
        submission_uuid: str,
        url_analysis_session_payload: dict[str, Any],
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, url_analysis_session_payload))
        with ctx, ThreatZone(api_key=api_key) as client:
            session = client.get_url_analysis_session(submission_uuid)
        assert isinstance(session, UrlAnalysisSession)
        assert session.state == "running"
        assert session.vnc_available is True
        assert session.expired is False
        assert session.link == "wss://gateway.example/?token=abc"
        assert session.session_config is not None
        assert session.session_config.device_preset_name == "iPhone 15 Pro"
        assert _call_url(mock).endswith(f"/submissions/{submission_uuid}/url-analysis/session")

    def test_get_url_analysis_session_503(self, api_key: str, submission_uuid: str) -> None:
        ctx, _ = _patched_client(_make_response(503, {"message": "session service unavailable"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(InternalServerError):
            client.get_url_analysis_session(submission_uuid)

    def test_start_url_analysis_session(self, api_key: str, submission_uuid: str) -> None:
        ctx, mock = _patched_client(
            _make_response(200, {"message": "Interactive browser session start initiated"})
        )
        with ctx, ThreatZone(api_key=api_key) as client:
            result = client.start_url_analysis_session(submission_uuid)
        assert isinstance(result, Message)
        assert _call_method(mock) == "POST"
        assert _call_url(mock).endswith(f"/submissions/{submission_uuid}/url-analysis/session")

    def test_restart_url_analysis_session(self, api_key: str, submission_uuid: str) -> None:
        ctx, mock = _patched_client(
            _make_response(200, {"message": "Interactive browser session restart initiated"})
        )
        with ctx, ThreatZone(api_key=api_key) as client:
            result = client.restart_url_analysis_session(submission_uuid)
        assert isinstance(result, Message)
        assert _call_method(mock) == "POST"
        assert _call_url(mock).endswith(
            f"/submissions/{submission_uuid}/url-analysis/session/restart"
        )

    def test_restart_url_analysis_posts_to_the_restart_route(
        self, api_key: str, submission_uuid: str
    ) -> None:
        ctx, mock = _patched_client(
            _make_response(200, {"message": "URL report restart initiated successfully"})
        )
        with ctx, ThreatZone(api_key=api_key) as client:
            result = client.restart_url_analysis(submission_uuid)
        assert _call_method(mock) == "POST"
        assert _call_url(mock).endswith(f"/submissions/{submission_uuid}/restart/url_analysis")
        assert "restart" in result.message


class TestUrlAnalysisScoreExplanation:
    def test_get_url_analysis_indicators(
        self,
        api_key: str,
        submission_uuid: str,
        url_analysis_indicators_payload: dict[str, Any],
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, url_analysis_indicators_payload))
        with ctx, ThreatZone(api_key=api_key) as client:
            result = client.get_url_analysis_indicators(submission_uuid)
        assert isinstance(result, UrlAnalysisIndicators)
        assert result.snapshot is not None
        assert result.snapshot.indicators[0].id == "domain-age"
        assert _call_method(mock) == "GET"
        assert _call_url(mock).endswith(f"/submissions/{submission_uuid}/url-analysis/indicators")

    def test_get_url_analysis_indicators_409(self, api_key: str, submission_uuid: str) -> None:
        body = _409_body("URL_ANALYSIS_REPORT_UNAVAILABLE", required_report="url_analysis")
        ctx, _ = _patched_client(_make_response(409, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(ReportUnavailableError):
            client.get_url_analysis_indicators(submission_uuid)

    def test_get_url_analysis_indicator_evidence_sends_the_selector(
        self,
        api_key: str,
        submission_uuid: str,
        url_analysis_evidence_payload: dict[str, Any],
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, url_analysis_evidence_payload))
        with ctx, ThreatZone(api_key=api_key) as client:
            evidence = client.get_url_analysis_indicator_evidence(
                submission_uuid,
                "domain/age",
                "whois",
                job_id="6710a3f2c1d2e3f4a5b6c7d8",
                scored_at="2026-10-01T09:30:00.000Z",
            )
        assert isinstance(evidence, UrlAnalysisIndicatorEvidence)
        assert evidence.state == "available"
        assert mock.call_count == 1
        assert _call_url(mock).endswith(
            f"/submissions/{submission_uuid}/url-analysis/indicators/domain%2Fage/evidence/whois"
        )
        assert _call_params(mock) == {
            "jobId": "6710a3f2c1d2e3f4a5b6c7d8",
            "scoredAt": "2026-10-01T09:30:00.000Z",
        }

    def test_get_url_analysis_indicator_evidence_reads_the_snapshot_first(
        self,
        api_key: str,
        submission_uuid: str,
        url_analysis_indicators_payload: dict[str, Any],
        url_analysis_evidence_payload: dict[str, Any],
    ) -> None:
        mock = MagicMock(
            side_effect=[
                _make_response(200, url_analysis_indicators_payload),
                _make_response(200, url_analysis_evidence_payload),
            ]
        )
        with patch.object(httpx.Client, "request", mock), ThreatZone(api_key=api_key) as client:
            evidence = client.get_url_analysis_indicator_evidence(
                submission_uuid, "domain-age", "whois"
            )
        assert evidence.state == "available"
        assert mock.call_count == 2
        assert str(mock.call_args_list[0].args[1]).endswith("/url-analysis/indicators")
        assert _call_params(mock) == {
            "jobId": "6710a3f2c1d2e3f4a5b6c7d8",
            "scoredAt": "2026-10-01T09:30:00.000Z",
        }

    def test_get_url_analysis_indicator_evidence_keeps_a_given_value(
        self,
        api_key: str,
        submission_uuid: str,
        url_analysis_indicators_payload: dict[str, Any],
        url_analysis_evidence_payload: dict[str, Any],
    ) -> None:
        mock = MagicMock(
            side_effect=[
                _make_response(200, url_analysis_indicators_payload),
                _make_response(200, url_analysis_evidence_payload),
            ]
        )
        with patch.object(httpx.Client, "request", mock), ThreatZone(api_key=api_key) as client:
            client.get_url_analysis_indicator_evidence(
                submission_uuid, "domain-age", "whois", job_id="aaaaaaaaaaaaaaaaaaaaaaaa"
            )
        assert _call_params(mock) == {
            "jobId": "aaaaaaaaaaaaaaaaaaaaaaaa",
            "scoredAt": "2026-10-01T09:30:00.000Z",
        }

    def test_get_url_analysis_indicator_evidence_404(
        self, api_key: str, submission_uuid: str
    ) -> None:
        body = {
            "statusCode": 404,
            "error": "Not Found",
            "message": "The indicator or the evidence reference does not exist.",
            "code": "URL_SCORE_EVIDENCE_NOT_FOUND",
        }
        ctx, _ = _patched_client(_make_response(404, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_url_analysis_indicator_evidence(
                submission_uuid,
                "ghost",
                "whois",
                job_id="6710a3f2c1d2e3f4a5b6c7d8",
                scored_at="2026-10-01T09:30:00.000Z",
            )

    def test_get_url_analysis_browser_section(
        self,
        api_key: str,
        submission_uuid: str,
        url_analysis_browser_section_payload: dict[str, Any],
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, url_analysis_browser_section_payload))
        with ctx, ThreatZone(api_key=api_key) as client:
            section = client.get_url_analysis_browser_section(submission_uuid, "tls")
        assert isinstance(section, UrlAnalysisBrowserSection)
        assert section.data["tls"]["issuer"] == "Example CA"
        assert _call_url(mock).endswith(f"/submissions/{submission_uuid}/url-analysis/browser/tls")

    def test_get_url_analysis_browser_section_unknown_name_404(
        self, api_key: str, submission_uuid: str
    ) -> None:
        body = {
            "statusCode": 404,
            "error": "Not Found",
            "message": "Unknown browser section.",
            "code": "URL_BROWSER_SECTION_NOT_FOUND",
        }
        ctx, mock = _patched_client(_make_response(404, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_url_analysis_browser_section(submission_uuid, "cookies")
        assert _call_url(mock).endswith("/url-analysis/browser/cookies")


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

    def test_get_network_lists_send_the_attribution_filter(
        self, api_key: str, sample_tcp_connections: list[dict[str, Any]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_tcp_connections))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_tcp_connections("sub-789", attribution=["sample", "windows_background"])
        assert _call_params(mock) == {"attribution": "sample,windows_background"}

    def test_get_network_lists_omit_the_attribution_filter_by_default(
        self, api_key: str, sample_network_threats: list[dict[str, Any]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_network_threats))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_network_threats("sub-789")
        assert not _call_params(mock)

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


class TestBehaviourMatchesAndArtifactYaraRule:
    def test_get_behaviour_matches_repeats_the_text_parameter(self, api_key: str) -> None:
        ctx, mock = _patched_client(
            _make_response(
                200,
                {
                    "items": [
                        {
                            "needle": "payload.dll",
                            "count": 3,
                            "firstEventId": 1024,
                            "samples": ["C:\\Temp\\payload.dll"],
                            "complete": True,
                            "scannedRows": 1337,
                        },
                        {
                            "needle": "a,b",
                            "count": 0,
                            "firstEventId": None,
                            "samples": [],
                            "complete": True,
                            "scannedRows": 1337,
                        },
                    ]
                },
            )
        )
        with ctx, ThreatZone(api_key=api_key) as client:
            matches = client.get_behaviour_matches("sub-789", ["payload.dll", "a,b"])
        assert _call_url(mock).endswith("/submissions/sub-789/behaviours/match")
        assert _call_params(mock) == {"text": ["payload.dll", "a,b"]}
        first, second = matches.items
        assert (first.first_event_id, first.scanned_rows, first.samples) == (
            1024,
            1337,
            ["C:\\Temp\\payload.dll"],
        )
        assert second.first_event_id is None

    def test_get_behaviour_matches_accepts_one_text(self, api_key: str) -> None:
        ctx, mock = _patched_client(_make_response(200, {"items": []}))
        with ctx, ThreatZone(api_key=api_key) as client:
            assert client.get_behaviour_matches("sub-789", "payload.dll").items == []
        assert _call_params(mock) == {"text": ["payload.dll"]}

    def test_get_behaviour_matches_refuses_no_text(self, api_key: str) -> None:
        ctx, mock = _patched_client(_make_response(200, {"items": []}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(ValueError):
            client.get_behaviour_matches("sub-789", [])
        mock.assert_not_called()

    def test_get_behaviour_matches_429_carries_the_code(self, api_key: str) -> None:
        body = {
            "statusCode": 429,
            "error": "Too Many Requests",
            "message": "Heavy route rate limit exceeded",
            "code": "RATE_LIMIT_EXCEEDED",
            "retryAfter": 12,
        }
        ctx, _ = _patched_client(_make_response(429, body, headers={"Retry-After": "12"}))
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(RateLimitError) as exc_info,
        ):
            client.get_behaviour_matches("sub-789", "payload.dll")
        assert (exc_info.value.code, exc_info.value.retry_after) == ("RATE_LIMIT_EXCEEDED", 12.0)

    def test_download_artifact_yara_rule_happy(self, api_key: str) -> None:
        response = _make_response(200, content=b"rule X {}")
        ctx, mock = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client:
            client.download_artifact_yara_rule("sub-789", "507f1f77bcf86cd799439011")
        url_arg = mock.call_args.args[1]
        assert url_arg.endswith("/submissions/sub-789/artifacts/507f1f77bcf86cd799439011/yara-rule")

    def test_download_artifact_yara_rule_pending_202(self, api_key: str) -> None:
        body = {
            "status": "accepted",
            "message": "YARA rule generation is in progress. Retry shortly.",
            "retryAfter": 10,
        }
        ctx, _ = _patched_stream(_make_response(202, json_data=body))
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(YaraRulePendingError) as exc_info,
        ):
            client.download_artifact_yara_rule("sub-789", "507f1f77bcf86cd799439011")
        assert exc_info.value.retry_after == 10.0
        assert exc_info.value.body == body

    def test_download_artifact_yara_rule_404(self, api_key: str) -> None:
        body = {"statusCode": 404, "message": "no", "code": "ARTIFACT_NOT_FOUND"}
        ctx, _ = _patched_stream(_make_response(404, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.download_artifact_yara_rule("sub-789", "507f1f77bcf86cd799439011")


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

    def test_download_https_pcap_happy(self, api_key: str) -> None:
        response = _make_response(200, content=b"HTTPS-PCAP")
        ctx, mock = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client:
            res = client.download_https_pcap("sub-789")
            assert res.read() == b"HTTPS-PCAP"
        url_arg = mock.call_args.args[1]
        assert url_arg.endswith("/submissions/sub-789/download/pcap-https")

    def test_download_https_pcap_403(self, api_key: str) -> None:
        response = _make_response(403, {"message": "no permission", "code": "FORBIDDEN"})
        ctx, _ = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(PermissionDeniedError):
            client.download_https_pcap("sub-789")

    def test_download_behaviour_happy(self, api_key: str) -> None:
        response = _make_response(200, content=b"[]")
        ctx, mock = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client:
            client.download_behaviour("sub-789")
        url_arg = mock.call_args.args[1]
        assert url_arg.endswith("/submissions/sub-789/download/behaviour")

    def test_download_behaviour_403(self, api_key: str) -> None:
        response = _make_response(403, {"message": "no permission", "code": "FORBIDDEN"})
        ctx, _ = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(PermissionDeniedError):
            client.download_behaviour("sub-789")

    def test_download_syscalls_happy(self, api_key: str) -> None:
        response = _make_response(200, content=b"line 1\nline 2")
        ctx, mock = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client:
            client.download_syscalls("sub-789")
        url_arg = mock.call_args.args[1]
        assert url_arg.endswith("/submissions/sub-789/download/syscalls")

    def test_download_syscalls_404(self, api_key: str) -> None:
        response = _make_response(404, {"message": "no"})
        ctx, _ = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.download_syscalls("sub-789")

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

    def test_get_static_scan_strings_happy(self, api_key: str) -> None:
        response = _make_response(200, content=b'{"strings": ["a", "b"]}')
        ctx, mock = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client:
            res = client.get_static_scan_strings("sub-789")
            assert res.read() == b'{"strings": ["a", "b"]}'
        url_arg = mock.call_args.args[1]
        assert url_arg.endswith("/submissions/sub-789/static-scan/strings")

    def test_get_static_scan_strings_404(self, api_key: str) -> None:
        response = _make_response(404, {"message": "no"})
        ctx, _ = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_static_scan_strings("ghost")


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

    def test_list_media_files_passes_the_source(
        self, api_key: str, sample_media_files: list[dict[str, Any]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_media_files))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.list_media_files("sub-789", source="url_analysis")
        assert _call_params(mock)["source"] == "url_analysis"

    def test_list_media_files_omits_the_source_when_absent(
        self, api_key: str, sample_media_files: list[dict[str, Any]]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_media_files))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.list_media_files("sub-789")
        assert "source" not in _call_params(mock)

    def test_list_media_files_carries_the_kind(
        self, api_key: str, sample_media_files: list[dict[str, Any]]
    ) -> None:
        ctx, _ = _patched_client(_make_response(200, sample_media_files))
        with ctx, ThreatZone(api_key=api_key) as client:
            files = client.list_media_files("sub-789")
        assert [f.kind for f in files] == ["screenshot", "video"]

    def test_get_media_file_passes_the_source(self, api_key: str) -> None:
        ctx, mock = _patched_client(_make_response(200, content=b"binary"))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_media_file("sub-789", "1.png", source="url_analysis")
        assert _call_params(mock)["source"] == "url_analysis"

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


# ---------------------------------------------------------------------------
# Fields and routes that the API already returns
# ---------------------------------------------------------------------------


class TestSearchBySha256Paging:
    def test_sends_page_and_limit(self, api_key: str, sample_submission: dict[str, Any]) -> None:
        ctx, mock = _patched_client(_make_response(200, [sample_submission]))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.search_by_sha256("abc", page=2, limit=100)
        assert _call_params(mock) == {"page": 2, "limit": 100}

    def test_omits_unset_page_and_limit(
        self, api_key: str, sample_submission: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, [sample_submission]))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.search_by_sha256("abc", limit=50)
        assert _call_params(mock) == {"limit": 50}

    def test_sends_no_params_by_default(
        self, api_key: str, sample_submission: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, [sample_submission]))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.search_by_sha256("abc")
        assert _call_params(mock) == {}


class TestNetworkExfilRequests:
    def test_happy(self, api_key: str, sample_network_exfil_request: dict[str, Any]) -> None:
        ctx, mock = _patched_client(_make_response(200, [sample_network_exfil_request]))
        with ctx, ThreatZone(api_key=api_key) as client:
            entries = client.get_network_exfil_requests("sub-789")
        assert all(isinstance(e, NetworkExfilRequest) for e in entries)
        assert entries[0].masked_target == "/bot123456789:FAKE-TOKEN-FOR-TESTS/sendDocument"
        assert _call_url(mock).endswith("/submissions/sub-789/network/exfil-requests")
        assert _call_params(mock) == {}

    def test_sends_limit_and_skip(
        self, api_key: str, sample_network_exfil_request: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, [sample_network_exfil_request]))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_network_exfil_requests("sub-789", limit=10, skip=20)
        assert _call_params(mock) == {"limit": 10, "skip": 20}

    def test_empty_list(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(200, []))
        with ctx, ThreatZone(api_key=api_key) as client:
            assert client.get_network_exfil_requests("sub-789") == []

    def test_409(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(409, _409_body()))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(ReportUnavailableError):
            client.get_network_exfil_requests("sub-789")


class TestAiReport:
    def test_200_returns_the_report(self, api_key: str, sample_ai_report: dict[str, Any]) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_ai_report))
        with ctx, ThreatZone(api_key=api_key) as client:
            report = client.get_ai_report("sub-789")
        assert isinstance(report, AiReport)
        assert report.verdict == "malicious"
        assert _call_url(mock).endswith("/submissions/sub-789/ai-report")

    def test_202_returns_a_pending_model(
        self, api_key: str, sample_ai_report_in_progress: dict[str, Any]
    ) -> None:
        ctx, _ = _patched_client(_make_response(202, sample_ai_report_in_progress))
        with ctx, ThreatZone(api_key=api_key) as client:
            report = client.get_ai_report("sub-789")
        assert isinstance(report, AiReportPending)
        assert report.status == "in_progress"
        assert report.stage == "writing"

    def test_202_waiting_for_analysis(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(202, {"status": "waiting_for_analysis"}))
        with ctx, ThreatZone(api_key=api_key) as client:
            report = client.get_ai_report("sub-789")
        assert isinstance(report, AiReportPending)
        assert report.status == "waiting_for_analysis"

    def test_403(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(403, {"message": "no aiReport permission"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(PermissionDeniedError):
            client.get_ai_report("sub-789")

    def test_404(self, api_key: str) -> None:
        body = {"message": "No AI report", "code": "AI_REPORT_NOT_FOUND"}
        ctx, _ = _patched_client(_make_response(404, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_ai_report("sub-789")

    def test_200_failed_report_has_the_error_code(
        self, api_key: str, sample_ai_report_failed: dict[str, Any]
    ) -> None:
        ctx, _ = _patched_client(_make_response(200, sample_ai_report_failed))
        with ctx, ThreatZone(api_key=api_key) as client:
            report = client.get_ai_report("sub-789")
        assert isinstance(report, AiReport)
        assert report.error is not None
        assert report.error.code == "PIPELINE_TIMEOUT"
        assert report.analysis_finalized is True


class TestRegenerateAiReport:
    def test_202_returns_the_queued_result(
        self, api_key: str, sample_ai_report_regenerate: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(202, sample_ai_report_regenerate))
        with ctx, ThreatZone(api_key=api_key) as client:
            result = client.regenerate_ai_report("sub-789")
        assert isinstance(result, AiReportRegenerateResult)
        assert isinstance(result, AiReportPending)
        assert result.status == "queued"
        assert _call_method(mock) == "POST"
        assert _call_url(mock).endswith("/submissions/sub-789/ai-report/regenerate")

    def test_403(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(403, {"message": "Forbidden"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(PermissionDeniedError):
            client.regenerate_ai_report("sub-789")

    @pytest.mark.parametrize("code", ["AI_REPORT_NOT_FINALIZED", "AI_REPORT_IN_PROGRESS"])
    def test_409_carries_the_code(self, api_key: str, code: str) -> None:
        body = {"statusCode": 409, "message": "Conflict", "code": code}
        ctx, _ = _patched_client(_make_response(409, body))
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(ReportUnavailableError) as exc_info,
        ):
            client.regenerate_ai_report("sub-789")
        assert exc_info.value.code == code

    def test_429_carries_retry_after(self, api_key: str) -> None:
        body = {"statusCode": 429, "message": "Quota used", "code": "AI_REPORT_QUOTA_EXCEEDED"}
        response = _make_response(429, body, headers={"Retry-After": "3600"})
        ctx, mock = _patched_client(response)
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(RateLimitError) as exc_info,
        ):
            client.regenerate_ai_report("sub-789")
        assert exc_info.value.retry_after == 3600.0
        assert mock.call_count == 1


def _patched_streams(*responses: httpx.Response) -> tuple[Any, MagicMock]:
    mock = MagicMock(side_effect=[_StreamCtx(r) for r in responses])
    return patch.object(httpx.Client, "stream", mock), mock


def _pdf_pending_response() -> httpx.Response:
    return _make_response(
        202,
        {
            "status": "accepted",
            "message": "PDF report generation is in progress.",
            "retryAfter": 3,
        },
    )


class TestStixAndPdfReports:
    def test_download_stix_report_happy(self, api_key: str) -> None:
        response = _make_response(200, content=b'{"type": "bundle"}')
        ctx, mock = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client:
            res = client.download_stix_report("sub-789")
            assert res.read() == b'{"type": "bundle"}'
        url_arg = mock.call_args.args[1]
        assert url_arg.endswith("/submissions/sub-789/download/stix-2.1-report")

    def test_download_stix_report_403(self, api_key: str) -> None:
        response = _make_response(403, {"message": "no stixReport permission"})
        ctx, _ = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(PermissionDeniedError):
            client.download_stix_report("sub-789")

    def test_get_pdf_report_status(
        self, api_key: str, sample_pdf_report_status_queued: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_pdf_report_status_queued))
        with ctx, ThreatZone(api_key=api_key) as client:
            status = client.get_pdf_report_status("sub-789")
        assert isinstance(status, PdfReportStatus)
        assert status.retry_after_seconds == 3
        assert _call_url(mock).endswith("/submissions/sub-789/download/pdf-report/status")

    def test_download_pdf_report_without_wait_returns_the_file(self, api_key: str) -> None:
        ctx, mock = _patched_stream(_make_response(200, content=b"%PDF-1.4"))
        with (
            ctx,
            patch.object(httpx.Client, "request") as request_mock,
            ThreatZone(api_key=api_key) as client,
        ):
            res = client.download_pdf_report("sub-789", wait=False)
            assert res.read() == b"%PDF-1.4"
        assert mock.call_args.args[1].endswith("/submissions/sub-789/download/pdf-report")
        request_mock.assert_not_called()

    def test_download_pdf_report_without_wait_raises_on_202(self, api_key: str) -> None:
        ctx, _ = _patched_stream(_pdf_pending_response())
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(PdfReportPendingError) as exc_info,
        ):
            client.download_pdf_report("sub-789", wait=False)
        assert exc_info.value.retry_after == 3.0
        assert exc_info.value.status_code == 202

    def test_download_pdf_report_without_wait_raises_on_409(self, api_key: str) -> None:
        body = {"message": "Please wait for the analysis to finish.", "code": "CONFLICT"}
        ctx, _ = _patched_stream(_make_response(409, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(ReportUnavailableError):
            client.download_pdf_report("sub-789", wait=False)

    def test_download_pdf_report_polls_the_status_until_ready(self, api_key: str) -> None:
        statuses = [
            _make_response(200, {"status": "analysis_in_progress", "message": "wait"}),
            _make_response(200, {"status": "queued", "retryAfterSeconds": 3}),
            _make_response(200, {"status": "ready"}),
        ]
        stream_ctx, stream_mock = _patched_streams(_make_response(200, content=b"%PDF-1.4"))
        with (
            stream_ctx,
            patch.object(httpx.Client, "request", side_effect=statuses) as request_mock,
            ThreatZone(api_key=api_key) as client,
        ):
            res = client.download_pdf_report("sub-789", poll_interval=0)
            assert res.read() == b"%PDF-1.4"
        assert request_mock.call_count == 3
        assert stream_mock.call_count == 1

    def test_download_pdf_report_retries_when_the_file_is_pending(self, api_key: str) -> None:
        statuses = [
            _make_response(200, {"status": "ready"}),
            _make_response(200, {"status": "ready"}),
        ]
        stream_ctx, stream_mock = _patched_streams(
            _pdf_pending_response(), _make_response(200, content=b"%PDF-1.4")
        )
        with (
            stream_ctx,
            patch.object(httpx.Client, "request", side_effect=statuses),
            ThreatZone(api_key=api_key) as client,
        ):
            res = client.download_pdf_report("sub-789", poll_interval=0)
            assert res.read() == b"%PDF-1.4"
        assert stream_mock.call_count == 2

    def test_download_pdf_report_uses_the_server_retry_hint(self, api_key: str) -> None:
        statuses = [
            _make_response(200, {"status": "generating", "retryAfterSeconds": 3}),
            _make_response(200, {"status": "ready"}),
        ]
        stream_ctx, _ = _patched_streams(_make_response(200, content=b"%PDF-1.4"))
        with (
            stream_ctx,
            patch.object(httpx.Client, "request", side_effect=statuses),
            patch("threatzone._sync_client.time.sleep") as sleep_mock,
            ThreatZone(api_key=api_key) as client,
        ):
            client.download_pdf_report("sub-789")
        sleep_mock.assert_called_once_with(3.0)

    def test_download_pdf_report_raises_when_generation_failed(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(200, {"status": "failed", "message": "boom"}))
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(InternalServerError) as exc_info,
        ):
            client.download_pdf_report("sub-789", poll_interval=0)
        assert exc_info.value.message == "boom"

    def test_download_pdf_report_stops_at_the_timeout(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(200, {"status": "queued", "retryAfterSeconds": 3}))
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(PdfReportPendingError) as exc_info,
        ):
            client.download_pdf_report("sub-789", timeout=0)
        assert exc_info.value.retry_after == 3.0


class TestUrlSessionConflict:
    def test_start_url_analysis_session_409_on_an_errored_report(
        self, api_key: str, submission_uuid: str
    ) -> None:
        body = _409_body("URL_ANALYSIS_REPORT_UNAVAILABLE", required_report="url_analysis")
        ctx, _ = _patched_client(_make_response(409, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(ReportUnavailableError):
            client.start_url_analysis_session(submission_uuid)

    def test_restart_url_analysis_session_409_on_an_errored_report(
        self, api_key: str, submission_uuid: str
    ) -> None:
        body = _409_body("URL_ANALYSIS_REPORT_UNAVAILABLE", required_report="url_analysis")
        ctx, _ = _patched_client(_make_response(409, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(ReportUnavailableError):
            client.restart_url_analysis_session(submission_uuid)


class TestNetworkListTotals:
    def test_list_reads_the_total_count_header(
        self, api_key: str, sample_tcp_connections: list[dict[str, Any]]
    ) -> None:
        response = _make_response(200, sample_tcp_connections, headers={"X-Total-Count": "128"})
        ctx, _ = _patched_client(response)
        with ctx, ThreatZone(api_key=api_key) as client:
            page = client.get_tcp_connections("sub-789", limit=1, skip=0)
        assert isinstance(page, TotalCountList)
        assert isinstance(page, list)
        assert all(isinstance(c, Connection) for c in page)
        assert page.total_count == 128

    def test_total_count_is_none_without_the_header(
        self, api_key: str, sample_dns_queries: list[dict[str, Any]]
    ) -> None:
        ctx, _ = _patched_client(_make_response(200, sample_dns_queries))
        with ctx, ThreatZone(api_key=api_key) as client:
            page = client.get_dns_queries("sub-789")
        assert page.total_count is None
        assert len(page) == 2

    def test_total_count_is_none_for_a_bad_header(
        self, api_key: str, sample_network_threats: list[dict[str, Any]]
    ) -> None:
        response = _make_response(200, sample_network_threats, headers={"X-Total-Count": "many"})
        ctx, _ = _patched_client(response)
        with ctx, ThreatZone(api_key=api_key) as client:
            page = client.get_network_threats("sub-789")
        assert page.total_count is None

    @pytest.mark.parametrize(
        "method",
        [
            "get_dns_queries",
            "get_http_requests",
            "get_tcp_connections",
            "get_udp_connections",
            "get_network_threats",
            "get_network_exfil_requests",
        ],
    )
    def test_every_list_returns_the_total(self, api_key: str, method: str) -> None:
        ctx, _ = _patched_client(_make_response(200, [], headers={"X-Total-Count": "0"}))
        with ctx, ThreatZone(api_key=api_key) as client:
            page = getattr(client, method)("sub-789")
        assert page == []
        assert page.total_count == 0


class TestNetworkPackets:
    def test_http_request_packets(
        self, api_key: str, sample_http_request_packets: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_http_request_packets))
        with ctx, ThreatZone(api_key=api_key) as client:
            packets = client.get_http_request_packets("sub-789", "507f1f77bcf86cd799439012")
        assert isinstance(packets, NetworkHttpPackets)
        assert packets.items[0].body is not None
        assert packets.items[0].body.data == b"test"
        assert _call_method(mock) == "GET"
        assert _call_url(mock).endswith(
            "/submissions/sub-789/network/http/507f1f77bcf86cd799439012/packets"
        )

    def test_tcp_connection_packets(
        self, api_key: str, sample_tcp_connection_packets: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_tcp_connection_packets))
        with ctx, ThreatZone(api_key=api_key) as client:
            packets = client.get_tcp_connection_packets("sub-789", "507f1f77bcf86cd799439013")
        assert isinstance(packets, NetworkFlowPackets)
        assert packets.items[0].data is not None
        assert packets.items[0].data.data == b"\x16\x03\x01\x00\x01"
        assert _call_url(mock).endswith(
            "/submissions/sub-789/network/tcp/507f1f77bcf86cd799439013/packets"
        )

    def test_udp_connection_packets(
        self, api_key: str, sample_tcp_connection_packets: dict[str, Any]
    ) -> None:
        payload = {**sample_tcp_connection_packets, "protocol": "udp"}
        ctx, mock = _patched_client(_make_response(200, payload))
        with ctx, ThreatZone(api_key=api_key) as client:
            packets = client.get_udp_connection_packets("sub-789", "507f1f77bcf86cd799439014")
        assert packets.protocol == "udp"
        assert _call_url(mock).endswith(
            "/submissions/sub-789/network/udp/507f1f77bcf86cd799439014/packets"
        )

    def test_eve_request_id_is_kept_in_the_path(
        self, api_key: str, sample_http_request_packets: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_http_request_packets))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_http_request_packets("sub-789", "eve-42")
        assert _call_url(mock).endswith("/submissions/sub-789/network/http/eve-42/packets")

    def test_row_of_another_submission_raises_not_found(self, api_key: str) -> None:
        body = {
            "statusCode": 404,
            "error": "Not Found",
            "message": "No TCP connection with this ID exists on this submission",
            "code": "NETWORK_ROW_NOT_FOUND",
        }
        ctx, _ = _patched_client(_make_response(404, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_tcp_connection_packets("sub-789", "507f1f77bcf86cd799439013")

    def test_packets_409(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(409, _409_body()))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(ReportUnavailableError):
            client.get_udp_connection_packets("sub-789", "507f1f77bcf86cd799439013")


class TestNetworkEndpoints:
    def test_endpoints(self, api_key: str, sample_network_endpoints: dict[str, Any]) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_network_endpoints))
        with ctx, ThreatZone(api_key=api_key) as client:
            endpoints = client.get_network_endpoints("sub-789")
        assert isinstance(endpoints, NetworkEndpoints)
        assert endpoints.items[0].key == "malware-c2.example.com"
        assert _call_url(mock).endswith("/submissions/sub-789/network/endpoints")
        assert _call_params(mock) == {}

    def test_endpoints_send_attribution_and_limit(
        self, api_key: str, sample_network_endpoints: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_network_endpoints))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_network_endpoints(
                "sub-789", attribution=["sample", "sample_child"], limit=100
            )
        assert _call_params(mock) == {"attribution": "sample,sample_child", "limit": 100}

    def test_endpoints_429(self, api_key: str) -> None:
        body = {
            "statusCode": 429,
            "error": "Too Many Requests",
            "message": "Too many heavy-route requests",
            "code": "RATE_LIMIT_EXCEEDED",
        }
        ctx, _ = _patched_client(_make_response(429, body, headers={"Retry-After": "12"}))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(RateLimitError):
            client.get_network_endpoints("sub-789")

    def test_host_flows(self, api_key: str, sample_network_host_flows: dict[str, Any]) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_network_host_flows))
        with ctx, ThreatZone(api_key=api_key) as client:
            page = client.get_network_host_flows("sub-789", "malware-c2.example.com")
        assert isinstance(page, NetworkHostFlows)
        assert page.alerts[0].signature == "ET MALWARE Test beacon"
        assert _call_url(mock).endswith(
            "/submissions/sub-789/network/endpoints/malware-c2.example.com/flows"
        )
        assert _call_params(mock) == {}

    def test_host_flows_encode_the_host_and_send_the_cursor(
        self, api_key: str, sample_network_host_flows: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_network_host_flows))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.get_network_host_flows(
                "sub-789",
                "fe80::1%eth0",
                attribution=["sample"],
                first=20,
                after="aGYxOjI",
            )
        assert _call_url(mock).endswith(
            "/submissions/sub-789/network/endpoints/fe80%3A%3A1%25eth0/flows"
        )
        assert _call_params(mock) == {"attribution": "sample", "first": 20, "after": "aGYxOjI"}

    def test_host_flows_400(self, api_key: str) -> None:
        body = {
            "statusCode": 400,
            "error": "Bad Request",
            "message": "after must be the pageInfo.endCursor of a previous page",
            "code": "INVALID_QUERY_PARAM",
        }
        ctx, _ = _patched_client(_make_response(400, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(BadRequestError):
            client.get_network_host_flows("sub-789", "c2.example.com", after="x")


def _call_json(mock: MagicMock) -> Any:
    _, kwargs = mock.call_args
    return kwargs.get("json")


class TestSearchBySha256Scope:
    @pytest.mark.parametrize("scope", ["workspace", "public"])
    def test_sends_scope(
        self, api_key: str, sample_submission: dict[str, Any], scope: Literal["workspace", "public"]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, [sample_submission]))
        with ctx, ThreatZone(api_key=api_key) as client:
            client.search_by_sha256("abc", scope=scope)
        assert _call_params(mock) == {"scope": scope}

    def test_invalid_scope_400(self, api_key: str) -> None:
        body = {"statusCode": 400, "message": "scope", "code": "INVALID_QUERY_PARAM"}
        ctx, _ = _patched_client(_make_response(400, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(BadRequestError):
            client.search_by_sha256("abc", scope="public")


class TestVerdictAndRun:
    def test_get_verdict(self, api_key: str, sample_verdict: dict[str, Any]) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_verdict))
        with ctx, ThreatZone(api_key=api_key) as client:
            verdict = client.get_verdict("sub-789")
        assert isinstance(verdict, Verdict)
        assert verdict.tier == "Suspicious"
        assert _call_method(mock) == "GET"
        assert _call_url(mock).endswith("/submissions/sub-789/verdict")

    def test_get_verdict_legacy(self, api_key: str, sample_verdict_legacy: dict[str, Any]) -> None:
        ctx, _ = _patched_client(_make_response(200, sample_verdict_legacy))
        with ctx, ThreatZone(api_key=api_key) as client:
            verdict = client.get_verdict("sub-789")
        assert verdict.story is None

    def test_get_verdict_409(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(409, _409_body()))
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(ReportUnavailableError) as exc_info,
        ):
            client.get_verdict("sub-789")
        assert exc_info.value.code == "DYNAMIC_REPORT_UNAVAILABLE"

    def test_get_verdict_404(self, api_key: str) -> None:
        body = {"statusCode": 404, "message": "Not found", "code": "NOT_FOUND"}
        ctx, _ = _patched_client(_make_response(404, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.get_verdict("sub-789")

    def test_get_run(self, api_key: str, sample_run_notes: dict[str, Any]) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_run_notes))
        with ctx, ThreatZone(api_key=api_key) as client:
            notes = client.get_run("sub-789")
        assert isinstance(notes, RunNotes)
        assert notes.java_output is not None
        assert notes.java_output.text == sample_run_notes["javaOutput"]["text"]
        assert _call_url(mock).endswith("/submissions/sub-789/run")

    def test_get_run_409(self, api_key: str) -> None:
        ctx, _ = _patched_client(_make_response(409, _409_body()))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(ReportUnavailableError):
            client.get_run("sub-789")


class TestAnnotations:
    def test_get_annotations(self, api_key: str, sample_annotations: dict[str, Any]) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_annotations))
        with ctx, ThreatZone(api_key=api_key) as client:
            annotations = client.get_annotations("sub-789")
        assert isinstance(annotations, Annotations)
        assert annotations.pins[0].ref == "process:pid-4120"
        assert _call_method(mock) == "GET"
        assert _call_url(mock).endswith("/submissions/sub-789/annotations")

    def test_pin_evidence_posts_the_body(
        self, api_key: str, sample_annotations: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_annotations))
        with ctx, ThreatZone(api_key=api_key) as client:
            annotations = client.pin_evidence(
                "sub-789", kind="process", ref="process:pid-4120", label="payload.exe"
            )
        assert isinstance(annotations, Annotations)
        assert _call_method(mock) == "POST"
        assert _call_url(mock).endswith("/submissions/sub-789/annotations/pins")
        assert _call_json(mock) == {
            "kind": "process",
            "ref": "process:pid-4120",
            "label": "payload.exe",
        }

    def test_pin_limit_400(self, api_key: str) -> None:
        body = {
            "statusCode": 400,
            "message": "Pin limit",
            "code": "ANNOTATION_PIN_LIMIT_REACHED",
            "details": {"limit": 200},
        }
        ctx, _ = _patched_client(_make_response(400, body))
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(BadRequestError) as exc_info,
        ):
            client.pin_evidence("sub-789", kind="technique", ref="technique:T1055", label="T1055")
        assert exc_info.value.body is not None
        assert exc_info.value.body["code"] == "ANNOTATION_PIN_LIMIT_REACHED"

    def test_unpin_evidence_sends_delete_without_body(
        self, api_key: str, sample_annotations: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, {**sample_annotations, "pins": []}))
        with ctx, ThreatZone(api_key=api_key) as client:
            annotations = client.unpin_evidence("sub-789", "c1c2c3c4-e5f6-4789-abcd-ef1234567892")
        assert annotations.pins == []
        assert _call_method(mock) == "DELETE"
        assert _call_url(mock).endswith(
            "/submissions/sub-789/annotations/pins/c1c2c3c4-e5f6-4789-abcd-ef1234567892"
        )
        assert _call_json(mock) is None

    def test_unpin_unknown_pin_404(self, api_key: str) -> None:
        body = {"statusCode": 404, "message": "No pin", "code": "ANNOTATION_PIN_NOT_FOUND"}
        ctx, _ = _patched_client(_make_response(404, body))
        with (
            ctx,
            ThreatZone(api_key=api_key) as client,
            pytest.raises(NotFoundError) as exc_info,
        ):
            client.unpin_evidence("sub-789", "c1c2c3c4-e5f6-4789-abcd-ef1234567892")
        assert exc_info.value.body is not None
        assert exc_info.value.body["code"] == "ANNOTATION_PIN_NOT_FOUND"

    def test_set_note_puts_the_text(self, api_key: str, sample_annotations: dict[str, Any]) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_annotations))
        with ctx, ThreatZone(api_key=api_key) as client:
            annotations = client.set_note("sub-789", "The sample drops a second stage.")
        assert annotations.note is not None
        assert _call_method(mock) == "PUT"
        assert _call_url(mock).endswith("/submissions/sub-789/annotations/note")
        assert _call_json(mock) == {"text": "The sample drops a second stage."}

    def test_set_empty_note_removes_it(
        self, api_key: str, sample_annotations: dict[str, Any]
    ) -> None:
        ctx, mock = _patched_client(_make_response(200, {**sample_annotations, "note": None}))
        with ctx, ThreatZone(api_key=api_key) as client:
            annotations = client.set_note("sub-789", "")
        assert annotations.note is None
        assert _call_json(mock) == {"text": ""}


class TestRunCompare:
    def test_get_previous_run(self, api_key: str) -> None:
        payload = {"previousRunUuid": "b1b2c3d4-e5f6-4789-abcd-ef1234567891"}
        ctx, mock = _patched_client(_make_response(200, payload))
        with ctx, ThreatZone(api_key=api_key) as client:
            previous = client.get_previous_run("sub-789")
        assert isinstance(previous, PreviousRun)
        assert previous.previous_run_uuid == "b1b2c3d4-e5f6-4789-abcd-ef1234567891"
        assert _call_url(mock).endswith("/submissions/sub-789/previous-run")

    def test_compare_runs(self, api_key: str, sample_run_comparison: dict[str, Any]) -> None:
        ctx, mock = _patched_client(_make_response(200, sample_run_comparison))
        with ctx, ThreatZone(api_key=api_key) as client:
            comparison = client.compare_runs("sub-789", "sub-123")
        assert isinstance(comparison, RunComparison)
        assert comparison.techniques.added == ["T1059"]
        assert _call_url(mock).endswith("/submissions/sub-789/compare/sub-123")

    def test_compare_runs_404(self, api_key: str) -> None:
        body = {"statusCode": 404, "message": "Not found", "code": "NOT_FOUND"}
        ctx, _ = _patched_client(_make_response(404, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(NotFoundError):
            client.compare_runs("sub-789", "private-run")


class TestIocExport:
    @pytest.mark.parametrize("export_format", ["csv", "text", "stix", "misp"])
    def test_download_iocs_sends_the_format(
        self, api_key: str, export_format: Literal["csv", "text", "stix", "misp"]
    ) -> None:
        response = _make_response(200, content=b"type,value,defanged,sources\n")
        ctx, mock = _patched_stream(response)
        with ctx, ThreatZone(api_key=api_key) as client:
            download = client.download_iocs("sub-789", format=export_format)
            assert download.read() == b"type,value,defanged,sources\n"
        assert mock.call_args.args[1].endswith("/submissions/sub-789/download/iocs")
        assert mock.call_args.kwargs["params"] == {"format": export_format}

    def test_download_iocs_403_without_stix_permission(self, api_key: str) -> None:
        body = {"statusCode": 403, "message": "Forbidden", "code": "FORBIDDEN"}
        ctx, _ = _patched_stream(_make_response(403, body))
        with ctx, ThreatZone(api_key=api_key) as client, pytest.raises(PermissionDeniedError):
            client.download_iocs("sub-789", format="misp")
