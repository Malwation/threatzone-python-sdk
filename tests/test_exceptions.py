"""Tests for Threat.Zone Python SDK exceptions."""

from __future__ import annotations

import httpx
import pytest

from threatzone._exceptions import (
    AnalysisTimeoutError,
    APIError,
    AuthenticationError,
    BadRequestError,
    InternalServerError,
    NotFoundError,
    PaymentRequiredError,
    PermissionDeniedError,
    RateLimitError,
    ReportUnavailableError,
    ThreatZoneError,
    YaraRulePendingError,
    raise_for_status,
)


class TestExceptionHierarchy:
    """Test exception inheritance."""

    def test_api_error_inherits_from_threatzone_error(self):
        error = APIError("Bad request", status_code=400)
        assert isinstance(error, ThreatZoneError)

    def test_authentication_error_inherits_from_api_error(self):
        error = AuthenticationError("Invalid API key", status_code=401)
        assert isinstance(error, APIError)
        assert isinstance(error, ThreatZoneError)

    def test_not_found_error_inherits_from_api_error(self):
        error = NotFoundError("Resource not found", status_code=404)
        assert isinstance(error, APIError)

    def test_permission_denied_error_inherits_from_api_error(self):
        error = PermissionDeniedError("Access denied", status_code=403)
        assert isinstance(error, APIError)

    def test_analysis_timeout_inherits_from_threatzone_error(self):
        error = AnalysisTimeoutError("Timeout", uuid="test-uuid", elapsed=30.0)
        assert isinstance(error, ThreatZoneError)
        assert not isinstance(error, APIError)

    def test_yara_pending_error_inherits_from_api_error(self):
        error = YaraRulePendingError("Pending", retry_after=5.0)
        assert isinstance(error, APIError)
        assert isinstance(error, ThreatZoneError)

    def test_report_unavailable_error_inherits_from_api_error(self):
        error = ReportUnavailableError("Not yet")
        assert isinstance(error, APIError)
        assert isinstance(error, ThreatZoneError)
        assert error.status_code == 409


class TestAPIError:
    """Test APIError properties."""

    def test_api_error_message(self):
        error = APIError("Server error", status_code=500)
        assert error.status_code == 500
        assert error.message == "Server error"
        assert "Server error" in str(error)

    def test_api_error_with_response(self):
        response = httpx.Response(400, content=b"Bad request")
        error = APIError("Invalid input", status_code=400, response=response)
        assert error.response is response

    def test_yara_pending_error_retry_after(self):
        error = YaraRulePendingError("Pending", retry_after=3.5)
        assert error.status_code == 202
        assert error.retry_after == 3.5
        assert "retry_after=3.5s" in str(error)


class TestRaiseForStatus:
    """Test raise_for_status function."""

    def test_200_ok_does_not_raise(self):
        response = httpx.Response(200, content=b"OK")
        raise_for_status(response)

    def test_201_created_does_not_raise(self):
        response = httpx.Response(201, content=b"Created")
        raise_for_status(response)

    def test_400_raises_bad_request_error(self):
        response = httpx.Response(400, json={"message": "Invalid parameters"})
        with pytest.raises(BadRequestError) as exc_info:
            raise_for_status(response)
        assert exc_info.value.status_code == 400

    def test_401_raises_authentication_error(self):
        response = httpx.Response(401, json={"message": "Invalid API key"})
        with pytest.raises(AuthenticationError) as exc_info:
            raise_for_status(response)
        assert exc_info.value.status_code == 401

    def test_402_raises_payment_required_error(self):
        response = httpx.Response(402, json={"message": "Subscription inactive"})
        with pytest.raises(PaymentRequiredError) as exc_info:
            raise_for_status(response)
        assert exc_info.value.status_code == 402

    def test_403_raises_permission_denied_error(self):
        response = httpx.Response(403, json={"message": "Access denied"})
        with pytest.raises(PermissionDeniedError) as exc_info:
            raise_for_status(response)
        assert exc_info.value.status_code == 403

    def test_404_raises_not_found_error(self):
        response = httpx.Response(404, json={"message": "Not found"})
        with pytest.raises(NotFoundError) as exc_info:
            raise_for_status(response)
        assert exc_info.value.status_code == 404

    def test_429_raises_rate_limit_error(self):
        response = httpx.Response(429, json={"message": "Rate limit exceeded"})
        with pytest.raises(RateLimitError) as exc_info:
            raise_for_status(response)
        assert exc_info.value.status_code == 429

    def test_500_raises_internal_server_error(self):
        response = httpx.Response(500, json={"message": "Server error"})
        with pytest.raises(InternalServerError) as exc_info:
            raise_for_status(response)
        assert exc_info.value.status_code == 500

    def test_502_raises_internal_server_error(self):
        response = httpx.Response(502, json={"message": "Bad gateway"})
        with pytest.raises(InternalServerError) as exc_info:
            raise_for_status(response)
        assert exc_info.value.status_code == 502

    def test_503_raises_internal_server_error(self):
        response = httpx.Response(503, json={"message": "Service unavailable"})
        with pytest.raises(InternalServerError) as exc_info:
            raise_for_status(response)
        assert exc_info.value.status_code == 503

    def test_unknown_4xx_raises_api_error(self):
        response = httpx.Response(418, json={"message": "I'm a teapot"})
        with pytest.raises(APIError) as exc_info:
            raise_for_status(response)
        assert exc_info.value.status_code == 418

    def test_error_extracts_message_from_json(self):
        response = httpx.Response(400, json={"message": "Custom error message"})
        with pytest.raises(BadRequestError) as exc_info:
            raise_for_status(response)
        assert "Custom error message" in str(exc_info.value)

    def test_error_handles_non_json_response(self):
        response = httpx.Response(500, content=b"Internal Server Error")
        with pytest.raises(InternalServerError):
            raise_for_status(response)

    def test_streaming_error_response_without_read_still_raises_api_error(self):
        response = httpx.Response(404, stream=httpx.ByteStream(b'{"message":"Not found"}'))
        with pytest.raises(NotFoundError) as exc_info:
            raise_for_status(response)
        assert exc_info.value.status_code == 404

    def test_error_handles_non_dict_json_response(self):
        response = httpx.Response(400, json=["unexpected", "shape"])
        with pytest.raises(BadRequestError) as exc_info:
            raise_for_status(response)
        assert exc_info.value.status_code == 400


class TestReportUnavailableError:
    """Tests for the 409 ReportUnavailableError typed exception."""

    def test_constructor_with_all_attributes(self):
        error = ReportUnavailableError(
            "Dynamic report not available",
            code="DYNAMIC_REPORT_UNAVAILABLE",
            submission_uuid="11111111-2222-3333-4444-555555555555",
            required_report="dynamic",
            current_status="in_progress",
            available_reports=["static", "cdr"],
        )
        assert error.status_code == 409
        assert error.code == "DYNAMIC_REPORT_UNAVAILABLE"
        assert error.submission_uuid == "11111111-2222-3333-4444-555555555555"
        assert error.required_report == "dynamic"
        assert error.current_status == "in_progress"
        assert error.available_reports == ["static", "cdr"]

    def test_constructor_with_partial_attributes(self):
        error = ReportUnavailableError("Report pending")
        assert error.code is None
        assert error.submission_uuid is None
        assert error.required_report is None
        assert error.current_status is None
        assert error.available_reports == []

    def test_str_representation_includes_report_info(self):
        error = ReportUnavailableError(
            "Dynamic report not available",
            required_report="dynamic",
            current_status="error",
        )
        text = str(error)
        assert "Dynamic report not available" in text
        assert "required_report=dynamic" in text
        assert "current_status=error" in text

    def test_str_representation_without_required_report(self):
        error = ReportUnavailableError("Oops")
        text = str(error)
        assert "Oops" in text
        assert "required_report" not in text

    def test_raise_for_status_409_parses_dynamic_report(self):
        body = {
            "statusCode": 409,
            "error": "Conflict",
            "message": "Dynamic report is not available",
            "code": "DYNAMIC_REPORT_UNAVAILABLE",
            "details": {
                "submissionUuid": "11111111-2222-3333-4444-555555555555",
                "requiredReport": "dynamic",
                "currentStatus": "in_progress",
                "availableReports": ["static"],
            },
        }
        response = httpx.Response(409, json=body)
        with pytest.raises(ReportUnavailableError) as exc_info:
            raise_for_status(response)
        err = exc_info.value
        assert err.status_code == 409
        assert err.code == "DYNAMIC_REPORT_UNAVAILABLE"
        assert err.submission_uuid == "11111111-2222-3333-4444-555555555555"
        assert err.required_report == "dynamic"
        assert err.current_status == "in_progress"
        assert err.available_reports == ["static"]
        assert "Dynamic report is not available" in err.message

    def test_raise_for_status_409_parses_static_report(self):
        body = {
            "statusCode": 409,
            "error": "Conflict",
            "message": "Static report is not available",
            "code": "STATIC_REPORT_UNAVAILABLE",
            "details": {
                "submissionUuid": "abc",
                "requiredReport": "static",
                "currentStatus": None,
                "availableReports": ["dynamic"],
            },
        }
        response = httpx.Response(409, json=body)
        with pytest.raises(ReportUnavailableError) as exc_info:
            raise_for_status(response)
        err = exc_info.value
        assert err.code == "STATIC_REPORT_UNAVAILABLE"
        assert err.required_report == "static"
        assert err.current_status is None
        assert err.available_reports == ["dynamic"]

    def test_raise_for_status_409_parses_cdr_report(self):
        body = {
            "statusCode": 409,
            "error": "Conflict",
            "message": "CDR report is not available",
            "code": "CDR_REPORT_UNAVAILABLE",
            "details": {
                "submissionUuid": "xyz",
                "requiredReport": "cdr",
                "currentStatus": "error",
                "availableReports": [],
            },
        }
        response = httpx.Response(409, json=body)
        with pytest.raises(ReportUnavailableError) as exc_info:
            raise_for_status(response)
        err = exc_info.value
        assert err.code == "CDR_REPORT_UNAVAILABLE"
        assert err.required_report == "cdr"
        assert err.available_reports == []

    def test_raise_for_status_409_parses_url_analysis_report(self):
        body = {
            "statusCode": 409,
            "error": "Conflict",
            "message": "URL analysis report is not available",
            "code": "URL_ANALYSIS_REPORT_UNAVAILABLE",
            "details": {
                "submissionUuid": "url-1",
                "requiredReport": "url_analysis",
                "currentStatus": "in_progress",
                "availableReports": ["dynamic"],
            },
        }
        response = httpx.Response(409, json=body)
        with pytest.raises(ReportUnavailableError) as exc_info:
            raise_for_status(response)
        err = exc_info.value
        assert err.code == "URL_ANALYSIS_REPORT_UNAVAILABLE"
        assert err.required_report == "url_analysis"

    def test_raise_for_status_409_with_missing_details_graceful(self):
        body = {
            "statusCode": 409,
            "error": "Conflict",
            "message": "Report not available",
            "code": "DYNAMIC_REPORT_UNAVAILABLE",
        }
        response = httpx.Response(409, json=body)
        with pytest.raises(ReportUnavailableError) as exc_info:
            raise_for_status(response)
        err = exc_info.value
        assert err.code == "DYNAMIC_REPORT_UNAVAILABLE"
        assert err.submission_uuid is None
        assert err.required_report is None
        assert err.current_status is None
        assert err.available_reports == []

    def test_raise_for_status_409_with_malformed_details_ignores_bad_types(self):
        body = {
            "statusCode": 409,
            "error": "Conflict",
            "message": "Report not available",
            "code": "DYNAMIC_REPORT_UNAVAILABLE",
            "details": {
                "submissionUuid": 123,  # wrong type
                "requiredReport": ["dynamic"],  # wrong type
                "currentStatus": None,
                "availableReports": "not-a-list",  # wrong type
            },
        }
        response = httpx.Response(409, json=body)
        with pytest.raises(ReportUnavailableError) as exc_info:
            raise_for_status(response)
        err = exc_info.value
        assert err.submission_uuid is None
        assert err.required_report is None
        assert err.available_reports == []

    def test_raise_for_status_409_with_non_json_body(self):
        response = httpx.Response(409, content=b"plain text")
        with pytest.raises(ReportUnavailableError) as exc_info:
            raise_for_status(response)
        err = exc_info.value
        assert err.status_code == 409
        assert err.code is None
        assert err.required_report is None
