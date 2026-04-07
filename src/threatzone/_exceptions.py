"""Exception classes for the Threat.Zone Python SDK."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import httpx


class ThreatZoneError(Exception):
    """Base exception for all Threat.Zone Python SDK errors."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


class APIError(ThreatZoneError):
    """Base exception for API errors with HTTP response details."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        response: httpx.Response | None = None,
        body: dict[str, Any] | None = None,
    ) -> None:
        self.status_code = status_code
        self.response = response
        self.body = body
        super().__init__(message)

    def __str__(self) -> str:
        return f"{self.message} (status_code={self.status_code})"


class AuthenticationError(APIError):
    """Raised when API key is invalid or missing (HTTP 401)."""


class PaymentRequiredError(APIError):
    """Raised when workspace subscription is inactive (HTTP 402)."""


class PermissionDeniedError(APIError):
    """Raised when access is denied or module not available (HTTP 403)."""


class NotFoundError(APIError):
    """Raised when the requested resource is not found (HTTP 404)."""


class BadRequestError(APIError):
    """Raised when the request is invalid (HTTP 400)."""


class RateLimitError(APIError):
    """Raised when rate limit is exceeded (HTTP 429).

    Attributes:
        retry_after: Seconds until the rate limit resets (from Retry-After header).
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 429,
        response: httpx.Response | None = None,
        body: dict[str, Any] | None = None,
        retry_after: float | None = None,
    ) -> None:
        self.retry_after = retry_after
        super().__init__(message, status_code=status_code, response=response, body=body)

    def __str__(self) -> str:
        base = super().__str__()
        if self.retry_after:
            return f"{base} (retry_after={self.retry_after}s)"
        return base


class ReportUnavailableError(APIError):
    """Raised when a guarded report is not yet available (HTTP 409).

    Emitted by endpoints gated by `ReportStatusGuard` when the required report
    is missing, in progress, errored, or never produced. Maps the public API
    error codes `DYNAMIC_REPORT_UNAVAILABLE`, `STATIC_REPORT_UNAVAILABLE`,
    `CDR_REPORT_UNAVAILABLE`, and `URL_ANALYSIS_REPORT_UNAVAILABLE` into a
    typed exception so callers can branch on report state without parsing the
    error envelope.

    Attributes:
        code: The machine-readable error code from the response envelope.
        submission_uuid: The submission whose report could not be served.
        required_report: The report type the endpoint required (e.g. ``dynamic``).
        current_status: The current status of the required report, or ``None``
            when the report has not yet been scheduled.
        available_reports: Report types that ARE currently available for the
            submission (a hint for the caller to recover gracefully).
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 409,
        response: httpx.Response | None = None,
        body: dict[str, Any] | None = None,
        code: str | None = None,
        submission_uuid: str | None = None,
        required_report: str | None = None,
        current_status: str | None = None,
        available_reports: list[str] | None = None,
    ) -> None:
        self.code = code
        self.submission_uuid = submission_uuid
        self.required_report = required_report
        self.current_status = current_status
        self.available_reports = available_reports or []
        super().__init__(message, status_code=status_code, response=response, body=body)

    def __str__(self) -> str:
        base = super().__str__()
        if self.required_report:
            return f"{base} (required_report={self.required_report}, current_status={self.current_status})"
        return base


class YaraRulePendingError(APIError):
    """Raised when YARA rule generation is still in progress (HTTP 202)."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 202,
        response: httpx.Response | None = None,
        body: dict[str, Any] | None = None,
        retry_after: float | None = None,
    ) -> None:
        self.retry_after = retry_after
        super().__init__(message, status_code=status_code, response=response, body=body)

    def __str__(self) -> str:
        base = super().__str__()
        if self.retry_after is not None:
            return f"{base} (retry_after={self.retry_after}s)"
        return base


class InternalServerError(APIError):
    """Raised when a server error occurs (HTTP 5xx)."""


class TimeoutError(ThreatZoneError):
    """Raised when a request times out."""


class ConnectionError(ThreatZoneError):
    """Raised when a connection to the API fails."""


class AnalysisTimeoutError(ThreatZoneError):
    """Raised when wait_for_completion exceeds the specified timeout."""

    def __init__(self, message: str, *, uuid: str, elapsed: float) -> None:
        self.uuid = uuid
        self.elapsed = elapsed
        super().__init__(message)


def raise_for_status(response: httpx.Response) -> None:
    """Raise an appropriate exception based on HTTP status code."""
    if response.is_success:
        return

    body: dict[str, Any] | None = None
    message = response.reason_phrase or "Unknown error"
    try:
        parsed_body = response.json()
        if isinstance(parsed_body, dict):
            body = parsed_body
            parsed_message = parsed_body.get("message")
            if isinstance(parsed_message, str) and parsed_message.strip():
                message = parsed_message
    except (json.JSONDecodeError, ValueError):
        pass
    except Exception:
        # Streaming responses from httpx.Client.stream()/AsyncClient.stream() may
        # raise ResponseNotRead here if not yet consumed. Fall back to reason phrase.
        pass

    status_code = response.status_code

    if status_code == 400:
        raise BadRequestError(message, status_code=status_code, response=response, body=body)
    elif status_code == 401:
        raise AuthenticationError(message, status_code=status_code, response=response, body=body)
    elif status_code == 402:
        raise PaymentRequiredError(message, status_code=status_code, response=response, body=body)
    elif status_code == 403:
        raise PermissionDeniedError(message, status_code=status_code, response=response, body=body)
    elif status_code == 404:
        raise NotFoundError(message, status_code=status_code, response=response, body=body)
    elif status_code == 409:
        code: str | None = None
        submission_uuid: str | None = None
        required_report: str | None = None
        current_status: str | None = None
        available_reports: list[str] = []
        if isinstance(body, dict):
            raw_code = body.get("code")
            if isinstance(raw_code, str):
                code = raw_code
            details = body.get("details")
            if isinstance(details, dict):
                raw_uuid = details.get("submissionUuid")
                if isinstance(raw_uuid, str):
                    submission_uuid = raw_uuid
                raw_required = details.get("requiredReport")
                if isinstance(raw_required, str):
                    required_report = raw_required
                raw_current = details.get("currentStatus")
                if isinstance(raw_current, str):
                    current_status = raw_current
                raw_available = details.get("availableReports")
                if isinstance(raw_available, list):
                    available_reports = [item for item in raw_available if isinstance(item, str)]
        raise ReportUnavailableError(
            message,
            status_code=status_code,
            response=response,
            body=body,
            code=code,
            submission_uuid=submission_uuid,
            required_report=required_report,
            current_status=current_status,
            available_reports=available_reports,
        )
    elif status_code == 429:
        retry_after = response.headers.get("retry-after")
        raise RateLimitError(
            message,
            status_code=status_code,
            response=response,
            body=body,
            retry_after=float(retry_after) if retry_after else None,
        )
    elif status_code >= 500:
        raise InternalServerError(message, status_code=status_code, response=response, body=body)
    else:
        raise APIError(message, status_code=status_code, response=response, body=body)
