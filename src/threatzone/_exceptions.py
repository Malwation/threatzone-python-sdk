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
    """Base exception for API errors with HTTP response details.

    Attributes:
        code: The machine-readable error code from the response envelope, for example
            ``WORKSPACE_INACTIVE`` or ``PLAN_API_ACCESS_DENIED``. ``None`` when the
            response has no JSON error envelope.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        response: httpx.Response | None = None,
        body: dict[str, Any] | None = None,
        code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response = response
        self.body = body
        self.code: str | None = code if code is not None else _body_code(body)

    def __str__(self) -> str:
        return f"{self.message} (status_code={self.status_code})"


class AuthenticationError(APIError):
    """Raised when API key is invalid or missing (HTTP 401)."""


class PaymentRequiredError(APIError):
    """Raised when the workspace is not active (HTTP 402, ``WORKSPACE_INACTIVE``).

    Renew the plan or contact the workspace owner.
    """


class PermissionDeniedError(APIError):
    """Raised when access is denied (HTTP 403).

    ``code`` is ``FORBIDDEN`` for a missing plan permission or module,
    ``PLAN_API_ACCESS_DENIED`` when the plan has no API access (a retry does not help),
    or ``LICENSE_INVALID``.
    """


class NotFoundError(APIError):
    """Raised when the requested resource is not found (HTTP 404)."""


class BadRequestError(APIError):
    """Raised when the request is invalid (HTTP 400, ``INVALID_QUERY_PARAM``)."""

    @property
    def field(self) -> str | None:
        """Path of the first field that failed validation (``details.field``), for example
        ``limit``. A nested field uses dots. ``None`` when the server does not send it."""
        value = _details(self.body).get("field")
        return value if isinstance(value, str) else None


class RateLimitError(APIError):
    """Raised when rate limit is exceeded (HTTP 429).

    Attributes:
        code: The machine-readable error code from the response envelope:
            ``RATE_LIMIT_EXCEEDED`` for the heavy-route limit and the monthly API request
            limit, ``SUBMISSION_LIMIT_EXCEEDED`` for the daily and concurrent submission
            limits, or ``AI_REPORT_QUOTA_EXCEEDED`` for the daily AI report quota. ``None``
            when an older server omits the code.
        retry_after: Seconds until the rate limit resets. The SDK reads the
            ``Retry-After`` header, and the ``retryAfter`` body field when the header is
            absent or is not a number.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 429,
        response: httpx.Response | None = None,
        body: dict[str, Any] | None = None,
        retry_after: float | None = None,
        code: str | None = None,
    ) -> None:
        super().__init__(message, status_code=status_code, response=response, body=body, code=code)
        self.retry_after = retry_after

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
        super().__init__(message, status_code=status_code, response=response, body=body, code=code)
        self.submission_uuid = submission_uuid
        self.required_report = required_report
        self.current_status = current_status
        self.available_reports = available_reports or []

    def __str__(self) -> str:
        base = super().__str__()
        if self.required_report:
            return f"{base} (required_report={self.required_report}, current_status={self.current_status})"
        return base


class BehaviourIndexingError(ReportUnavailableError):
    """Raised when the behaviour index of a submission is not ready.

    The routes that read the behaviour index raise it: ``get_behaviours()`` with an
    index parameter, ``get_behaviour_summary()``, ``get_behaviour_facets()`` and
    ``get_behaviour_matches()``. Current servers return ``503 BEHAVIOUR_INDEX_BUILDING``,
    which raises the subclass ``BehaviourIndexBuildingError``. Older servers return
    ``409 BEHAVIOUR_INDEXING``. Retry after ``retry_after`` seconds, or call
    ``get_behaviours()`` without the index parameters.

    Attributes:
        retry_after: Seconds to wait before a retry (``details.retryAfterSeconds``).
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 409,
        response: httpx.Response | None = None,
        body: dict[str, Any] | None = None,
        code: str | None = "BEHAVIOUR_INDEXING",
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message, status_code=status_code, response=response, body=body, code=code)
        self.retry_after = retry_after

    def __str__(self) -> str:
        base = super().__str__()
        if self.retry_after is not None:
            return f"{base} (retry_after={self.retry_after}s)"
        return base


class BehaviourTooLargeError(APIError):
    """Raised when behaviour data is too large for the route (HTTP 413).

    Maps the code ``BEHAVIOUR_TOO_LARGE``. The behaviour file is above the
    read limit of ``get_behaviours()``, or an index filter needs a scan above
    that limit. Narrow the filter, or call ``download_behaviour()``.

    Attributes:
        code: The machine-readable error code from the response envelope.
        size_bytes: The size of the file, or of the row scan, in bytes.
        max_bytes: The read limit of the route in bytes.
        download_route: The raw download route that the server names.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 413,
        response: httpx.Response | None = None,
        body: dict[str, Any] | None = None,
        code: str | None = "BEHAVIOUR_TOO_LARGE",
        size_bytes: int | None = None,
        max_bytes: int | None = None,
        download_route: str | None = None,
    ) -> None:
        super().__init__(message, status_code=status_code, response=response, body=body, code=code)
        self.size_bytes = size_bytes
        self.max_bytes = max_bytes
        self.download_route = download_route


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
        super().__init__(message, status_code=status_code, response=response, body=body)
        self.retry_after = retry_after

    def __str__(self) -> str:
        base = super().__str__()
        if self.retry_after is not None:
            return f"{base} (retry_after={self.retry_after}s)"
        return base


class PdfReportPendingError(APIError):
    """Raised when the PDF report is not ready (HTTP 202).

    ``download_pdf_report(wait=False)`` raises it when the server answers 202.
    ``download_pdf_report(wait=True)`` raises it when the report is not ready
    before the timeout.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 202,
        response: httpx.Response | None = None,
        body: dict[str, Any] | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message, status_code=status_code, response=response, body=body)
        self.retry_after = retry_after

    def __str__(self) -> str:
        base = super().__str__()
        if self.retry_after is not None:
            return f"{base} (retry_after={self.retry_after}s)"
        return base


class InternalServerError(APIError):
    """Raised when a server error occurs (HTTP 5xx)."""


class ServiceUnavailableError(InternalServerError):
    """Raised when the server is busy or a dependency is down (HTTP 503).

    Every ``503`` of the API has a ``Retry-After`` header and ``details.retryAfterSeconds``.
    The SDK retries idempotent requests on ``503`` when the wait is short. Retry other
    requests after ``retry_after`` seconds.

    Attributes:
        retry_after: Seconds to wait before a retry. The SDK reads the ``Retry-After``
            header, then the ``retryAfter`` body field, then ``details.retryAfterSeconds``.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 503,
        response: httpx.Response | None = None,
        body: dict[str, Any] | None = None,
        code: str | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message, status_code=status_code, response=response, body=body, code=code)
        self.retry_after = retry_after

    def __str__(self) -> str:
        base = super().__str__()
        if self.retry_after is not None:
            return f"{base} (retry_after={self.retry_after}s)"
        return base


class BehaviourIndexBuildingError(BehaviourIndexingError, ServiceUnavailableError):
    """Raised when the behaviour index is being built (HTTP 503, ``BEHAVIOUR_INDEX_BUILDING``).

    The behaviour index routes ask the platform to build a missing index and answer from a
    direct read of the behaviour file. When that read cannot answer the request, they return
    this error. Retry after ``retry_after`` seconds. It is a ``BehaviourIndexingError``, so
    code that handles the older ``409 BEHAVIOUR_INDEXING`` also handles it.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 503,
        response: httpx.Response | None = None,
        body: dict[str, Any] | None = None,
        code: str | None = "BEHAVIOUR_INDEX_BUILDING",
        retry_after: float | None = None,
    ) -> None:
        super().__init__(
            message,
            status_code=status_code,
            response=response,
            body=body,
            code=code,
            retry_after=retry_after,
        )

    def __str__(self) -> str:
        base = APIError.__str__(self)
        if self.retry_after is not None:
            return f"{base} (retry_after={self.retry_after}s)"
        return base


class QuotaUnavailableError(ServiceUnavailableError):
    """Raised when the server cannot check the submission quota (HTTP 503).

    Maps the code ``QUOTA_UNAVAILABLE``. The create routes and
    ``restart_url_analysis()`` raise it. The server did not create a submission. Retry
    after ``retry_after`` seconds.

    Attributes:
        code: The machine-readable error code from the response envelope.
        retry_after: Seconds to wait before a retry. The SDK reads the ``Retry-After``
            header, and the ``retryAfter`` body field when the header is absent or is
            not a number.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 503,
        response: httpx.Response | None = None,
        body: dict[str, Any] | None = None,
        code: str | None = "QUOTA_UNAVAILABLE",
        retry_after: float | None = None,
    ) -> None:
        super().__init__(
            message,
            status_code=status_code,
            response=response,
            body=body,
            code=code,
            retry_after=retry_after,
        )


class BehaviourUnreadableError(InternalServerError):
    """Raised when the stored behaviour file is not a valid JSON array (HTTP 502).

    Maps the code ``BEHAVIOUR_UNREADABLE``.

    Attributes:
        code: The machine-readable error code from the response envelope.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 502,
        response: httpx.Response | None = None,
        body: dict[str, Any] | None = None,
        code: str | None = "BEHAVIOUR_UNREADABLE",
    ) -> None:
        super().__init__(message, status_code=status_code, response=response, body=body, code=code)


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


def _body_code(body: dict[str, Any] | None) -> str | None:
    code = body.get("code") if body is not None else None
    return code if isinstance(code, str) else None


def _details(body: dict[str, Any] | None) -> dict[str, Any]:
    details = body.get("details") if body is not None else None
    return details if isinstance(details, dict) else {}


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _body_number(body: dict[str, Any] | None, key: str) -> float | None:
    return _as_number(body.get(key)) if body is not None else None


def _detail_number(body: dict[str, Any] | None, key: str) -> float | None:
    return _as_number(_details(body).get(key))


def _header_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def retry_after_seconds(response: httpx.Response, body: dict[str, Any] | None) -> float | None:
    """Seconds to wait from the ``Retry-After`` header, the ``retryAfter`` body field or
    ``details.retryAfterSeconds``, in that order."""
    for seconds in (
        _header_seconds(response.headers.get("retry-after")),
        _body_number(body, "retryAfter"),
        _detail_number(body, "retryAfterSeconds"),
    ):
        if seconds is not None:
            return seconds
    return None


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
        if code == "BEHAVIOUR_INDEXING":
            raise BehaviourIndexingError(
                message,
                status_code=status_code,
                response=response,
                body=body,
                code=code,
                retry_after=_detail_number(body, "retryAfterSeconds"),
            )
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
    elif status_code == 413 and _body_code(body) == "BEHAVIOUR_TOO_LARGE":
        size_bytes = _detail_number(body, "sizeBytes")
        max_bytes = _detail_number(body, "maxBytes")
        download_route = _details(body).get("downloadRoute")
        raise BehaviourTooLargeError(
            message,
            status_code=status_code,
            response=response,
            body=body,
            size_bytes=int(size_bytes) if size_bytes is not None else None,
            max_bytes=int(max_bytes) if max_bytes is not None else None,
            download_route=download_route if isinstance(download_route, str) else None,
        )
    elif status_code == 429:
        raise RateLimitError(
            message,
            status_code=status_code,
            response=response,
            body=body,
            retry_after=retry_after_seconds(response, body),
            code=_body_code(body),
        )
    elif status_code == 503:
        unavailable_class: type[ServiceUnavailableError] = {
            "QUOTA_UNAVAILABLE": QuotaUnavailableError,
            "BEHAVIOUR_INDEX_BUILDING": BehaviourIndexBuildingError,
        }.get(_body_code(body) or "", ServiceUnavailableError)
        raise unavailable_class(
            message,
            status_code=status_code,
            response=response,
            body=body,
            code=_body_code(body),
            retry_after=retry_after_seconds(response, body),
        )
    elif status_code == 502 and _body_code(body) == "BEHAVIOUR_UNREADABLE":
        raise BehaviourUnreadableError(
            message, status_code=status_code, response=response, body=body
        )
    elif status_code >= 500:
        raise InternalServerError(message, status_code=status_code, response=response, body=body)
    else:
        raise APIError(message, status_code=status_code, response=response, body=body)
