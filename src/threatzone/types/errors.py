"""Standardized API error envelope.

Mirrors the canonical error contract emitted by `ApiException` /
`ApiExceptionFilter` in the Threat.Zone Public API (`api.exception.ts` and
`error.response.ts`).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ApiErrorCode = (
    Literal[
        "INVALID_QUERY_PARAM",
        "UNAUTHORIZED",
        "LICENSE_INVALID",
        "FORBIDDEN",
        "NOT_FOUND",
        "METHOD_NOT_ALLOWED",
        "CONFLICT",
        "ANNOTATION_PIN_LIMIT_REACHED",
        "ANNOTATION_PIN_NOT_FOUND",
        "ARTIFACT_NOT_FOUND",
        "SAMPLE_NOT_AVAILABLE",
        "MEDIA_NOT_FOUND",
        "NETWORK_ROW_NOT_FOUND",
        "URL_SCORE_EVIDENCE_NOT_FOUND",
        "URL_BROWSER_SECTION_NOT_FOUND",
        "URL_BROWSER_SECTION_UNAVAILABLE",
        "DYNAMIC_REPORT_UNAVAILABLE",
        "STATIC_REPORT_UNAVAILABLE",
        "CDR_REPORT_UNAVAILABLE",
        "URL_ANALYSIS_REPORT_UNAVAILABLE",
        "RATE_LIMIT_EXCEEDED",
        "SUBMISSION_LIMIT_EXCEEDED",
        "QUOTA_UNAVAILABLE",
        "INTERNAL_ERROR",
        "STORAGE_UNAVAILABLE",
        "BEHAVIOUR_INDEXING",
        "BEHAVIOUR_TOO_LARGE",
        "BEHAVIOUR_UNREADABLE",
        "SAMPLE_INDEX_UNAVAILABLE",
        "SAMPLE_INDEX_ERROR",
        "SESSION_SERVICE_UNAVAILABLE",
        "SESSION_NOT_FOUND",
        "AI_REPORT_NOT_FOUND",
        "AI_REPORTS_DISABLED",
        "AI_REPORT_NOT_FINALIZED",
        "AI_REPORT_IN_PROGRESS",
        "AI_REPORT_QUOTA_EXCEEDED",
        "AI_REPORT_QUEUE_UNAVAILABLE",
    ]
    | str
)
"""The ``code`` values of the public API. Any other string is also accepted, so a code that
a newer server adds does not fail the parse."""


class ApiError(BaseModel):
    """Canonical error envelope returned by the public API."""

    model_config = ConfigDict(populate_by_name=True)

    status_code: int = Field(alias="statusCode")
    # The documented 500 body of the API has no error field.
    error: str | None = None
    message: str
    code: ApiErrorCode
    # Structured context. Free-form: shape depends on the error code.
    details: dict[str, Any] | None = None
