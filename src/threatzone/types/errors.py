"""Standardized API error envelope.

Mirrors the canonical error contract emitted by `ApiException` /
`ApiExceptionFilter` in the Threat.Zone Public API (`api.exception.ts` and
`error.response.ts`).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

ApiErrorCode = Literal[
    "INVALID_UUID",
    "INVALID_QUERY_PARAM",
    "UNAUTHORIZED",
    "FORBIDDEN",
    "NOT_FOUND",
    "ANNOTATION_PIN_LIMIT_REACHED",
    "ANNOTATION_PIN_NOT_FOUND",
    "SUBMISSION_PRIVATE",
    "SUBMISSION_NOT_FOUND",
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
    "INTERNAL_ERROR",
    "STORAGE_UNAVAILABLE",
    "BEHAVIOUR_INDEXING",
    "BEHAVIOUR_TOO_LARGE",
    "BEHAVIOUR_UNREADABLE",
]


class ApiError(BaseModel):
    """Canonical error envelope returned by the public API."""

    model_config = ConfigDict(populate_by_name=True)

    status_code: int
    error: str
    message: str
    code: ApiErrorCode
    # Structured context. Free-form: shape depends on the error code.
    details: dict[str, Any] | None = None
