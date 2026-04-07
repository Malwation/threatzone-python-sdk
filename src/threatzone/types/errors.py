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
    "SUBMISSION_PRIVATE",
    "SUBMISSION_NOT_FOUND",
    "ARTIFACT_NOT_FOUND",
    "SAMPLE_NOT_AVAILABLE",
    "MEDIA_NOT_FOUND",
    "DYNAMIC_REPORT_UNAVAILABLE",
    "STATIC_REPORT_UNAVAILABLE",
    "CDR_REPORT_UNAVAILABLE",
    "URL_ANALYSIS_REPORT_UNAVAILABLE",
    "RATE_LIMIT_EXCEEDED",
    "SUBMISSION_LIMIT_EXCEEDED",
    "INTERNAL_ERROR",
    "STORAGE_UNAVAILABLE",
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
