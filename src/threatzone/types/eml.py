"""EML analysis type definitions.

Mirrors the `EmlAnalysisDto` family from the `indicators.response.dto.ts`
DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class EmlAnalysisHeaders(BaseModel):
    """Parsed email headers."""

    model_config = ConfigDict(populate_by_name=True)

    message_id: str
    subject: str
    date: str
    from_email: str
    to_emails: list[str]
    cc_emails: list[str]
    bcc_emails: list[str]


class EmlAnalysisAttachment(BaseModel):
    """An email attachment."""

    model_config = ConfigDict(populate_by_name=True)

    filename: str
    size: int
    extension: str
    mime_type: str
    hash: dict[str, str]


class EmlAnalysisQrResult(BaseModel):
    """A QR code detected inside the email body or attachments."""

    model_config = ConfigDict(populate_by_name=True)

    data: str
    filename: str


class EmlAnalysis(BaseModel):
    """Parsed analysis of a single .eml artifact."""

    model_config = ConfigDict(populate_by_name=True)

    headers: EmlAnalysisHeaders
    other_headers: dict[str, str]
    attachments: list[EmlAnalysisAttachment]
    qr_results: list[EmlAnalysisQrResult]
    artifact: str = Field(alias="artifact")
