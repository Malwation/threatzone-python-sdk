"""URL analysis type definitions.

Mirrors the `url-analysis.response.dto.ts` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .common import ReportStatusValue, ThreatLevel


class UrlAnalysisThreatStatus(BaseModel):
    """Verdict bag attached to URL analysis sub-objects (page, IP, file)."""

    model_config = ConfigDict(populate_by_name=True)

    verdict: ThreatLevel
    title: str
    description: str


class UrlAnalysisGeneralInfo(BaseModel):
    """Basic facts about the analysed URL."""

    model_config = ConfigDict(populate_by_name=True)

    url: str
    domain: str
    website_title: str | None = Field(default=None, alias="websiteTitle")


class UrlAnalysisScreenshot(BaseModel):
    """Screenshot availability flag."""

    model_config = ConfigDict(populate_by_name=True)

    available: bool


class UrlAnalysisIpInfo(BaseModel):
    """Resolved IP information for the analysed URL."""

    model_config = ConfigDict(populate_by_name=True)

    ip: str
    asn: str | None = None
    city: str | None = None
    country: str | None = None
    isp: str | None = None
    organization: str | None = None
    threat_status: UrlAnalysisThreatStatus = Field(alias="threatStatus")


class UrlAnalysisDnsRecord(BaseModel):
    """DNS records grouped by record type."""

    model_config = ConfigDict(populate_by_name=True)

    type: str
    records: list[str]


class UrlAnalysisWhoisInfo(BaseModel):
    """WHOIS record for the analysed domain."""

    model_config = ConfigDict(populate_by_name=True)

    domain_name: str | None = Field(default=None, alias="domainName")
    domain_id: str | None = Field(default=None, alias="domainId")
    name_servers: list[str] = Field(alias="nameServers")
    creation_date: str | None = Field(default=None, alias="creationDate")
    updated_date: str | None = Field(default=None, alias="updatedDate")
    expiration_date: str | None = Field(default=None, alias="expirationDate")
    registrar: str | None = None
    registrar_iana_id: str | None = Field(default=None, alias="registrarIanaId")
    email: str | None = None
    phone: str | None = None


class UrlAnalysisSslCertificate(BaseModel):
    """Parsed leaf TLS certificate for the analysed URL."""

    model_config = ConfigDict(populate_by_name=True)

    subject: str
    issuer: str
    renewed_at: int = Field(alias="renewedAt")
    expires_at: int = Field(alias="expiresAt")
    serial_number: str = Field(alias="serialNumber")
    fingerprint: str


class UrlAnalysisExtractedFile(BaseModel):
    """A file the analyser extracted from the page."""

    model_config = ConfigDict(populate_by_name=True)

    uuid: str
    threat_status: UrlAnalysisThreatStatus = Field(alias="threatStatus")


class UrlAnalysisThreatOverviewItem(BaseModel):
    """A per-source verdict in the URL threat analysis overview."""

    model_config = ConfigDict(populate_by_name=True)

    source: str
    title: str
    description: str
    verdict: ThreatLevel


class UrlAnalysisThreatDetailItem(BaseModel):
    """A per-source detail payload in the URL threat analysis."""

    model_config = ConfigDict(populate_by_name=True)

    source: str
    # Free-form: shape varies per intelligence source.
    details: dict[str, Any] | None = None


class UrlAnalysisThreatAnalysis(BaseModel):
    """Aggregated threat intelligence for the analysed URL."""

    model_config = ConfigDict(populate_by_name=True)

    overview: list[UrlAnalysisThreatOverviewItem]
    blacklist: bool
    threat_details: list[UrlAnalysisThreatDetailItem] = Field(alias="threatDetails")


class UrlAnalysisResponse(BaseModel):
    """Full URL analysis report payload."""

    model_config = ConfigDict(populate_by_name=True)

    level: ThreatLevel
    status: ReportStatusValue
    general_info: UrlAnalysisGeneralInfo = Field(alias="generalInfo")
    screenshot: UrlAnalysisScreenshot
    ip_info: UrlAnalysisIpInfo | None = Field(default=None, alias="ipInfo")
    dns_records: list[UrlAnalysisDnsRecord] = Field(alias="dnsRecords")
    whois: UrlAnalysisWhoisInfo | None = None
    ssl_certificate: UrlAnalysisSslCertificate | None = Field(default=None, alias="sslCertificate")
    # Free-form: header names are not normalised by the API.
    response_headers: dict[str, Any] | None = Field(default=None, alias="responseHeaders")
    extracted_file: UrlAnalysisExtractedFile | None = Field(default=None, alias="extractedFile")
    threat_analysis: UrlAnalysisThreatAnalysis | None = Field(default=None, alias="threatAnalysis")
    pages: list[str]
