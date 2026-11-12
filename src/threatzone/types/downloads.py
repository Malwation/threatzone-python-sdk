"""Download-related type definitions."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import unquote

from pydantic import BaseModel, ConfigDict, Field

from .._streaming import AsyncDownloadResponse, DownloadResponse

if TYPE_CHECKING:
    import httpx

PdfReportStatusValue = (
    Literal["analysis_in_progress", "queued", "generating", "ready", "failed"] | str
)

IocExportFormat = Literal["csv", "text", "stix", "misp"]
"""File format of ``download_iocs()``. ``stix`` and ``misp`` need the ``stixReport`` plan
permission."""


class MediaFile(BaseModel):
    """A media file from dynamic analysis."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    content_type: str | None = Field(default=None, alias="contentType")
    size: int | None = None
    kind: str | None = None


class PdfReportStatus(BaseModel):
    """Generation state of the PDF report of a submission.

    ``retry_after_seconds`` is set while the status is ``queued`` or
    ``generating``. ``message`` is set for ``analysis_in_progress`` and
    ``failed``.
    """

    model_config = ConfigDict(populate_by_name=True)

    status: PdfReportStatusValue
    message: str | None = None
    retry_after_seconds: float | None = Field(default=None, alias="retryAfterSeconds")


def _header_text(response: httpx.Response, name: str) -> str | None:
    value = response.headers.get(name)
    return value or None


def _header_int(response: httpx.Response, name: str) -> int | None:
    value = _header_text(response, name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


class _UrlDownloadFileFacts:
    """Facts about the fetched file that the ``X-File-*``, ``X-Final-Url`` and
    ``X-Tls-Error`` headers carry."""

    def _read_file_facts(self, response: httpx.Response) -> None:
        raw_name = _header_text(response, "x-file-name")
        self._file_name = unquote(raw_name) if raw_name is not None else None
        self._detected_type = _header_text(response, "x-file-detected-type")
        self._mimetype = _header_text(response, "x-file-mimetype")
        self._file_size = _header_int(response, "x-file-size")
        self._sha256 = _header_text(response, "x-file-sha256")
        self._final_url = _header_text(response, "x-final-url")
        self._tls_error = _header_text(response, "x-tls-error")

    @property
    def file_name(self) -> str | None:
        """Filename of the fetched file, without ``.zip``."""
        return self._file_name

    @property
    def detected_type(self) -> str | None:
        """Content-detected file extension. ``None`` when detection found none."""
        return self._detected_type

    @property
    def mimetype(self) -> str | None:
        """Content-detected MIME type of the fetched file."""
        return self._mimetype

    @property
    def file_size(self) -> int | None:
        """Size of the fetched file in bytes. ``size`` is the size of the ZIP."""
        return self._file_size

    @property
    def sha256(self) -> str | None:
        """SHA-256 of the fetched file."""
        return self._sha256

    @property
    def final_url(self) -> str | None:
        """URL after the redirects."""
        return self._final_url

    @property
    def tls_error(self) -> str | None:
        """Certificate error code of the first TLS hop that failed verification. ``None``
        when every TLS hop verified."""
        return self._tls_error


def _zip_filename(file_name: str | None) -> str | None:
    return f"{file_name}.zip" if file_name is not None else None


class UrlDownloadFile(_UrlDownloadFileFacts, DownloadResponse):
    """Response of ``download_url()``.

    The body is an AES-256 ZIP with the password ``infected`` and one entry, the
    fetched file. ``read()``, ``iter_bytes()`` and ``save()`` give the ZIP bytes.
    ``filename`` is ``<file_name>.zip``.
    """

    def __init__(self, response: httpx.Response, *, stream_context: Any | None = None) -> None:
        self._read_file_facts(response)
        super().__init__(
            response, filename=_zip_filename(self._file_name), stream_context=stream_context
        )


class AsyncUrlDownloadFile(_UrlDownloadFileFacts, AsyncDownloadResponse):
    """Async version of ``UrlDownloadFile``."""

    def __init__(self, response: httpx.Response, *, stream_context: Any | None = None) -> None:
        self._read_file_facts(response)
        super().__init__(
            response, filename=_zip_filename(self._file_name), stream_context=stream_context
        )
