"""Streaming download primitives for the Threat.Zone Python SDK."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ._constants import CHUNK_SIZE

if TYPE_CHECKING:
    import httpx


class DownloadResponse:
    """Represents a streamed download response with multiple consumption options."""

    def __init__(
        self,
        response: httpx.Response,
        *,
        filename: str | None = None,
        stream_context: Any | None = None,
    ) -> None:
        self._response = response
        self._stream_context = stream_context
        self._closed = False
        self._consumed = False

        content_disposition = response.headers.get("content-disposition", "")
        if filename:
            self._filename = filename
        elif "filename=" in content_disposition:
            self._filename = content_disposition.split("filename=")[-1].strip('"')
        else:
            self._filename = "download"

        self._status_code = getattr(response, "status_code", 200)
        self._content_type = str(response.headers.get("content-type", "application/octet-stream"))

        content_length = response.headers.get("content-length")
        self._size: int | None = int(content_length) if content_length else None

    @property
    def filename(self) -> str:
        """The filename from the response headers."""
        return self._filename

    @property
    def content_type(self) -> str:
        """The content type of the response."""
        return self._content_type

    @property
    def status_code(self) -> int:
        """The HTTP status code of the response."""
        return self._status_code

    @property
    def size(self) -> int | None:
        """The content length in bytes, if available."""
        return self._size

    def _check_consumed(self) -> None:
        if self._consumed:
            raise RuntimeError("Response has already been consumed")

    def read(self) -> bytes:
        """Read the entire response content into memory."""
        self._check_consumed()
        self._consumed = True
        return self._response.read()

    def iter_bytes(self, chunk_size: int = CHUNK_SIZE) -> Iterator[bytes]:
        """Iterate over the response content in chunks."""
        self._check_consumed()
        self._consumed = True
        return self._response.iter_bytes(chunk_size=chunk_size)

    def save(self, path: str | Path) -> Path:
        """Save the response content to a file."""
        self._check_consumed()
        self._consumed = True

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "wb") as f:
            for chunk in self._response.iter_bytes(chunk_size=CHUNK_SIZE):
                f.write(chunk)

        return path

    def close(self) -> None:
        """Close the underlying response."""
        if self._closed:
            return
        self._closed = True

        if self._stream_context is not None:
            self._stream_context.__exit__(None, None, None)
            return

        self._response.close()

    def __enter__(self) -> DownloadResponse:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class AsyncDownloadResponse:
    """Async version of DownloadResponse."""

    def __init__(
        self,
        response: httpx.Response,
        *,
        filename: str | None = None,
        stream_context: Any | None = None,
    ) -> None:
        self._response = response
        self._stream_context = stream_context
        self._closed = False
        self._consumed = False

        content_disposition = response.headers.get("content-disposition", "")
        if filename:
            self._filename = filename
        elif "filename=" in content_disposition:
            self._filename = content_disposition.split("filename=")[-1].strip('"')
        else:
            self._filename = "download"

        self._status_code = getattr(response, "status_code", 200)
        self._content_type = str(response.headers.get("content-type", "application/octet-stream"))

        content_length = response.headers.get("content-length")
        self._size: int | None = int(content_length) if content_length else None

    @property
    def filename(self) -> str:
        """The filename from the response headers."""
        return self._filename

    @property
    def content_type(self) -> str:
        """The content type of the response."""
        return self._content_type

    @property
    def status_code(self) -> int:
        """The HTTP status code of the response."""
        return self._status_code

    @property
    def size(self) -> int | None:
        """The content length in bytes, if available."""
        return self._size

    def _check_consumed(self) -> None:
        if self._consumed:
            raise RuntimeError("Response has already been consumed")

    async def read(self) -> bytes:
        """Read the entire response content into memory."""
        self._check_consumed()
        self._consumed = True
        return await self._response.aread()

    async def iter_bytes(self, chunk_size: int = CHUNK_SIZE) -> AsyncIterator[bytes]:
        """Iterate over the response content in chunks."""
        self._check_consumed()
        self._consumed = True
        async for chunk in self._response.aiter_bytes(chunk_size=chunk_size):
            yield chunk

    async def save(self, path: str | Path) -> Path:
        """Save the response content to a file."""
        self._check_consumed()
        self._consumed = True

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "wb") as f:
            async for chunk in self._response.aiter_bytes(chunk_size=CHUNK_SIZE):
                f.write(chunk)

        return path

    async def close(self) -> None:
        """Close the underlying response."""
        if self._closed:
            return
        self._closed = True

        if self._stream_context is not None:
            await self._stream_context.__aexit__(None, None, None)
            return

        await self._response.aclose()

    async def __aenter__(self) -> AsyncDownloadResponse:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()
