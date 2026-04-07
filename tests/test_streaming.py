"""Tests for Threat.Zone Python SDK streaming primitives."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from threatzone._streaming import AsyncDownloadResponse, DownloadResponse


class TestDownloadResponse:
    """Tests for sync DownloadResponse."""

    def test_init_with_filename_param(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}

        download = DownloadResponse(response, filename="custom.exe")

        assert download.filename == "custom.exe"

    def test_init_with_content_disposition(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {"content-disposition": 'attachment; filename="malware.dll"'}

        download = DownloadResponse(response)

        assert download.filename == "malware.dll"

    def test_init_with_default_filename(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}

        download = DownloadResponse(response)

        assert download.filename == "download"

    def test_init_extracts_content_type(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {"content-type": "application/x-msdownload"}
        response.status_code = 200

        download = DownloadResponse(response)

        assert download.content_type == "application/x-msdownload"

    def test_init_extracts_status_code(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}
        response.status_code = 202

        download = DownloadResponse(response)

        assert download.status_code == 202

    def test_init_default_content_type(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}

        download = DownloadResponse(response)

        assert download.content_type == "application/octet-stream"

    def test_init_extracts_content_length(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {"content-length": "12345"}

        download = DownloadResponse(response)

        assert download.size == 12345

    def test_init_no_content_length(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}

        download = DownloadResponse(response)

        assert download.size is None

    def test_read_returns_content(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}
        response.read.return_value = b"file content"

        download = DownloadResponse(response)
        content = download.read()

        assert content == b"file content"
        response.read.assert_called_once()

    def test_read_raises_if_consumed(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}
        response.read.return_value = b"content"

        download = DownloadResponse(response)
        download.read()

        with pytest.raises(RuntimeError, match="already been consumed"):
            download.read()

    def test_iter_bytes_returns_iterator(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}
        response.iter_bytes.return_value = iter([b"chunk1", b"chunk2"])

        download = DownloadResponse(response)
        chunks = list(download.iter_bytes(chunk_size=1024))

        assert chunks == [b"chunk1", b"chunk2"]
        response.iter_bytes.assert_called_once_with(chunk_size=1024)

    def test_iter_bytes_raises_if_consumed(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}
        response.iter_bytes.return_value = iter([b"chunk"])

        download = DownloadResponse(response)
        list(download.iter_bytes())

        with pytest.raises(RuntimeError, match="already been consumed"):
            list(download.iter_bytes())

    def test_save_writes_to_file(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}
        response.iter_bytes.return_value = iter([b"chunk1", b"chunk2"])

        download = DownloadResponse(response)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "subdir" / "output.bin"
            result = download.save(path)

            assert result == path
            assert path.exists()
            assert path.read_bytes() == b"chunk1chunk2"

    def test_save_raises_if_consumed(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}
        response.read.return_value = b"content"

        download = DownloadResponse(response)
        download.read()

        with pytest.raises(RuntimeError, match="already been consumed"):
            download.save("/tmp/test.bin")

    def test_close_calls_response_close(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}

        download = DownloadResponse(response)
        download.close()

        response.close.assert_called_once()

    def test_close_calls_stream_context_exit_when_provided(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}
        stream_context = MagicMock()

        download = DownloadResponse(response, stream_context=stream_context)
        download.close()

        stream_context.__exit__.assert_called_once_with(None, None, None)
        response.close.assert_not_called()

    def test_context_manager(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}

        with DownloadResponse(response) as download:
            assert download is not None

        response.close.assert_called_once()


class TestAsyncDownloadResponse:
    """Tests for async AsyncDownloadResponse."""

    def test_init_with_filename_param(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}

        download = AsyncDownloadResponse(response, filename="custom.exe")

        assert download.filename == "custom.exe"

    def test_init_with_content_disposition(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {"content-disposition": 'attachment; filename="malware.dll"'}

        download = AsyncDownloadResponse(response)

        assert download.filename == "malware.dll"

    def test_init_with_default_filename(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}

        download = AsyncDownloadResponse(response)

        assert download.filename == "download"

    def test_init_extracts_content_type(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {"content-type": "application/x-msdownload"}
        response.status_code = 200

        download = AsyncDownloadResponse(response)

        assert download.content_type == "application/x-msdownload"

    def test_init_extracts_status_code(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}
        response.status_code = 202

        download = AsyncDownloadResponse(response)

        assert download.status_code == 202

    def test_init_extracts_content_length(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {"content-length": "99999"}

        download = AsyncDownloadResponse(response)

        assert download.size == 99999

    @pytest.mark.asyncio
    async def test_read_returns_content(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}
        response.aread = AsyncMock(return_value=b"async content")

        download = AsyncDownloadResponse(response)
        content = await download.read()

        assert content == b"async content"

    @pytest.mark.asyncio
    async def test_read_raises_if_consumed(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}
        response.aread = AsyncMock(return_value=b"content")

        download = AsyncDownloadResponse(response)
        await download.read()

        with pytest.raises(RuntimeError, match="already been consumed"):
            await download.read()

    @pytest.mark.asyncio
    async def test_iter_bytes_yields_chunks(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}

        async def mock_aiter_bytes(**_kwargs):
            yield b"chunk1"
            yield b"chunk2"

        response.aiter_bytes = mock_aiter_bytes

        download = AsyncDownloadResponse(response)
        chunks = [chunk async for chunk in download.iter_bytes(chunk_size=1024)]

        assert chunks == [b"chunk1", b"chunk2"]

    @pytest.mark.asyncio
    async def test_iter_bytes_raises_if_consumed(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}
        response.aread = AsyncMock(return_value=b"content")

        download = AsyncDownloadResponse(response)
        await download.read()

        with pytest.raises(RuntimeError, match="already been consumed"):
            async for _ in download.iter_bytes():
                pass

    @pytest.mark.asyncio
    async def test_save_writes_to_file(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}

        async def mock_aiter_bytes(**_kwargs):
            yield b"async1"
            yield b"async2"

        response.aiter_bytes = mock_aiter_bytes

        download = AsyncDownloadResponse(response)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nested" / "async_output.bin"
            result = await download.save(path)

            assert result == path
            assert path.exists()
            assert path.read_bytes() == b"async1async2"

    @pytest.mark.asyncio
    async def test_save_raises_if_consumed(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}
        response.aread = AsyncMock(return_value=b"content")

        download = AsyncDownloadResponse(response)
        await download.read()

        with pytest.raises(RuntimeError, match="already been consumed"):
            await download.save("/tmp/test.bin")

    @pytest.mark.asyncio
    async def test_close_calls_response_aclose(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}
        response.aclose = AsyncMock()

        download = AsyncDownloadResponse(response)
        await download.close()

        response.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_calls_stream_context_aexit_when_provided(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}
        response.aclose = AsyncMock()
        stream_context = MagicMock()
        stream_context.__aexit__ = AsyncMock()

        download = AsyncDownloadResponse(response, stream_context=stream_context)
        await download.close()

        stream_context.__aexit__.assert_called_once_with(None, None, None)
        response.aclose.assert_not_called()

    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        response = MagicMock(spec=httpx.Response)
        response.headers = {}
        response.aclose = AsyncMock()

        async with AsyncDownloadResponse(response) as download:
            assert download is not None

        response.aclose.assert_called_once()
