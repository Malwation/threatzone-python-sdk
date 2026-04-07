"""Tests for Threat.Zone Python SDK HTTP client primitives."""

from __future__ import annotations

import io
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from threatzone._client import AsyncHTTPClient, BaseClient, SyncHTTPClient
from threatzone._config import ClientConfig
from threatzone._exceptions import ConnectionError, TimeoutError
from threatzone._streaming import AsyncDownloadResponse, DownloadResponse


@pytest.fixture
def config():
    """Create a test config."""
    return ClientConfig(
        api_key="test-key",
        base_url="https://test.threat.zone",
        timeout=30.0,
        max_retries=2,
        verify_ssl=False,
    )


class TestBaseClient:
    """Tests for BaseClient file handling."""

    def test_prepare_file_upload_from_path(self, config: ClientConfig):
        client = BaseClient(config)

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"MZ executable content")
            temp_path = f.name

        try:
            field_name, (filename, content, content_type) = client._prepare_file_upload(temp_path)

            assert field_name == "file"
            assert filename.endswith(".exe")
            assert hasattr(content, "read")
            assert content.read() == b"MZ executable content"
            assert content_type == "application/octet-stream"
        finally:
            client._cleanup_files()
            Path(temp_path).unlink()

    def test_prepare_file_upload_from_path_object(self, config: ClientConfig):
        client = BaseClient(config)

        with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as f:
            f.write(b"DLL content")
            temp_path = Path(f.name)

        try:
            field_name, (filename, content, content_type) = client._prepare_file_upload(temp_path)

            assert field_name == "file"
            assert filename.endswith(".dll")
            assert hasattr(content, "read")
            assert content.read() == b"DLL content"
        finally:
            client._cleanup_files()
            temp_path.unlink()

    def test_prepare_file_upload_from_bytes(self, config: ClientConfig):
        client = BaseClient(config)

        field_name, (filename, content, content_type) = client._prepare_file_upload(
            b"raw bytes content"
        )

        assert field_name == "file"
        assert filename == "file"
        assert content == b"raw bytes content"
        assert content_type == "application/octet-stream"

    def test_prepare_file_upload_from_file_object(self, config: ClientConfig):
        client = BaseClient(config)

        file_obj = io.BytesIO(b"file object content")
        file_obj.name = "/path/to/sample.bin"

        field_name, (filename, content, content_type) = client._prepare_file_upload(file_obj)

        assert field_name == "file"
        assert filename == "sample.bin"
        assert content is file_obj

    def test_prepare_file_upload_from_file_object_no_name(self, config: ClientConfig):
        client = BaseClient(config)

        file_obj = io.BytesIO(b"anonymous content")

        field_name, (filename, content, content_type) = client._prepare_file_upload(file_obj)

        assert field_name == "file"
        assert filename == "file"
        assert content is file_obj

    def test_prepare_file_upload_unsupported_type(self, config: ClientConfig):
        client = BaseClient(config)

        with pytest.raises(TypeError, match="Unsupported file type"):
            client._prepare_file_upload(12345)

    def test_prepare_file_upload_custom_field_name(self, config: ClientConfig):
        client = BaseClient(config)

        field_name, _ = client._prepare_file_upload(b"content", field_name="sample")

        assert field_name == "sample"

    def test_build_multipart_data_basic(self, config: ClientConfig):
        client = BaseClient(config)

        result = client._build_multipart_data(b"file content")

        assert "files" in result
        assert "data" in result
        assert "file" in result["files"]

    def test_build_multipart_data_with_string_field(self, config: ClientConfig):
        client = BaseClient(config)

        result = client._build_multipart_data(b"content", environment="w10_x64")

        assert result["data"]["environment"] == "w10_x64"

    def test_build_multipart_data_with_bool_field(self, config: ClientConfig):
        client = BaseClient(config)

        result = client._build_multipart_data(b"content", private=True)

        assert result["data"]["private"] == "true"

    def test_build_multipart_data_with_list_field(self, config: ClientConfig):
        client = BaseClient(config)

        result = client._build_multipart_data(b"content", tags=["malware", "trojan"])

        assert result["data"]["tags"] == '["malware", "trojan"]'

    def test_build_multipart_data_with_dict_field(self, config: ClientConfig):
        client = BaseClient(config)

        result = client._build_multipart_data(b"content", metafields={"timeout": 120})

        assert result["data"]["metafields"] == '{"timeout": 120}'

    def test_build_multipart_data_with_metafields_kv_list(self, config: ClientConfig):
        import json

        client = BaseClient(config)

        result = client._build_multipart_data(
            b"content",
            metafields=[
                {"key": "timeout", "value": 120},
                {"key": "internet_connection", "value": True},
            ],
        )

        assert json.loads(result["data"]["metafields"]) == {
            "timeout": 120,
            "internet_connection": True,
        }

    def test_build_multipart_data_with_metafields_invalid_list(self, config: ClientConfig):
        client = BaseClient(config)

        with pytest.raises(TypeError, match="metafields list items"):
            client._build_multipart_data(b"content", metafields=["timeout"])

    def test_build_multipart_data_skips_none(self, config: ClientConfig):
        client = BaseClient(config)

        result = client._build_multipart_data(b"content", optional_field=None)

        assert "optional_field" not in result["data"]

    def test_build_multipart_data_converts_int(self, config: ClientConfig):
        client = BaseClient(config)

        result = client._build_multipart_data(b"content", timeout=120)

        assert result["data"]["timeout"] == "120"


class TestSyncHTTPClient:
    """Tests for SyncHTTPClient."""

    def test_context_manager(self, config: ClientConfig):
        with SyncHTTPClient(config) as client:
            assert client is not None

    def test_close(self, config: ClientConfig):
        client = SyncHTTPClient(config)
        client.close()

    def test_request_with_timeout_retry(self, config: ClientConfig):
        client = SyncHTTPClient(config)

        with patch.object(client._client, "request") as mock_request:
            mock_request.side_effect = [
                httpx.TimeoutException("timeout"),
                httpx.Response(200, json={"status": "ok"}),
            ]

            response = client._request("GET", "/test")

            assert response.status_code == 200
            assert mock_request.call_count == 2

        client.close()

    def test_request_with_timeout_exhausted(self, config: ClientConfig):
        client = SyncHTTPClient(config)

        with patch.object(client._client, "request") as mock_request:
            mock_request.side_effect = httpx.TimeoutException("timeout")

            with pytest.raises(TimeoutError, match="timed out"):
                client._request("GET", "/test")

            assert mock_request.call_count == 3  # Initial + 2 retries

        client.close()

    def test_request_with_connect_error_retry(self, config: ClientConfig):
        client = SyncHTTPClient(config)

        with patch.object(client._client, "request") as mock_request:
            mock_request.side_effect = [
                httpx.ConnectError("connection refused"),
                httpx.Response(200, json={"status": "ok"}),
            ]

            response = client._request("GET", "/test")

            assert response.status_code == 200

        client.close()

    def test_request_with_connect_error_exhausted(self, config: ClientConfig):
        client = SyncHTTPClient(config)

        with patch.object(client._client, "request") as mock_request:
            mock_request.side_effect = httpx.ConnectError("connection refused")

            with pytest.raises(ConnectionError, match="Failed to connect"):
                client._request("GET", "/test")

        client.close()

    def test_get_stream_success(self, config: ClientConfig):
        client = SyncHTTPClient(config)

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.is_success = True
        mock_response.headers = {"content-type": "application/octet-stream"}

        mock_stream_context = MagicMock()
        mock_stream_context.__enter__ = MagicMock(return_value=mock_response)

        with patch.object(client._client, "stream", return_value=mock_stream_context):
            result = client.get_stream("/download/sample")

            assert isinstance(result, DownloadResponse)
            result.close()
            mock_stream_context.__exit__.assert_called_once_with(None, None, None)

        client.close()

    def test_get_stream_timeout(self, config: ClientConfig):
        client = SyncHTTPClient(config)

        mock_stream_context = MagicMock()
        mock_stream_context.__enter__ = MagicMock(side_effect=httpx.TimeoutException("timeout"))

        with (
            patch.object(client._client, "stream", return_value=mock_stream_context),
            pytest.raises(TimeoutError, match="timed out"),
        ):
            client.get_stream("/download/sample")

        client.close()

    def test_get_stream_connect_error(self, config: ClientConfig):
        client = SyncHTTPClient(config)

        mock_stream_context = MagicMock()
        mock_stream_context.__enter__ = MagicMock(
            side_effect=httpx.ConnectError("connection refused")
        )

        with (
            patch.object(client._client, "stream", return_value=mock_stream_context),
            pytest.raises(ConnectionError, match="Failed to connect"),
        ):
            client.get_stream("/download/sample")

        client.close()

    def test_get_stream_with_params(self, config: ClientConfig):
        client = SyncHTTPClient(config)

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.is_success = True
        mock_response.headers = {}

        mock_stream_context = MagicMock()
        mock_stream_context.__enter__ = MagicMock(return_value=mock_response)

        with patch.object(
            client._client, "stream", return_value=mock_stream_context
        ) as mock_stream:
            client.get_stream("/download", params={"id": "123", "empty": None})

            call_kwargs = mock_stream.call_args[1]
            assert call_kwargs["params"] == {"id": "123"}

        client.close()


class TestAsyncHTTPClient:
    """Tests for AsyncHTTPClient."""

    @pytest.mark.asyncio
    async def test_async_context_manager(self, config: ClientConfig):
        async with AsyncHTTPClient(config) as client:
            assert client is not None

    @pytest.mark.asyncio
    async def test_close(self, config: ClientConfig):
        client = AsyncHTTPClient(config)
        await client.close()

    @pytest.mark.asyncio
    async def test_request_with_timeout_retry(self, config: ClientConfig):
        client = AsyncHTTPClient(config)

        call_count = 0

        async def mock_request(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise httpx.TimeoutException("timeout")
            return httpx.Response(200, json={"status": "ok"})

        with patch.object(client._client, "request", side_effect=mock_request):
            response = await client._request("GET", "/test")

            assert response.status_code == 200
            assert call_count == 2

        await client.close()

    @pytest.mark.asyncio
    async def test_request_with_timeout_exhausted(self, config: ClientConfig):
        client = AsyncHTTPClient(config)

        async def mock_request(*_args, **_kwargs):
            raise httpx.TimeoutException("timeout")

        with (
            patch.object(client._client, "request", side_effect=mock_request),
            pytest.raises(TimeoutError, match="timed out"),
        ):
            await client._request("GET", "/test")

        await client.close()

    @pytest.mark.asyncio
    async def test_request_with_connect_error_retry(self, config: ClientConfig):
        client = AsyncHTTPClient(config)

        call_count = 0

        async def mock_request(*_args, **_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise httpx.ConnectError("connection refused")
            return httpx.Response(200, json={"status": "ok"})

        with patch.object(client._client, "request", side_effect=mock_request):
            response = await client._request("GET", "/test")

            assert response.status_code == 200

        await client.close()

    @pytest.mark.asyncio
    async def test_request_with_connect_error_exhausted(self, config: ClientConfig):
        client = AsyncHTTPClient(config)

        async def mock_request(*_args, **_kwargs):
            raise httpx.ConnectError("connection refused")

        with (
            patch.object(client._client, "request", side_effect=mock_request),
            pytest.raises(ConnectionError, match="Failed to connect"),
        ):
            await client._request("GET", "/test")

        await client.close()

    @pytest.mark.asyncio
    async def test_get_stream_success(self, config: ClientConfig):
        client = AsyncHTTPClient(config)

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.is_success = True
        mock_response.headers = {"content-type": "application/octet-stream"}

        mock_stream_context = MagicMock()
        mock_stream_context.__aenter__ = AsyncMock(return_value=mock_response)
        mock_stream_context.__aexit__ = AsyncMock()

        with patch.object(client._client, "stream", return_value=mock_stream_context):
            result = await client.get_stream("/download/sample")

            assert isinstance(result, AsyncDownloadResponse)
            await result.close()
            mock_stream_context.__aexit__.assert_called_once_with(None, None, None)

        await client.close()

    @pytest.mark.asyncio
    async def test_get_stream_timeout(self, config: ClientConfig):
        client = AsyncHTTPClient(config)

        mock_stream_context = MagicMock()
        mock_stream_context.__aenter__ = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        with (
            patch.object(client._client, "stream", return_value=mock_stream_context),
            pytest.raises(TimeoutError, match="timed out"),
        ):
            await client.get_stream("/download/sample")

        await client.close()

    @pytest.mark.asyncio
    async def test_get_stream_connect_error(self, config: ClientConfig):
        client = AsyncHTTPClient(config)

        mock_stream_context = MagicMock()
        mock_stream_context.__aenter__ = AsyncMock(
            side_effect=httpx.ConnectError("connection refused")
        )

        with (
            patch.object(client._client, "stream", return_value=mock_stream_context),
            pytest.raises(ConnectionError, match="Failed to connect"),
        ):
            await client.get_stream("/download/sample")

        await client.close()

    @pytest.mark.asyncio
    async def test_get_stream_with_params(self, config: ClientConfig):
        client = AsyncHTTPClient(config)

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.is_success = True
        mock_response.headers = {}

        mock_stream_context = MagicMock()
        mock_stream_context.__aenter__ = AsyncMock(return_value=mock_response)

        with patch.object(
            client._client, "stream", return_value=mock_stream_context
        ) as mock_stream:
            await client.get_stream("/download", params={"id": "456", "null": None})

            call_kwargs = mock_stream.call_args[1]
            assert call_kwargs["params"] == {"id": "456"}

        await client.close()


class TestConfigBuildUrl:
    """Tests for ClientConfig.build_url edge cases."""

    def test_build_url_without_leading_slash(self):
        config = ClientConfig(
            api_key="test",
            base_url="https://api.threat.zone",
            timeout=30.0,
            max_retries=2,
            verify_ssl=False,
        )

        url = config.build_url("v1/submissions")

        assert url == "https://api.threat.zone/v1/submissions"

    def test_build_url_with_leading_slash(self):
        config = ClientConfig(
            api_key="test",
            base_url="https://api.threat.zone",
            timeout=30.0,
            max_retries=2,
            verify_ssl=False,
        )

        url = config.build_url("/v1/submissions")

        assert url == "https://api.threat.zone/v1/submissions"
