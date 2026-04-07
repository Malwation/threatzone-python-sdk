"""Base HTTP client logic for the Threat.Zone Python SDK."""

from __future__ import annotations

import contextlib
import time
from collections.abc import Mapping
from io import IOBase
from pathlib import Path
from typing import Any, BinaryIO

import httpx

from ._config import ClientConfig
from ._exceptions import (
    ConnectionError,
    TimeoutError,
    raise_for_status,
)
from ._streaming import AsyncDownloadResponse, DownloadResponse

FileInput = BinaryIO | bytes | str | Path | IOBase


class BaseClient:
    """Base class with shared HTTP logic for sync and async clients."""

    def __init__(self, config: ClientConfig) -> None:
        self._config = config
        self._file_stack: contextlib.ExitStack = contextlib.ExitStack()

    def _prepare_file_upload(
        self,
        file: FileInput,
        field_name: str = "file",
    ) -> tuple[str, tuple[str, BinaryIO | bytes | IOBase, str]]:
        """Prepare a file for multipart upload.

        For file paths, opens the file and passes the handle directly to enable
        streaming uploads without loading the entire file into memory.
        """
        content: BinaryIO | bytes | IOBase
        if isinstance(file, (str, Path)):
            path = Path(file)
            file_handle = self._file_stack.enter_context(path.open("rb"))
            filename = path.name
            content = file_handle
        elif isinstance(file, bytes):
            content = file
            filename = "file"
        elif hasattr(file, "read"):
            filename = Path(file.name).name if hasattr(file, "name") else "file"
            content = file
        else:
            raise TypeError(f"Unsupported file type: {type(file)}")

        return field_name, (filename, content, "application/octet-stream")

    def _cleanup_files(self) -> None:
        """Close any file handles opened during file upload preparation."""
        with contextlib.suppress(Exception):
            self._file_stack.close()
        self._file_stack = contextlib.ExitStack()

    def _build_multipart_data(
        self,
        file: FileInput,
        **fields: Any,
    ) -> dict[str, Any]:
        """Build multipart form data with file and additional fields."""
        file_tuple = self._prepare_file_upload(file)

        files = {file_tuple[0]: file_tuple[1]}

        data: dict[str, Any] = {}
        for key, value in fields.items():
            if value is None:
                continue
            if key == "metafields" and isinstance(value, list):
                # Accept both formats:
                # - {"timeout": 120, "internet_connection": True}
                # - [{"key": "timeout", "value": 120}, ...]
                # Normalize to the object-map format expected by the Public API.
                normalized: dict[str, Any] = {}
                for item in value:
                    if not isinstance(item, dict) or "key" not in item:
                        raise TypeError(
                            "metafields list items must be dicts with at least a 'key' field"
                        )
                    k = str(item["key"])
                    normalized[k] = item.get("value")
                import json

                data[key] = json.dumps(normalized)
                continue
            if isinstance(value, bool):
                data[key] = str(value).lower()
            elif isinstance(value, (list, dict)):
                import json

                data[key] = json.dumps(value)
            else:
                data[key] = str(value)

        return {"files": files, "data": data}


class SyncHTTPClient(BaseClient):
    """Synchronous HTTP client wrapper."""

    def __init__(
        self,
        config: ClientConfig,
        *,
        http_client: httpx.Client | None = None,
    ) -> None:
        super().__init__(config)
        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            self._client = httpx.Client(
                timeout=httpx.Timeout(config.timeout),
                follow_redirects=True,
                verify=config.verify_ssl,
            )
            self._owns_client = True

    def close(self) -> None:
        """Close the HTTP client.

        If the client was supplied by the caller via ``http_client=``, the SDK does not
        close it — the caller retains ownership and is responsible for cleanup.
        """
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> SyncHTTPClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any | None = None,
        data: Mapping[str, Any] | None = None,
        files: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        """Make an HTTP request with error handling and retries."""
        url = self._config.build_url(path)
        request_headers = {**self._config.get_headers(), **(headers or {})}

        filtered_params = None
        if params:
            filtered_params = {k: v for k, v in params.items() if v is not None}

        last_error: Exception | None = None

        for attempt in range(self._config.max_retries + 1):
            try:
                response = self._client.request(
                    method,
                    url,
                    params=filtered_params,
                    json=json,
                    data=data,
                    files=files,
                    headers=request_headers,
                )
                raise_for_status(response)
                return response
            except httpx.TimeoutException as e:
                last_error = TimeoutError(f"Request timed out: {e}")
                if attempt == self._config.max_retries:
                    raise last_error from e
            except httpx.ConnectError as e:
                last_error = ConnectionError(f"Failed to connect: {e}")
                if attempt == self._config.max_retries:
                    raise last_error from e
            except Exception:
                raise

            time.sleep(2**attempt)

        raise last_error or RuntimeError("Unexpected error in request retry loop")

    def get(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        """Make a GET request."""
        return self._request("GET", path, params=params)

    def post(
        self,
        path: str,
        *,
        json: Any | None = None,
        data: Mapping[str, Any] | None = None,
        files: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        """Make a POST request."""
        try:
            return self._request("POST", path, json=json, data=data, files=files)
        finally:
            self._cleanup_files()

    def get_stream(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> DownloadResponse:
        """Make a GET request and return a streaming response."""
        url = self._config.build_url(path)
        headers = self._config.get_headers()

        filtered_params = None
        if params:
            filtered_params = {k: v for k, v in params.items() if v is not None}

        stream_context = self._client.stream(
            "GET",
            url,
            params=filtered_params,
            headers=headers,
        )
        try:
            response = stream_context.__enter__()
        except httpx.TimeoutException as e:
            raise TimeoutError(f"Request timed out: {e}") from e
        except httpx.ConnectError as e:
            raise ConnectionError(f"Failed to connect: {e}") from e
        try:
            raise_for_status(response)
            return DownloadResponse(response, stream_context=stream_context)
        except Exception:
            stream_context.__exit__(None, None, None)
            raise


class AsyncHTTPClient(BaseClient):
    """Asynchronous HTTP client wrapper."""

    def __init__(
        self,
        config: ClientConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__(config)
        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(config.timeout),
                follow_redirects=True,
                verify=config.verify_ssl,
            )
            self._owns_client = True

    async def close(self) -> None:
        """Close the HTTP client.

        If the client was supplied by the caller via ``http_client=``, the SDK does not
        close it — the caller retains ownership and is responsible for cleanup.
        """
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> AsyncHTTPClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json: Any | None = None,
        data: Mapping[str, Any] | None = None,
        files: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        """Make an HTTP request with error handling and retries."""
        import asyncio

        url = self._config.build_url(path)
        request_headers = {**self._config.get_headers(), **(headers or {})}

        filtered_params = None
        if params:
            filtered_params = {k: v for k, v in params.items() if v is not None}

        last_error: Exception | None = None

        for attempt in range(self._config.max_retries + 1):
            try:
                response = await self._client.request(
                    method,
                    url,
                    params=filtered_params,
                    json=json,
                    data=data,
                    files=files,
                    headers=request_headers,
                )
                raise_for_status(response)
                return response
            except httpx.TimeoutException as e:
                last_error = TimeoutError(f"Request timed out: {e}")
                if attempt == self._config.max_retries:
                    raise last_error from e
            except httpx.ConnectError as e:
                last_error = ConnectionError(f"Failed to connect: {e}")
                if attempt == self._config.max_retries:
                    raise last_error from e
            except Exception:
                raise

            await asyncio.sleep(2**attempt)

        raise last_error or RuntimeError("Unexpected error in request retry loop")

    async def get(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        """Make a GET request."""
        return await self._request("GET", path, params=params)

    async def post(
        self,
        path: str,
        *,
        json: Any | None = None,
        data: Mapping[str, Any] | None = None,
        files: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        """Make a POST request."""
        try:
            return await self._request("POST", path, json=json, data=data, files=files)
        finally:
            self._cleanup_files()

    async def get_stream(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> AsyncDownloadResponse:
        """Make a GET request and return a streaming response."""
        url = self._config.build_url(path)
        headers = self._config.get_headers()

        filtered_params = None
        if params:
            filtered_params = {k: v for k, v in params.items() if v is not None}

        stream_context = self._client.stream(
            "GET",
            url,
            params=filtered_params,
            headers=headers,
        )
        try:
            response = await stream_context.__aenter__()
        except httpx.TimeoutException as e:
            raise TimeoutError(f"Request timed out: {e}") from e
        except httpx.ConnectError as e:
            raise ConnectionError(f"Failed to connect: {e}") from e
        try:
            raise_for_status(response)
            return AsyncDownloadResponse(response, stream_context=stream_context)
        except Exception:
            await stream_context.__aexit__(None, None, None)
            raise
