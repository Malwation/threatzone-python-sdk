"""Client configuration for the Threat.Zone Python SDK."""

from __future__ import annotations

import os
from dataclasses import dataclass

from ._constants import (
    API_KEY_ENV_VAR,
    DEFAULT_BASE_URL,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT,
)
from ._exceptions import AuthenticationError


@dataclass(frozen=True)
class ClientConfig:
    """Configuration for the Threat.Zone API client."""

    api_key: str
    base_url: str
    timeout: float
    max_retries: int
    verify_ssl: bool

    @classmethod
    def from_env(
        cls,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float | None = None,
        max_retries: int | None = None,
        verify_ssl: bool = False,
    ) -> ClientConfig:
        """Create a ClientConfig instance with defaults and environment variable fallback.

        Args:
            api_key: API key for authentication. Falls back to THREATZONE_API_KEY env var.
            base_url: Base URL for the API. Defaults to https://app.threat.zone/public-api.
            timeout: Request timeout in seconds. Defaults to 60.
            max_retries: Maximum number of retries for failed requests. Defaults to 2.
            verify_ssl: Whether to verify SSL certificates. Set to False for self-signed certs
                        in on-premise deployments. Defaults to False.
        """
        resolved_api_key = api_key or os.environ.get(API_KEY_ENV_VAR)

        if not resolved_api_key:
            raise AuthenticationError(
                f"API key is required. Provide it via the 'api_key' parameter "
                f"or set the {API_KEY_ENV_VAR} environment variable.",
                status_code=401,
            )

        resolved_base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")

        return cls(
            api_key=resolved_api_key,
            base_url=resolved_base_url,
            timeout=timeout if timeout is not None else DEFAULT_TIMEOUT,
            max_retries=max_retries if max_retries is not None else DEFAULT_MAX_RETRIES,
            verify_ssl=verify_ssl,
        )

    def get_headers(self) -> dict[str, str]:
        """Get HTTP headers for API requests."""
        from ._constants import USER_AGENT

        return {
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        }

    def build_url(self, path: str) -> str:
        """Build a full URL for the given API path."""
        if not path.startswith("/"):
            path = f"/{path}"
        return f"{self.base_url}{path}"
