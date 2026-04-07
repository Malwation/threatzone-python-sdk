"""Constants and default values for the Threat.Zone Python SDK."""

from typing import Final

DEFAULT_BASE_URL: Final[str] = "https://app.threat.zone/public-api"
DEFAULT_TIMEOUT: Final[float] = 60.0
DEFAULT_MAX_RETRIES: Final[int] = 2
DEFAULT_POLL_INTERVAL: Final[float] = 5.0
DEFAULT_WAIT_TIMEOUT: Final[float] = 600.0

API_KEY_ENV_VAR: Final[str] = "THREATZONE_API_KEY"
API_KEY_HEADER: Final[str] = "Authorization"

USER_AGENT: Final[str] = "threatzone-python-sdk/1.0.0"

CHUNK_SIZE: Final[int] = 8192
