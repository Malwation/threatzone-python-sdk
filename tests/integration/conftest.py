"""Pytest fixtures for the fake-backed integration suite.

Every test in ``tests/integration/`` gets a fresh ``FakeThreatZoneAPI`` and a
``ThreatZone`` / ``AsyncThreatZone`` client wired to it via the ``http_client``
constructor argument. State is reset between tests so seeds never leak.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import pytest

from threatzone import AsyncThreatZone, ThreatZone
from threatzone.testing import FakeThreatZoneAPI


@pytest.fixture
def fake_api() -> Iterator[FakeThreatZoneAPI]:
    """Fresh ``FakeThreatZoneAPI`` for each test, reset on teardown."""
    fake = FakeThreatZoneAPI()
    yield fake
    fake.reset()


@pytest.fixture
def sync_client(fake_api: FakeThreatZoneAPI) -> Iterator[ThreatZone]:
    """Sync ``ThreatZone`` client wired to the fake transport."""
    client = ThreatZone(
        api_key="test-key",
        base_url="https://fake.threat.zone/public-api",
        http_client=fake_api.as_httpx_client(),
    )
    try:
        yield client
    finally:
        client.close()


@pytest.fixture
async def async_client(
    fake_api: FakeThreatZoneAPI,
) -> AsyncIterator[AsyncThreatZone]:
    """Async ``AsyncThreatZone`` client wired to the fake transport."""
    client = AsyncThreatZone(
        api_key="test-key",
        base_url="https://fake.threat.zone/public-api",
        http_client=fake_api.as_async_httpx_client(),
    )
    try:
        yield client
    finally:
        await client.close()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Auto-tag every test under ``tests/integration/`` with the integration marker."""
    del config
    for item in items:
        if "tests/integration/" in str(item.fspath).replace("\\", "/"):
            item.add_marker(pytest.mark.integration)
