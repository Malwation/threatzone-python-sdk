"""Recipe 10 — the async client.

Mirrors `docs/RECIPES.md#10-use-the-async-client`.
"""

from __future__ import annotations

import asyncio

import pytest

from threatzone import AnalysisTimeoutError, AsyncThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import Submission


@pytest.mark.asyncio
async def test_async_create_and_wait(
    fake_api: FakeThreatZoneAPI, async_client: AsyncThreatZone
) -> None:
    """``AsyncThreatZone`` mirrors the sync happy path."""
    scenarios.seed_malicious_pe(fake_api)
    created = await async_client.create_sandbox_submission(b"PE")
    final = await async_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    assert isinstance(final, Submission)
    assert final.is_complete()


@pytest.mark.asyncio
async def test_async_gather_batch(
    fake_api: FakeThreatZoneAPI, async_client: AsyncThreatZone
) -> None:
    """Concurrent submissions complete via ``asyncio.gather``."""
    for i in range(3):
        fake_api.register_sample(sha256=f"{i:064x}", advance_after_polls=1)

    created = await asyncio.gather(
        *[async_client.create_sandbox_submission(b"x") for _ in range(3)]
    )
    results = await asyncio.gather(
        *[async_client.wait_for_completion(c.uuid, poll_interval=0.001, timeout=5) for c in created]
    )
    assert len(results) == 3
    assert all(r.is_complete() for r in results)


@pytest.mark.asyncio
async def test_async_timeout_propagates(
    fake_api: FakeThreatZoneAPI, async_client: AsyncThreatZone
) -> None:
    """Stalled submissions raise ``AnalysisTimeoutError`` from the async client."""
    fake_api.register_sample(sha256="a" * 64, advance_after_polls=9999)
    created = await async_client.create_sandbox_submission(b"PE")
    with pytest.raises(AnalysisTimeoutError):
        await async_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=0.05)


@pytest.mark.asyncio
async def test_async_search_by_sha256(
    fake_api: FakeThreatZoneAPI, async_client: AsyncThreatZone
) -> None:
    """Async ``search_by_sha256`` behaves like the sync variant."""
    sha = scenarios.seed_malicious_pe(fake_api, sha256="f" * 64)
    matches = await async_client.search_by_sha256(sha)
    assert len(matches) >= 1
    assert matches[0].hashes is not None
    assert matches[0].hashes.sha256 == sha
