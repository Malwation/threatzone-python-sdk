"""Recipe 08 — paginate through a large list.

Mirrors `docs/RECIPES.md#8-paginate-through-a-large-list`.
"""

from __future__ import annotations

import pytest

from threatzone import BadRequestError, ThreatZone
from threatzone.testing import FakeThreatZoneAPI
from threatzone.types import PaginatedSubmissions, SubmissionListItem


def _seed_n(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone, n: int) -> None:
    for i in range(n):
        fake_api.register_sample(sha256=f"{i:064x}", advance_after_polls=1)
        sync_client.create_sandbox_submission(b"x")


def test_pagination_total_pages(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    """``total_pages`` reflects ceil(total/limit)."""
    _seed_n(fake_api, sync_client, 5)

    response = sync_client.list_submissions(page=1, limit=2)
    assert isinstance(response, PaginatedSubmissions)
    assert response.total == 5
    assert response.total_pages == 3


def test_iterate_every_page(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    """Walking pages yields every seeded submission exactly once."""
    _seed_n(fake_api, sync_client, 7)

    seen: list[SubmissionListItem] = []
    page = 1
    while True:
        response = sync_client.list_submissions(page=page, limit=3)
        if not response.items:
            break
        seen.extend(response.items)
        if page >= response.total_pages:
            break
        page += 1
    assert len(seen) == 7
    assert len({item.uuid for item in seen}) == 7


def test_empty_list_when_no_submissions(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """A fresh fake returns an empty page."""
    del fake_api
    response = sync_client.list_submissions(page=1, limit=10)
    assert response.items == []
    assert response.total == 0


def test_limit_above_100_rejected(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    """``limit`` must be between 1 and 100."""
    del fake_api
    with pytest.raises(BadRequestError):
        sync_client.list_submissions(page=1, limit=500)
