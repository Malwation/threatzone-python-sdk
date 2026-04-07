"""Recipe 04 — list and download artifacts.

Mirrors `docs/RECIPES.md#4-download-all-artifacts`.
"""

from __future__ import annotations

import pytest

from threatzone import NotFoundError, ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import ArtifactsResponse


def test_list_artifacts(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    """``get_artifacts`` returns a typed envelope with at least one item."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    response = sync_client.get_artifacts(created.uuid)
    assert isinstance(response, ArtifactsResponse)
    assert response.total >= 1
    assert len(response.items) >= 1


def test_download_first_artifact(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    """The first artifact downloads as non-empty bytes."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    response = sync_client.get_artifacts(created.uuid)
    artifact = response.items[0]

    with sync_client.download_artifact(created.uuid, artifact.id) as download:
        payload = download.read()
    assert isinstance(payload, bytes)
    assert len(payload) > 0


def test_download_nonexistent_artifact_raises_404(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """A bogus artifact id returns 404 / ``NotFoundError``."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    with (
        pytest.raises(NotFoundError),
        sync_client.download_artifact(created.uuid, "no-such-artifact") as _,
    ):
        pass


def test_artifacts_have_hashes(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> None:
    """Every artifact carries an MD5/SHA1/SHA256 hash triple."""
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")

    response = sync_client.get_artifacts(created.uuid)
    for artifact in response.items:
        assert len(artifact.hashes.md5) == 32
        assert len(artifact.hashes.sha1) == 40
        assert len(artifact.hashes.sha256) == 64
