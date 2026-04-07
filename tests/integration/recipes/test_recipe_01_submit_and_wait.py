"""Recipe 01 — submit a file and wait for completion.

Mirrors `docs/RECIPES.md#1-submit-a-file-and-wait-for-completion`.
"""

from __future__ import annotations

import pytest

from threatzone import AnalysisTimeoutError, ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import Submission, SubmissionCreated


def test_submit_malicious_pe_and_wait_for_completion(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """Happy path: state advances from accepted to completed and verdict is malicious."""
    sha = scenarios.seed_malicious_pe(fake_api)

    created = sync_client.create_sandbox_submission(b"PE-bytes")
    assert isinstance(created, SubmissionCreated)
    assert created.uuid
    assert created.sha256 == sha

    final = sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    assert isinstance(final, Submission)
    assert final.is_complete()
    assert final.level == "malicious"


def test_poll_count_matches_expected_advances(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """``wait_for_completion`` polls until ``advance_after_polls`` is reached."""
    fake_api.register_sample(sha256="b" * 64, advance_after_polls=3)

    created = sync_client.create_sandbox_submission(b"data")
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)

    polls = fake_api.poll_count(created.uuid)
    assert polls >= 3


def test_wait_for_completion_times_out_on_stalled_submission(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """A submission that never advances raises ``AnalysisTimeoutError``."""
    fake_api.register_sample(sha256="c" * 64, advance_after_polls=9999)
    created = sync_client.create_sandbox_submission(b"stuck")

    with pytest.raises(AnalysisTimeoutError) as exc_info:
        sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=0.05)

    assert exc_info.value.uuid == created.uuid
    assert exc_info.value.elapsed >= 0.0


def test_submission_level_propagates_from_seed(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """Seeded ``benign`` document surfaces as a benign completed submission."""
    scenarios.seed_benign_document(fake_api)
    created = sync_client.create_static_submission(b"PDF-bytes")

    final = sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    assert final.level == "benign"
    assert final.is_complete()


def test_creation_returns_uuid_and_sha256(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    """Sandbox submission response carries both ``uuid`` and ``sha256``."""
    sha = scenarios.seed_malicious_pe(fake_api, sha256="d" * 64)
    created = sync_client.create_sandbox_submission(b"hello")

    assert created.uuid
    assert created.sha256 == sha
    assert isinstance(created.message, str)
