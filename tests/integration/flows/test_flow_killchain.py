"""Flow — the kill chain timeline of a dynamic analysis."""

from __future__ import annotations

import pytest

from threatzone import AsyncThreatZone, ReportUnavailableError, ThreatZone
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import Killchain


def _submit(fake_api: FakeThreatZoneAPI, sync_client: ThreatZone) -> str:
    scenarios.seed_malicious_pe(fake_api)
    created = sync_client.create_sandbox_submission(b"PE")
    sync_client.wait_for_completion(created.uuid, poll_interval=0.001, timeout=5)
    return created.uuid


def test_killchain_matches_the_process_list(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    killchain = sync_client.get_killchain(uuid)
    assert isinstance(killchain, Killchain)
    assert killchain.dump_collector_active is True
    process = sync_client.get_processes(uuid).items[0]
    [step] = killchain.created_processes
    assert (step.pid, step.pid_gen) == (process.pid, process.pid_gen)
    assert step.work_dir == process.cwd
    assert step.process_name == process.name


def test_killchain_artifact_id_is_listed_and_downloadable(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    killchain = sync_client.get_killchain(uuid)
    [group] = killchain.dropped_files
    [dropped] = group.files
    assert dropped.artifact_id is not None
    assert dropped.analysis_status == "analyzed"
    assert dropped.retention == "retained"
    listed = {artifact.id for artifact in sync_client.get_artifacts(uuid).items}
    assert dropped.artifact_id in listed
    with sync_client.download_artifact(uuid, dropped.artifact_id) as download:
        assert download.read()
    [dump] = killchain.mem_dumps[0].regions[0].dumps
    assert dump.artifact_id is None
    assert dump.analysis_status is None


def test_killchain_needs_a_dynamic_report(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone
) -> None:
    scenarios.seed_static_only_submission(fake_api)
    created = sync_client.create_static_submission(b"PE")
    with pytest.raises(ReportUnavailableError):
        sync_client.get_killchain(created.uuid)


async def test_async_killchain(
    fake_api: FakeThreatZoneAPI, sync_client: ThreatZone, async_client: AsyncThreatZone
) -> None:
    uuid = _submit(fake_api, sync_client)
    killchain = await async_client.get_killchain(uuid)
    assert isinstance(killchain, Killchain)
    assert killchain.artifact_inventory_coverage is not None
    assert killchain.artifact_inventory_coverage.source_status == "available"
