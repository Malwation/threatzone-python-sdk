"""Kill chain type definitions.

Mirrors the `killchain.response.dto.ts` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .indicators import ArtifactAnalysisStatus
from .processes import ProcessEvents, ProcessNetwork, ProcessOrigin

KillchainPathAuthority = Literal["literal", "verified_volume_map", "unverified"] | str
"""Source of the ``path`` of a dropped file. A newer server can send another value."""

KillchainFileRetention = (
    Literal["retained", "observed_only", "invalid_ref", "unavailable", "ambiguous", "withheld"]
    | str
)
"""Retention state of the bytes of a dropped file. A newer server can send another value."""

KillchainInventorySourceError = (
    Literal[
        "inventory_not_captured",
        "inventory_coverage_missing",
        "sidecar_source_unavailable",
        "sidecar_folder_missing",
        "sidecar_dir_missing",
        "sidecar_count_limit",
        "sidecar_byte_limit",
        "source_unreadable",
    ]
    | str
)
"""Code that tells why the file capture source is not available. An unknown cause is
``source_unreadable``. A newer server can send another value."""


class KillchainProcess(BaseModel):
    """A process on the kill chain timeline, in report order."""

    model_config = ConfigDict(populate_by_name=True)

    pid: int
    pid_gen: int | None = Field(default=None, alias="pidGen")
    """Incarnation number of the process. ``(pid, pid_gen)`` identifies one process. ``None``
    on reports that do not record it."""
    origin: ProcessOrigin | None = None
    """Who started the process. ``None`` on reports that do not record it."""
    ppid: int
    tid: int | None = None
    """Thread ID. ``None`` when the report does not record an integer value."""
    process_name: str | None = Field(default=None, alias="processName")
    image: str | None = None
    """Full path of the process image."""
    cmd: str | None = None
    method: str | None = None
    """Method that created the process (for example ``NtCreateUserProcess``)."""
    work_dir: str | None = Field(default=None, alias="workDir")
    """Working directory at process start. The same value as ``Process.cwd``."""
    timestamp: float | None = None
    """Process start time in unix seconds. The value can have a fraction. ``None`` when the
    sandbox did not record it."""
    exit_timestamp: float | None = Field(default=None, alias="exitTimestamp")
    """Process exit time in unix seconds. ``None`` when the process did not exit during the
    analysis or the sandbox did not record it."""
    events: ProcessEvents
    network: ProcessNetwork


class KillchainMemoryDump(BaseModel):
    """A stored file on the kill chain: a memory dump, or the base of a dropped file."""

    model_config = ConfigDict(populate_by_name=True)

    path: str
    """Path of the file in the analysis machine."""
    sha256: str | None = None
    file_size: int | None = Field(default=None, alias="fileSize")
    timestamp: float | None = None
    """Capture time in unix seconds. ``None`` when the sandbox did not record it."""
    artifact_id: str | None = Field(default=None, alias="artifactId")
    """ID of the stored artifact. Download it with ``download_artifact()``. ``None`` when no
    stored artifact of the current analysis exists for this file."""
    analysis_status: ArtifactAnalysisStatus | None = Field(default=None, alias="analysisStatus")
    """Analysis state of the stored artifact, as in ``get_artifacts()``. ``None`` when
    ``artifact_id`` is ``None``."""
    analysis_reason: str | None = Field(default=None, alias="analysisReason")
    """Error code for the analysis state, as in ``get_artifacts()``. Never free text."""


class KillchainDroppedFile(KillchainMemoryDump):
    """A file that a process wrote during the analysis."""

    raw_path: str | None = Field(default=None, alias="rawPath")
    """Path as the sandbox recorded it, before the volume map. ``None`` on V1 reports."""
    path_authority: KillchainPathAuthority | None = Field(default=None, alias="pathAuthority")
    """Source of ``path``. ``None`` on V1 reports."""
    path_authority_reason: str | None = Field(default=None, alias="pathAuthorityReason")
    source_actor_bound: bool | None = Field(default=None, alias="sourceActorBound")
    """True when the write is bound to the process of the group. ``None`` on V1 reports."""
    capture_closed: bool | None = Field(default=None, alias="captureClosed")
    """True when the sandbox observed a native close of the file. It does not prove a
    completed write. ``None`` on V1 reports."""
    retention: KillchainFileRetention | None = None
    """Retention state of the file bytes. ``None`` on V1 reports."""
    retention_detail: str | None = Field(default=None, alias="retentionDetail")
    pid_gen: int | None = Field(default=None, alias="pidGen")
    """Incarnation number of the writing process. ``None`` on V1 reports."""
    event_seq: int | None = Field(default=None, alias="eventSeq")
    """Capture sequence number of the write event. ``None`` on V1 reports."""


class KillchainDroppedFileGroup(BaseModel):
    """The files that one process wrote."""

    model_config = ConfigDict(populate_by_name=True)

    pid: int
    pid_gen: int | None = Field(default=None, alias="pidGen")
    process_name: str = Field(alias="processName")
    executable_path: str = Field(alias="executablePath")
    files: list[KillchainDroppedFile]


class KillchainMemoryRegion(BaseModel):
    """A dumped memory region of a process."""

    model_config = ConfigDict(populate_by_name=True)

    offset_start: str = Field(alias="offsetStart")
    """Start address of the region (hex)."""
    offset_end: str = Field(alias="offsetEnd")
    """End address of the region (hex)."""
    dumps: list[KillchainMemoryDump]


class KillchainMemoryDumpGroup(BaseModel):
    """The memory dumps of one process, grouped by memory region."""

    model_config = ConfigDict(populate_by_name=True)

    pid: int
    process_name: str = Field(alias="processName")
    executable_path: str = Field(alias="executablePath")
    regions: list[KillchainMemoryRegion]


class KillchainCoverageCount(BaseModel):
    """One named count of the dropped-file inventory."""

    model_config = ConfigDict(populate_by_name=True)

    name: str
    value: int


class KillchainInventoryCoverage(BaseModel):
    """Coverage of the Windows V2 dropped-file inventory."""

    model_config = ConfigDict(populate_by_name=True)

    source_status: str = Field(alias="sourceStatus")
    """State of the file capture source, for example ``available``. When the state is not
    ``available``, the counts are not measured values."""
    source_error: KillchainInventorySourceError | None = Field(default=None, alias="sourceError")
    counts: list[KillchainCoverageCount]
    """Inventory counts, sorted by name."""
    unretained_rows_omitted: int | None = Field(default=None, alias="unretainedRowsOmitted")
    """Unretained observations the worker did not store because of the row limit."""


class Killchain(BaseModel):
    """Kill chain timeline of a dynamic analysis."""

    model_config = ConfigDict(populate_by_name=True)

    dump_collector_active: bool = Field(alias="dumpCollectorActive")
    """True when the memory dump collector ran. When it is false, an empty ``mem_dumps`` does
    not tell that no dump was possible."""
    artifact_inventory_coverage: KillchainInventoryCoverage | None = Field(
        default=None, alias="artifactInventoryCoverage"
    )
    """``None`` on reports without a Windows V2 file inventory."""
    created_processes: list[KillchainProcess] = Field(alias="createdProcesses")
    dropped_files: list[KillchainDroppedFileGroup] = Field(alias="droppedFiles")
    mem_dumps: list[KillchainMemoryDumpGroup] = Field(alias="memDumps")
