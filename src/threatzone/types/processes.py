"""Process surface type definitions.

Mirrors the `processes.response.dto.ts` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ProcessOrigin = Literal["sample", "shell"] | str
"""Who started a process: ``sample`` (the submitted sample tree) or ``shell`` (the analyst on
the guest desktop). A newer server can send another value."""


class ProcessNetworkItem(BaseModel):
    """A single network endpoint contacted by a process."""

    model_config = ConfigDict(populate_by_name=True)

    ip: str
    port: int
    protocol: str


class ProcessNetwork(BaseModel):
    """Network activity associated with a process."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[ProcessNetworkItem]
    count: int


class ProcessEventItem(BaseModel):
    """A single system event performed by a process."""

    model_config = ConfigDict(populate_by_name=True)

    type: str
    path: str
    mode: str


class ProcessEvents(BaseModel):
    """System events performed by a process."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[ProcessEventItem]
    count: int


class Process(BaseModel):
    """A process observed during dynamic analysis."""

    model_config = ConfigDict(populate_by_name=True)

    pid: int
    ppid: int
    pid_gen: int | None = Field(default=None, alias="pidGen")
    """Incarnation number of the process. A reused pid gets a new ``pid_gen``, so
    ``(pid, pid_gen)`` identifies one process. ``None`` on reports that do not record it and
    on older servers."""
    origin: ProcessOrigin | None = None
    """Who started the process. ``None`` on reports that do not record it and on older
    servers."""
    tid: int
    name: str | None = None
    cmd: str | None = None
    cwd: str | None = None
    image: str | None = None
    """Full path of the process image as the sandbox observed it."""
    method: str | None = None
    """Method that created the process (for example ``NtCreateUserProcess``)."""
    timestamp: float | None = None
    """Process start time in unix seconds. The value can have a fraction. ``None`` when the
    sandbox did not record it."""
    exit_timestamp: float | None = Field(default=None, alias="exitTimestamp")
    """Process exit time in unix seconds. ``None`` when the process did not exit during the
    analysis or the sandbox did not record it."""
    network: ProcessNetwork
    events: ProcessEvents


class ProcessesResponse(BaseModel):
    """List of processes observed during dynamic analysis."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[Process]
    total: int


class ProcessTreeNode(BaseModel):
    """A node in the process spawn tree."""

    model_config = ConfigDict(populate_by_name=True)

    pid: int
    ppid: int
    pid_gen: int | None = Field(default=None, alias="pidGen")
    """Incarnation number of the process. Each ``(pid, pid_gen)`` is its own node. ``None``
    on reports that do not record it and on older servers."""
    origin: ProcessOrigin | None = None
    """Who started the process. ``None`` on reports that do not record it and on older
    servers."""
    tid: int
    name: str | None = None
    cmd: str | None = None
    cwd: str | None = None
    """Working directory at process start. ``None`` when the sandbox did not capture it and on
    older servers."""
    children: list[ProcessTreeNode]


ProcessTreeNode.model_rebuild()


class ProcessTreeResponse(BaseModel):
    """Top-level nodes of the process spawn tree."""

    model_config = ConfigDict(populate_by_name=True)

    nodes: list[ProcessTreeNode]
