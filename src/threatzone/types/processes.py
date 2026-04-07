"""Process surface type definitions.

Mirrors the `processes.response.dto.ts` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


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
    tid: int
    name: str | None = None
    cmd: str | None = None
    cwd: str | None = None
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
    tid: int
    name: str | None = None
    cmd: str | None = None
    children: list[ProcessTreeNode]


ProcessTreeNode.model_rebuild()


class ProcessTreeResponse(BaseModel):
    """Top-level nodes of the process spawn tree."""

    model_config = ConfigDict(populate_by_name=True)

    nodes: list[ProcessTreeNode]
