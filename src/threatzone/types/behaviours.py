"""Behaviour event type definitions.

Mirrors the `behaviours.response.dto.ts` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

BehaviourOs = Literal["windows", "linux", "android", "macos"]

BehaviourEventSort = Literal["eventId", "time"] | str
"""Row order that ``get_behaviours(sort=...)`` asks for."""

BehaviourPageOrder = Literal["eventId", "time", "file"] | str
"""Row order of a returned page. ``file`` is the order of the behaviour file when its event
IDs are not in order."""

BehaviourFacetField = Literal["operation", "type", "processName", "function", "subject"] | str
"""Event field that ``get_behaviour_facets()`` counts values of."""

BehaviourFieldFilterKey = (
    Literal[
        "path",
        "key",
        "mutex",
        "cmd",
        "status",
        "value",
        "handle",
        "method",
        "function",
        "filename",
        "argv",
        "flags",
        "executable_path",
        "target_path",
        "csflags",
        "file_flag",
        "source",
        "protection",
        "category",
        "arg",
        "args",
        "fd",
    ]
    | str
)
"""Detail key of a ``field.<key>`` behaviour filter. ``cmd`` also matches the Android
``command`` detail."""


class BehaviourEvent(BaseModel):
    """A single behaviour event captured during dynamic analysis."""

    model_config = ConfigDict(populate_by_name=True)

    type: str
    pid: int
    ppid: int
    pid_gen: int | None = Field(default=None, alias="pidGen")
    """Process generation. ``(pid, pid_gen)`` identifies one process when the OS reuses a
    PID. ``None`` when the report does not record it and on older servers."""
    process_name: str | None = Field(default=None, alias="processName")
    operation: str
    event_id: int = Field(alias="eventId")
    event_count: int = Field(alias="eventCount")
    syscall_line_number: int | None = Field(default=None, alias="syscallLineNumber")
    timestamp: float | None = None
    subject: str | None = None
    """The object the event acted on, as the web UI shows it: a command line, file path,
    registry key, mutex, endpoint or API name. ``None`` when no detail names an object and on
    older servers."""
    # OS-specific structured payload. Shape depends on the submission OS and event type.
    details: dict[str, Any]


class BehavioursResponse(BaseModel):
    """Paginated behaviour event list."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[BehaviourEvent]
    total: int
    page: int
    limit: int
    total_pages: int = Field(alias="totalPages")
    sorted_by: BehaviourPageOrder | None = Field(default=None, alias="sortedBy")
    """Row order of the page. Set only when the request used an index parameter."""
    many_processes_match: bool | None = Field(default=None, alias="manyProcessesMatch")
    """``True`` when more than 50 process names contain the ``process_name_contains`` text.
    The page then holds the events of the 50 names with the most events. Set only when the
    request used an index parameter."""


class BehaviourValueCount(BaseModel):
    """Number of behaviour events with one field value."""

    model_config = ConfigDict(populate_by_name=True)

    value: str
    count: int


class BehaviourProcessCount(BaseModel):
    """Number of behaviour events of one process."""

    model_config = ConfigDict(populate_by_name=True)

    process_id: int = Field(alias="processId")
    process_name: str = Field(alias="processName")
    """The process name of the first event of the process."""
    count: int
    first_timestamp: float | None = Field(default=None, alias="firstTimestamp")
    """Time of the first event of the process, in unix seconds."""
    last_timestamp: float | None = Field(default=None, alias="lastTimestamp")
    """Time of the last event of the process, in unix seconds."""


class BehaviourExit(BaseModel):
    """The first exit event of one process."""

    model_config = ConfigDict(populate_by_name=True)

    process_id: int = Field(alias="processId")
    event_id: int = Field(alias="eventId")
    status: str | None = None
    """The status detail of the exit event. ``None`` when the event has none."""


class BehaviourSummary(BaseModel):
    """Behaviour event counts that the web UI shows above the Behaviour view."""

    model_config = ConfigDict(populate_by_name=True)

    total_count: int = Field(alias="totalCount")
    first_timestamp: float | None = Field(default=None, alias="firstTimestamp")
    """Time of the first event, in unix seconds."""
    last_timestamp: float | None = Field(default=None, alias="lastTimestamp")
    """Time of the last event, in unix seconds."""
    by_type: list[BehaviourValueCount] = Field(alias="byType")
    """Event counts by type, most frequent first. At most 200 values."""
    by_operation: list[BehaviourValueCount] = Field(alias="byOperation")
    """Event counts by operation, most frequent first. At most 200 values."""
    by_process: list[BehaviourProcessCount] = Field(alias="byProcess")
    """Event counts by process, most frequent first. At most 500 processes."""
    exits: list[BehaviourExit]
    """The first exit event of each process that exited."""


class BehaviourFacets(BaseModel):
    """The most frequent values of one behaviour event field."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[BehaviourValueCount]
    """Value counts, most frequent first."""
    complete: bool
    """``False`` when the read limit stopped the row scan. The counts are then too low."""
    scanned_rows: int = Field(alias="scannedRows")
    """Rows that the request examined."""
