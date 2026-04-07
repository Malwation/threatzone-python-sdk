"""Behaviour event type definitions.

Mirrors the `behaviours.response.dto.ts` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

BehaviourOs = Literal["windows", "linux", "android", "macos"]


class BehaviourEvent(BaseModel):
    """A single behaviour event captured during dynamic analysis."""

    model_config = ConfigDict(populate_by_name=True)

    type: str
    pid: int
    ppid: int
    process_name: str | None = Field(default=None, alias="processName")
    operation: str
    event_id: int = Field(alias="eventId")
    event_count: int = Field(alias="eventCount")
    syscall_line_number: int | None = Field(default=None, alias="syscallLineNumber")
    timestamp: int
    # OS-specific structured payload. Shape depends on `os` and event `type`.
    details: dict[str, Any]


class BehavioursResponse(BaseModel):
    """Paginated behaviour event list, OS-tagged."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[BehaviourEvent]
    total: int
    os: BehaviourOs
