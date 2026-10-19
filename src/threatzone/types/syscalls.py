"""Syscall log type definitions.

Mirrors the `syscalls.response.dto.ts` and `syscalls-search.response.dto.ts` DTOs in the
Threat.Zone Public API.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class SyscallsResponse(BaseModel):
    """Paginated raw syscall log lines."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[str]
    total: int
    page: int | None = None
    limit: int | None = None
    total_pages: int | None = Field(default=None, alias="totalPages")
    first_line: int | None = Field(default=None, alias="firstLine")
    """1-based line number of ``items[0]``. ``items[i]`` is line ``first_line + i``, the same
    number as ``BehaviourEvent.syscall_line_number``. ``None`` when ``items`` is empty and on
    older servers."""


class SyscallSearchLine(BaseModel):
    """One syscall log line that matched a search."""

    model_config = ConfigDict(populate_by_name=True)

    line: int
    """1-based line number in the syscall log."""
    raw: str
    """The raw line without leading and trailing spaces. The server cuts a long line. Read the
    full line with ``get_syscalls()``."""


class SyscallSearchResult(BaseModel):
    """One page of syscall search hits and the scan position."""

    model_config = ConfigDict(populate_by_name=True)

    lines: list[SyscallSearchLine]
    """The hits of this page, in line order."""
    next_from_line: int | None = Field(default=None, alias="nextFromLine")
    """Send this value as ``after_line`` to get the next page. ``None`` when the scan read the
    last line of the log."""
    scanned_to: int = Field(alias="scannedTo")
    """The last line number that the scan read. When ``busy`` is ``True``, the value is
    ``after_line``."""
    total_count: int | None = Field(default=None, alias="totalCount")
    """Number of lines in the log. ``None`` when ``busy`` is ``True``."""
    done: bool
    """``True`` when the scan read the last line of the log."""
    truncated: bool
    """``True`` when the line limit or the time limit stopped the scan before it found
    ``limit`` hits."""
    busy: bool
    """``True`` when the server runs too many searches and did not scan. Send the same request
    again later."""
    retry_after_seconds: float | None = Field(default=None, alias="retryAfterSeconds")
    """Seconds to wait before the same request when ``busy`` is ``True``. ``None`` on other
    responses and on older servers."""
