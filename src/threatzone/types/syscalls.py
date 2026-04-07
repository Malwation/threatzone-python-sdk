"""Syscall log type definitions.

Mirrors the `syscalls.response.dto.ts` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class SyscallsResponse(BaseModel):
    """Paginated raw syscall log lines."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[str]
    total: int
