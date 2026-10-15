"""Query parameter builders that the sync and async clients share."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def _join(values: Sequence[int | str] | None) -> str | None:
    if values is None:
        return None
    return ",".join(str(value) for value in values)


def behaviour_filter_params(
    *,
    event_ids: Sequence[int] | None,
    pids: Sequence[int] | None,
    parent_pids: Sequence[int] | None,
    types: Sequence[str] | None,
    operations: Sequence[str] | None,
    statuses: Sequence[str] | None,
    process_name_contains: str | None,
    from_timestamp: float | None,
    to_timestamp: float | None,
    syscall_line_from: int | None,
    syscall_line_to: int | None,
    fields: Mapping[str, str | Sequence[str]] | None,
) -> dict[str, Any]:
    """Build the behaviour index filter parameters. Unset filters are left out."""
    params: dict[str, Any] = {
        "eventIds": _join(event_ids),
        "pids": _join(pids),
        "parentPids": _join(parent_pids),
        "types": _join(types),
        "operations": _join(operations),
        "statuses": _join(statuses),
        "processNameContains": process_name_contains,
        "fromTimestamp": from_timestamp,
        "toTimestamp": to_timestamp,
        "syscallLineFrom": syscall_line_from,
        "syscallLineTo": syscall_line_to,
    }
    for key, value in (fields or {}).items():
        params[f"field.{key}"] = value if isinstance(value, str) else list(value)
    return {name: value for name, value in params.items() if value is not None}


def syscall_search_params(
    *,
    query: str,
    pids: Sequence[int] | None,
    failed_only: bool | None,
    apis: Sequence[str] | None,
    after_line: int | None,
    limit: int | None,
) -> dict[str, Any]:
    """Build the syscall search parameters. Unset parameters are left out."""
    params: dict[str, Any] = {
        "query": query,
        "pids": _join(pids),
        "failedOnly": None if failed_only is None else str(failed_only).lower(),
        "apis": _join(apis),
        "afterLine": after_line,
        "limit": limit,
    }
    return {name: value for name, value in params.items() if value is not None}
