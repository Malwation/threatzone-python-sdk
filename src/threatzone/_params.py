"""Query parameter builders that the sync and async clients share."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def _join(name: str, values: Sequence[int | str] | None) -> str | None:
    if values is None:
        return None
    if not values:
        raise ValueError(f"{name} must not be empty. Pass None to leave out the filter.")
    if isinstance(values, str):
        return values
    return ",".join(str(value) for value in values)


def _field_value(key: str, value: str | Sequence[str]) -> str | list[str]:
    if isinstance(value, str):
        return value
    if not value:
        raise ValueError(f"fields[{key!r}] must not be empty. Leave out the key instead.")
    return list(value)


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
        "eventIds": _join("event_ids", event_ids),
        "pids": _join("pids", pids),
        "parentPids": _join("parent_pids", parent_pids),
        "types": _join("types", types),
        "operations": _join("operations", operations),
        "statuses": _join("statuses", statuses),
        "processNameContains": process_name_contains,
        "fromTimestamp": from_timestamp,
        "toTimestamp": to_timestamp,
        "syscallLineFrom": syscall_line_from,
        "syscallLineTo": syscall_line_to,
    }
    for key, value in (fields or {}).items():
        params[f"field.{key}"] = _field_value(key, value)
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
        "pids": _join("pids", pids),
        "failedOnly": None if failed_only is None else str(failed_only).lower(),
        "apis": _join("apis", apis),
        "afterLine": after_line,
        "limit": limit,
    }
    return {name: value for name, value in params.items() if value is not None}


def behaviour_match_params(texts: str | Sequence[str]) -> dict[str, Any]:
    """Build the behaviour match parameters. Each text is one ``text`` parameter."""
    values = [texts] if isinstance(texts, str) else list(texts)
    if not values:
        raise ValueError("texts must not be empty.")
    return {"text": values}
