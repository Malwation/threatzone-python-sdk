"""Shared parsing of list responses, with and without the list envelope."""

from __future__ import annotations

from typing import Any

import httpx


def total_count_header(response: httpx.Response) -> int | None:
    value = response.headers.get("x-total-count")
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def list_page(response: httpx.Response) -> tuple[list[Any], int | None]:
    """Return the rows of a list response and the total of matching rows.

    A plain array uses the ``X-Total-Count`` header. The envelope
    ``{items, total, page, pageSize, next}`` uses its ``total``.
    """
    body = response.json()
    header_total = total_count_header(response)
    if isinstance(body, dict) and isinstance(body.get("items"), list):
        total = body.get("total")
        if isinstance(total, int) and not isinstance(total, bool):
            return body["items"], total
        return body["items"], header_total
    if isinstance(body, list):
        return body, header_total
    raise ValueError(f"Expected a list response, got {type(body).__name__}")
