"""URL pattern matching for the in-process fake Threat.Zone API.

Handles only the path component (the host is matched up-front by the
fake_api.FakeThreatZoneAPI). Each route is a compiled regex against the path
suffix below ``/public-api``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class RouteMatch:
    """The result of matching a request path against a known route."""

    name: str
    params: dict[str, str]


_UUID = r"[A-Za-z0-9_-]+"
_SHA = r"[A-Fa-f0-9]{1,128}"


_ROUTES_GET: list[tuple[str, re.Pattern[str]]] = [
    ("get_user_info", re.compile(r"^/me$")),
    ("get_metafields_all", re.compile(r"^/config/metafields$")),
    (
        "get_metafields_by_type",
        re.compile(r"^/config/metafields/(?P<scan_type>[A-Za-z_]+)$"),
    ),
    ("get_environments", re.compile(r"^/config/environments$")),
    ("list_submissions", re.compile(r"^/submissions$")),
    (
        "search_by_sha256",
        re.compile(rf"^/submissions/search/sha256/(?P<sha256>{_SHA})$"),
    ),
    ("get_summary", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/summary$")),
    ("get_indicators", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/indicators$")),
    ("get_iocs", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/iocs$")),
    ("get_yara_rules", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/yara-rules$")),
    (
        "get_extracted_configs",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/extracted-configs$"),
    ),
    ("get_artifacts", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/artifacts$")),
    ("get_eml_analysis", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/eml-analysis$")),
    ("get_mitre", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/mitre$")),
    ("get_static_scan", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/static-scan$")),
    ("get_cdr", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/cdr$")),
    (
        "get_signature_check",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/signature-check$"),
    ),
    (
        "get_process_tree",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/processes/tree$"),
    ),
    ("get_processes", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/processes$")),
    ("get_behaviours", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/behaviours$")),
    ("get_syscalls", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/syscalls$")),
    (
        "get_network_summary",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/network/summary$"),
    ),
    (
        "get_network_dns",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/network/dns$"),
    ),
    (
        "get_network_http",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/network/http$"),
    ),
    (
        "get_network_tcp",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/network/tcp$"),
    ),
    (
        "get_network_udp",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/network/udp$"),
    ),
    (
        "get_network_threats",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/network/threats$"),
    ),
    (
        "download_pcap",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/download/pcap$"),
    ),
    (
        "download_sample",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/download/sample$"),
    ),
    (
        "download_artifact",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/download/artifact/(?P<artifact_id>[^/]+)$"),
    ),
    (
        "download_yara_rule",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/download/yara-rule$"),
    ),
    (
        "download_html_report",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/download/html-report$"),
    ),
    (
        "download_cdr",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/download/cdr$"),
    ),
    (
        "get_url_analysis",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/url-analysis$"),
    ),
    (
        "get_screenshot",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/screenshot$"),
    ),
    (
        "get_media_file",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/media/(?P<file_id>[^/]+)$"),
    ),
    ("list_media", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/media$")),
    ("get_submission", re.compile(rf"^/submissions/(?P<uuid>{_UUID})$")),
]


_ROUTES_POST: list[tuple[str, re.Pattern[str]]] = [
    ("create_sandbox", re.compile(r"^/submissions/sandbox$")),
    ("create_static", re.compile(r"^/submissions/static$")),
    ("create_cdr", re.compile(r"^/submissions/cdr$")),
    ("create_url_analysis", re.compile(r"^/submissions/url_analysis$")),
    ("create_open_in_browser", re.compile(r"^/submissions/open_in_browser$")),
]


def match_route(method: str, path: str) -> RouteMatch | None:
    """Match a request path against the known fake routes.

    Returns a RouteMatch with the named-group params, or None when no
    route matches the given (method, path).
    """
    if method == "GET":
        candidates = _ROUTES_GET
    elif method == "POST":
        candidates = _ROUTES_POST
    else:
        return None

    for name, pattern in candidates:
        m = pattern.match(path)
        if m is not None:
            return RouteMatch(name=name, params=m.groupdict())
    return None
