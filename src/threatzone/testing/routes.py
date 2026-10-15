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
    ("get_device_presets", re.compile(r"^/config/device-presets$")),
    ("list_network_configs", re.compile(r"^/v1/network-configs$")),
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
    (
        "get_artifact_jobs",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/artifacts/(?P<artifact_id>[^/]+)/jobs$"),
    ),
    ("get_eml_analysis", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/eml-analysis$")),
    ("get_mitre", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/mitre$")),
    (
        "get_static_scan_strings",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/static-scan/strings$"),
    ),
    (
        "get_static_scan_strings_items",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/static-scan/strings/items$"),
    ),
    (
        "get_static_scan_string_facts",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/static-scan/string-facts$"),
    ),
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
    ("get_killchain", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/killchain$")),
    ("get_behaviours", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/behaviours$")),
    ("get_syscalls", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/syscalls$")),
    (
        "get_behaviour_summary",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/behaviours/summary$"),
    ),
    (
        "get_behaviour_facets",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/behaviours/facets$"),
    ),
    (
        "get_behaviour_matches",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/behaviours/match$"),
    ),
    (
        "search_syscalls",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/syscalls/search$"),
    ),
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
        "get_network_exfil_requests",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/network/exfil-requests$"),
    ),
    (
        "get_http_request_packets",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/network/http/(?P<row_id>[^/]+)/packets$"),
    ),
    (
        "get_tcp_connection_packets",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/network/tcp/(?P<row_id>[^/]+)/packets$"),
    ),
    (
        "get_udp_connection_packets",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/network/udp/(?P<row_id>[^/]+)/packets$"),
    ),
    (
        "get_network_endpoints",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/network/endpoints$"),
    ),
    (
        "get_network_host_flows",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/network/endpoints/(?P<host>[^/]+)/flows$"),
    ),
    ("get_ai_report", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/ai-report$")),
    ("get_verdict", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/verdict$")),
    ("get_run", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/run$")),
    ("get_annotations", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/annotations$")),
    ("get_previous_run", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/previous-run$")),
    (
        "compare_runs",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/compare/(?P<other_uuid>[^/]+)$"),
    ),
    (
        "download_iocs",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/download/iocs$"),
    ),
    (
        "download_pcap",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/download/pcap$"),
    ),
    (
        "download_https_pcap",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/download/pcap-https$"),
    ),
    (
        "download_behaviour",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/download/behaviour$"),
    ),
    (
        "download_syscalls",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/download/syscalls$"),
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
        "download_artifact_yara_rule",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/artifacts/(?P<artifact_id>[^/]+)/yara-rule$"),
    ),
    (
        "download_html_report",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/download/html-report$"),
    ),
    (
        "download_stix_report",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/download/stix-2\.1-report$"),
    ),
    (
        "get_pdf_report_status",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/download/pdf-report/status$"),
    ),
    (
        "download_pdf_report",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/download/pdf-report$"),
    ),
    (
        "download_cdr",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/download/cdr$"),
    ),
    (
        "get_url_analysis_session",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/url-analysis/session$"),
    ),
    (
        "get_url_analysis",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/url-analysis$"),
    ),
    (
        "get_url_analysis_indicators",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/url-analysis/indicators$"),
    ),
    (
        "get_url_analysis_indicator_evidence",
        re.compile(
            rf"^/submissions/(?P<uuid>{_UUID})/url-analysis/indicators/(?P<indicator_id>[^/]+)"
            r"/evidence/(?P<reference_id>[^/]+)$"
        ),
    ),
    (
        "get_url_analysis_browser_section",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/url-analysis/browser/(?P<section>[^/]+)$"),
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
    (
        "restart_url_analysis_session",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/url-analysis/session/restart$"),
    ),
    (
        "start_url_analysis_session",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/url-analysis/session$"),
    ),
    (
        "restart_url_analysis",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/restart/url_analysis$"),
    ),
    (
        "regenerate_ai_report",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/ai-report/regenerate$"),
    ),
    (
        "pin_evidence",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/annotations/pins$"),
    ),
]


_ROUTES_PUT: list[tuple[str, re.Pattern[str]]] = [
    ("set_note", re.compile(rf"^/submissions/(?P<uuid>{_UUID})/annotations/note$")),
]


_ROUTES_DELETE: list[tuple[str, re.Pattern[str]]] = [
    (
        "unpin_evidence",
        re.compile(rf"^/submissions/(?P<uuid>{_UUID})/annotations/pins/(?P<pin_id>[^/]+)$"),
    ),
]

_ROUTES_BY_METHOD: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "GET": _ROUTES_GET,
    "POST": _ROUTES_POST,
    "PUT": _ROUTES_PUT,
    "DELETE": _ROUTES_DELETE,
}


def match_route(method: str, path: str) -> RouteMatch | None:
    """Match a request path against the known fake routes.

    Returns a RouteMatch with the named-group params, or None when no
    route matches the given (method, path).
    """
    candidates = _ROUTES_BY_METHOD.get(method)
    if candidates is None:
        return None

    for name, pattern in candidates:
        m = pattern.match(path)
        if m is not None:
            return RouteMatch(name=name, params=m.groupdict())
    return None
