#!/usr/bin/env python3
"""Turn recorded Public API responses into shape-only fixtures for the parity test.

Usage: scrub-recorded-responses.py <run dir> <fixture dir>

<run dir> holds one <route>.json per route of one submission, for example
root.json and network_dns_limit_5.json. Keys, nesting, value types, numbers,
booleans, nulls, timestamps and short code tokens stay. Every other string (names, paths,
hosts, URLs, sentences, hashes, IDs and addresses) is replaced. The WHOIS and certificate dates
and the geolocation city, which can identify the analysed domain, get fixed values. Lists keep their first 5
items plus every later item that adds a key path.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
OID_RE = re.compile(r"^[0-9a-f]{24}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]{32,128}$")
ISO_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)?$")
TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_\-]{0,39}$")
NUM_RE = re.compile(r"^-?\d{1,4}(\.\d+)?$")

maps: dict[str, dict[str, str]] = {"uuid": {}, "oid": {}, "hex": {}, "ip": {}}


def _seq(kind: str, value: str, make) -> str:
    table = maps[kind]
    if value not in table:
        table[value] = make(len(table) + 1)
    return table[value]


def scrub_str(s: str) -> str:
    if s in ("", "-") or NUM_RE.match(s) or ISO_RE.match(s):
        return s
    if UUID_RE.match(s):
        return _seq("uuid", s.lower(), lambda n: f"00000000-0000-4000-8000-{n:012d}")
    if OID_RE.match(s):
        return _seq("oid", s, lambda n: f"65f0aa{n:018d}")
    if HEX_RE.match(s):
        return _seq("hex", s.lower(), lambda n: (f"{n:x}" * len(s))[: len(s)].rjust(len(s), "0"))
    try:
        ip = ipaddress.ip_address(s)
        return _seq("ip", s, lambda n: f"192.0.2.{n}" if ip.version == 4 else f"2001:db8::{n:x}")
    except ValueError:
        pass
    if TOKEN_RE.match(s) and not re.search(r"\d{5,}", s):
        return s
    return "redacted"


def key_paths(v, prefix=""):
    out = set()
    if isinstance(v, dict):
        for k, x in v.items():
            out.add(prefix + "." + k)
            out |= key_paths(x, prefix + "." + k)
    elif isinstance(v, list):
        for x in v:
            out |= key_paths(x, prefix + "[]")
    return out


def pick(items):
    kept, seen = [], set()
    for i, item in enumerate(items):
        paths = key_paths(item)
        if i < 5 or paths - seen:
            kept.append(item)
            seen |= paths
    return kept


NAME_KEYS = {
    "host",
    "hostname",
    "key",
    "domain",
    "value",
    "filename",
    "image",
    "processName",
    "processImage",
    "path",
    "cmd",
    "url",
    "workDir",
    "family",
    "application_name",
    "package_name",
    "packageName",
    "city",
    "registrarIanaId",
}

WHOIS_DATE_KEYS = {"creationDate", "updatedDate", "expirationDate", "whoisCreationDate"}
CERT_KEYS = {"sslCertificate"}
CERT_DATE_KEYS = {"renewedAt", "expiresAt"}


def fixed_date(v):
    if isinstance(v, str):
        return "2000-01-01T00:00:00.000Z" if ISO_RE.match(v) else v
    if isinstance(v, int) and not isinstance(v, bool):
        return 946684800
    return v


def scrub_dates(v, key=None):
    if isinstance(v, dict):
        return {
            k: fixed_date(x)
            if k in WHOIS_DATE_KEYS or (key in CERT_KEYS and k in CERT_DATE_KEYS)
            else scrub_dates(x, k)
            for k, x in v.items()
        }
    if isinstance(v, list):
        return [scrub_dates(x, key) for x in v]
    return v


def scrub(v, key=None):
    if isinstance(v, str) and key in NAME_KEYS and v not in ("", "-"):
        return "redacted"
    if isinstance(v, dict):
        return {k: scrub(x, k) for k, x in v.items()}
    if isinstance(v, list):
        return [scrub(x, key) for x in pick(v)]
    if isinstance(v, str):
        return scrub_str(v)
    return v


def main() -> None:
    source, target = Path(sys.argv[1]), Path(sys.argv[2])
    target.mkdir(parents=True, exist_ok=True)
    for path in sorted(source.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        text = json.dumps(scrub_dates(scrub(data)), indent=1)
        (target / path.name).write_text(text + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
