"""Network surface type definitions.

Mirrors the `network.response.dto.ts` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

DnsRecordType = Literal[
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "PTR",
    "SOA",
    "TXT",
    "SRV",
    "DNSKEY",
    "RRSIG",
    "NSEC",
    "NSEC3",
    "DS",
    "NAPTR",
    "CAA",
]

DnsStatus = Literal[
    "NOERROR",
    "FORMERR",
    "SERVFAIL",
    "NXDOMAIN",
    "NOTIMP",
    "REFUSED",
    "YXDOMAIN",
    "YXRRSET",
    "NXRRSET",
    "NOTAUTH",
    "NOTZONE",
    "BADVERS",
    "BADKEY",
    "BADTIME",
    "BADMODE",
    "BADNAME",
    "BADALG",
    "BADTRUNC",
    "TIMEOUT",
]

ConnectionProtocol = Literal["tcp", "udp"]
ThreatProtocol = Literal["TCP", "UDP"]
ThreatAppProto = Literal["HTTP", "TLS", "DNS"]
ThreatSeverity = Literal["high", "low"]

NetworkAvailabilityState = Literal["disabled", "unavailable", "verified_zero", "observed"] | str
NetworkCoverage = Literal["none", "partial", "complete"] | str
NetworkAttribution = (
    Literal[
        "sample",
        "sample_child",
        "sensor_only",
        "windows_background",
    ]
    | str
)

NetworkSourceScope = (
    Literal[
        "sample_attributed",
        "submission_ip_scoped",
        "submission_unattributed",
        "none",
    ]
    | str
)


class NetworkAvailability(BaseModel):
    """Network evidence state of a Windows V2 report."""

    model_config = ConfigDict(populate_by_name=True)

    state: NetworkAvailabilityState
    reason: str | None = None
    coverage: NetworkCoverage


class NetworkSummary(BaseModel):
    """Summary of network activity captured during dynamic analysis."""

    model_config = ConfigDict(populate_by_name=True)

    dns_count: int = Field(alias="dnsCount")
    http_count: int = Field(alias="httpCount")
    tcp_count: int = Field(alias="tcpCount")
    udp_count: int = Field(alias="udpCount")
    threat_count: int = Field(alias="threatCount")
    pcap_available: bool = Field(alias="pcapAvailable")
    windows_background_count: int | None = Field(default=None, alias="windowsBackgroundCount")
    counts_available: bool | None = Field(default=None, alias="countsAvailable")
    availability: NetworkAvailability | None = None
    source_scope: NetworkSourceScope | None = Field(default=None, alias="sourceScope")


class NetworkRowSource(BaseModel):
    """Source fields of a network row.

    Each field is ``None`` when an older server omits it. A server with row
    sources sends ``attribution="sample"`` for rows of older reports.
    """

    model_config = ConfigDict(populate_by_name=True)

    attribution: NetworkAttribution | None = None
    attribution_reason: str | None = Field(default=None, alias="attributionReason")
    process_id: int | None = Field(default=None, alias="processId")
    process_image: str | None = Field(default=None, alias="processImage")


class DnsQuery(NetworkRowSource):
    """A DNS query captured during dynamic analysis."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    host: str
    type: DnsRecordType
    status: DnsStatus
    status_text: str | None = Field(default=None, alias="statusText")
    records: list[str]
    timeshift: float
    source_scope: NetworkSourceScope | None = Field(default=None, alias="sourceScope")


class HttpRequest(NetworkRowSource):
    """An HTTP request observed during dynamic analysis (slim shape)."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    host: str
    ip: str
    port: int
    country: str | None = None
    source_scope: NetworkSourceScope | None = Field(default=None, alias="sourceScope")


class ConnectionPackets(BaseModel):
    """Packet count summary for a network connection."""

    model_config = ConfigDict(populate_by_name=True)

    sent: int
    received: int
    empty: bool


class Connection(NetworkRowSource):
    """A TCP or UDP connection captured during dynamic analysis."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    protocol: ConnectionProtocol
    destination_ip: str = Field(alias="destinationIp")
    destination_port: int = Field(alias="destinationPort")
    domain: str | None = None
    asn: str | None = None
    country: str | None = None
    packets: ConnectionPackets
    timeshift: float
    source_scope: NetworkSourceScope | None = Field(default=None, alias="sourceScope")


class NetworkThreatTls(BaseModel):
    """TLS fingerprint block attached to TLS-bound network threats."""

    model_config = ConfigDict(populate_by_name=True)

    version: str
    sni: str
    ja3_hash: str = Field(alias="ja3Hash")
    ja3s_hash: str = Field(alias="ja3sHash")
    ja3_string: str = Field(alias="ja3String")
    ja3s_string: str = Field(alias="ja3sString")


class NetworkThreat(NetworkRowSource):
    """A Suricata-style network alert captured during dynamic analysis."""

    model_config = ConfigDict(populate_by_name=True)

    signature: str
    description: str
    severity: ThreatSeverity
    protocol: ThreatProtocol
    app_proto: ThreatAppProto = Field(alias="appProto")
    destination_ip: str = Field(alias="destinationIp")
    destination_port: int = Field(alias="destinationPort")
    timeshift: float
    metadata: dict[str, list[str]]
    details: dict[str, str | int]
    tls: NetworkThreatTls | None = None
    source_scope: NetworkSourceScope | None = Field(default=None, alias="sourceScope")
