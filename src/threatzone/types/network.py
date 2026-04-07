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


class NetworkSummary(BaseModel):
    """Summary of network activity captured during dynamic analysis."""

    model_config = ConfigDict(populate_by_name=True)

    dns_count: int = Field(alias="dnsCount")
    http_count: int = Field(alias="httpCount")
    tcp_count: int = Field(alias="tcpCount")
    udp_count: int = Field(alias="udpCount")
    threat_count: int = Field(alias="threatCount")
    pcap_available: bool = Field(alias="pcapAvailable")


class DnsQuery(BaseModel):
    """A DNS query captured during dynamic analysis."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    host: str
    type: DnsRecordType
    status: DnsStatus
    records: list[str]
    timeshift: float


class HttpRequest(BaseModel):
    """An HTTP request observed during dynamic analysis (slim shape)."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    host: str
    ip: str
    port: int
    country: str | None = None


class ConnectionPackets(BaseModel):
    """Packet count summary for a network connection."""

    model_config = ConfigDict(populate_by_name=True)

    sent: int
    received: int
    empty: bool


class Connection(BaseModel):
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


class NetworkThreatTls(BaseModel):
    """TLS fingerprint block attached to TLS-bound network threats."""

    model_config = ConfigDict(populate_by_name=True)

    version: str
    sni: str
    ja3_hash: str = Field(alias="ja3Hash")
    ja3s_hash: str = Field(alias="ja3sHash")
    ja3_string: str = Field(alias="ja3String")
    ja3s_string: str = Field(alias="ja3sString")


class NetworkThreat(BaseModel):
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
