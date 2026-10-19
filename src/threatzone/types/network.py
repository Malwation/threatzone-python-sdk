"""Network surface type definitions.

Mirrors the `network.response.dto.ts` DTO in the Threat.Zone Public API.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Iterable
from datetime import datetime
from typing import Annotated, Literal, TypeVar

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, PlainSerializer

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

DnsStatus = (
    Literal[
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
        "UNKNOWN",
    ]
    | str
)
"""DNS response status. ``TIMEOUT`` means that the query got no answer. ``UNKNOWN`` means that
the sensor text is not a standard status; read ``status_text``."""

ConnectOutcome = Literal["established", "no_response", "refused", "not_captured"] | str
"""Outcome of a TCP or UDP connection attempt.

``established``: the remote side answered. ``no_response``: nothing came back. ``refused``: the
remote side reset the connection. ``not_captured``: the process monitor saw the connect, but the
capture holds no flow for it, for example in a run without internet access."""

ConnectionProtocol = Literal["tcp", "udp"]
ThreatProtocol = Literal["TCP", "UDP"]
ThreatAppProto = Literal["HTTP", "TLS", "DNS"]
ThreatSeverity = Literal["high", "low", "info"] | str
NetworkThreatSeverityLevel = Literal[1, 2, 3, 4] | int
"""Suricata priority of a rule: ``1`` is the highest and ``4`` is the lowest."""
NetworkThreatCapture = Literal["decrypted_https", "offline_scan"] | str
NetworkExfilRequestApi = Literal["telegram_bot", "discord_webhook", "slack_webhook"] | str
NetworkExfilRequestKind = Literal["poll", "send_message", "send_file"] | str
NetworkExfilRequestCapture = Literal["decrypted_https"] | str

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

NetworkPacketDirection = Literal["send", "receive"] | str
"""Direction of a TCP or UDP packet. ``send``: from the analysis machine. ``receive``: from the
remote endpoint."""

NetworkHostFlowProtocol = Literal["DNS", "HTTP", "TCP", "UDP"] | str

_ItemT = TypeVar("_ItemT")


class TotalCountList(list[_ItemT]):
    """A page of a network list route, with the total of matching rows.

    The object is a plain ``list`` of the rows. ``total_count`` is the ``X-Total-Count``
    response header: the number of rows that match the request without ``skip`` and
    ``limit``, with the same filters. More pages exist when ``skip + len(page)`` is less than
    ``total_count``. It is ``None`` when the server does not send the header.
    """

    total_count: int | None

    def __init__(self, items: Iterable[_ItemT] = (), *, total_count: int | None = None) -> None:
        super().__init__(items)
        self.total_count = total_count


def _decode_base64(value: object) -> object:
    if not isinstance(value, str):
        return value
    try:
        return base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise ValueError("data must be base64 (RFC 4648, with padding)") from exc


def _encode_base64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


Base64Payload = Annotated[
    bytes,
    BeforeValidator(_decode_base64),
    PlainSerializer(_encode_base64, return_type=str, when_used="json"),
]
"""Bytes that the API sends as a base64 string. JSON serialization encodes them again."""


class NetworkAvailability(BaseModel):
    """Network evidence state of a Windows V2 report."""

    model_config = ConfigDict(populate_by_name=True)

    state: NetworkAvailabilityState
    reason: str | None = None
    coverage: NetworkCoverage


class NetworkSourceCounts(BaseModel):
    """Rows of one network list by source."""

    model_config = ConfigDict(populate_by_name=True)

    sample: int
    sample_child: int = Field(alias="sampleChild")
    sensor_only: int = Field(alias="sensorOnly")
    windows_background: int = Field(alias="windowsBackground")


class NetworkAttributionCounts(BaseModel):
    """Rows of each network list by source.

    Rows without a stored source count as ``sample``. When a list of an older report has no
    stored sources, ``sensor_only`` also counts the records of ``unattributed_counts``.
    """

    model_config = ConfigDict(populate_by_name=True)

    dns: NetworkSourceCounts
    http: NetworkSourceCounts
    tcp: NetworkSourceCounts
    udp: NetworkSourceCounts
    threats: NetworkSourceCounts


class NetworkUnattributedCounts(BaseModel):
    """Records of the network sensor summary of an older report without a sample process."""

    model_config = ConfigDict(populate_by_name=True)

    dns: int
    http: int
    tcp: int
    udp: int
    threats: int


class NetworkSubmissionOnlyAlertRow(BaseModel):
    """One Suricata alert that the scan of the recorded traffic found."""

    model_config = ConfigDict(populate_by_name=True)

    line_number: int = Field(alias="lineNumber")
    sid: int | None = None
    signature: str | None = None
    severity: int | None = None
    """Suricata priority, ``1`` (highest) to ``4``."""
    protocol: str | None = None
    source_ip: str | None = Field(default=None, alias="sourceIp")
    destination_ip: str | None = Field(default=None, alias="destinationIp")


class NetworkSubmissionOnlyAlerts(BaseModel):
    """Suricata alerts outside the remote IP addresses of the sample.

    No sample process is linked to them. ``rows`` holds at most 100 alerts; ``omitted`` gives
    the alerts that the report did not keep.
    """

    model_config = ConfigDict(populate_by_name=True)

    scope: str
    source: str
    total: int
    omitted: int
    rows: list[NetworkSubmissionOnlyAlertRow]


class NetworkSummary(BaseModel):
    """Summary of network activity captured during dynamic analysis."""

    model_config = ConfigDict(populate_by_name=True)

    dns_count: int = Field(alias="dnsCount")
    http_count: int = Field(alias="httpCount")
    tcp_count: int = Field(alias="tcpCount")
    udp_count: int = Field(alias="udpCount")
    threat_count: int = Field(alias="threatCount")
    pcap_available: bool = Field(alias="pcapAvailable")
    exfil_request_count: int | None = Field(default=None, alias="exfilRequestCount")
    windows_background_count: int | None = Field(default=None, alias="windowsBackgroundCount")
    counts_available: bool | None = Field(default=None, alias="countsAvailable")
    availability: NetworkAvailability | None = None
    source_scope: NetworkSourceScope | None = Field(default=None, alias="sourceScope")
    https_pcap_available: bool | None = Field(default=None, alias="httpsPcapAvailable")
    """``True`` when the report stored the decrypted capture of the relayed HTTPS
    connections. Download it with ``download_https_pcap()``."""
    has_https_inspection: bool | None = Field(default=None, alias="hasHttpsInspection")
    """``True`` when the analysis ran with HTTPS inspection."""
    unattributed_pcap_available: bool | None = Field(
        default=None, alias="unattributedPcapAvailable"
    )
    """``True`` when ``source_scope`` is ``submission_unattributed`` and ``download_pcap()``
    returns the full capture of the analysis. Its traffic is not linked to a sample process."""
    attribution_counts: NetworkAttributionCounts | None = Field(
        default=None, alias="attributionCounts"
    )
    """Rows of each list by source, also the ``windows_background`` rows."""
    unattributed_counts: NetworkUnattributedCounts | None = Field(
        default=None, alias="unattributedCounts"
    )
    """Records of the sensor summary of an older report that no sample process is linked to.
    The lists do not return them. ``None`` when the report has no sensor summary."""
    submission_only_alerts: NetworkSubmissionOnlyAlerts | None = Field(
        default=None, alias="submissionOnlyAlerts"
    )
    """Suricata alerts outside the remote addresses of the sample. ``get_network_threats()``
    does not return them. ``None`` when the report has none."""


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
    answered: bool | None = None
    """``False`` when the query got no answer. ``None`` for rows of older reports and on older
    servers."""
    timeshift: float
    timeshift_seconds: float | None = Field(default=None, alias="timeshiftSeconds")
    """Seconds from the start of the capture. ``None`` when the server does not send it."""
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
    source_ip: str | None = Field(default=None, alias="sourceIp")
    """Local address of the connection, usually the analysis machine."""
    source_port: int | None = Field(default=None, alias="sourcePort")
    destination_ip: str = Field(alias="destinationIp")
    destination_port: int = Field(alias="destinationPort")
    domain: str | None = None
    """Best host name of ``destination_ip``: the DNS answer, the TLS SNI, the HTTP ``Host``
    header, the reverse DNS name, then the sensor host name. It is not always reverse DNS."""
    ptr_domain: str | None = Field(default=None, alias="ptrDomain")
    """Reverse DNS (PTR) name of ``destination_ip``. It can differ from ``domain``."""
    asn: str | None = None
    country: str | None = None
    packets: ConnectionPackets
    app_proto: str | None = Field(default=None, alias="appProto")
    """Application protocol that the live network sensor linked to the flow."""
    hostname: str | None = None
    """Host name that the live network sensor linked to the flow."""
    pkts_to_server: int | None = Field(default=None, alias="pktsToServer")
    pkts_to_client: int | None = Field(default=None, alias="pktsToClient")
    bytes_to_server: int | None = Field(default=None, alias="bytesToServer")
    bytes_to_client: int | None = Field(default=None, alias="bytesToClient")
    packets_total: int | None = Field(default=None, alias="packetsTotal")
    """Capture packets of the flow."""
    packets_omitted: int | None = Field(default=None, alias="packetsOmitted")
    """Capture packets that the report packet limit left out. Download the PCAP to read them."""
    connect_outcome: ConnectOutcome | None = Field(default=None, alias="connectOutcome")
    """Outcome of the connection attempt. ``None`` for rows of older reports and on older
    servers."""
    timeshift: float
    timeshift_seconds: float | None = Field(default=None, alias="timeshiftSeconds")
    """Seconds from the start of the capture. ``None`` when the server does not send it."""
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
    severity_level: NetworkThreatSeverityLevel | None = Field(default=None, alias="severityLevel")
    """Suricata priority, ``1`` (highest) to ``4``. ``severity`` is the label of this value.
    ``None`` when the stored value is not 1 to 4."""
    protocol: ThreatProtocol
    app_proto: ThreatAppProto = Field(alias="appProto")
    source_ip: str | None = Field(default=None, alias="sourceIp")
    source_port: int | None = Field(default=None, alias="sourcePort")
    destination_ip: str = Field(alias="destinationIp")
    destination_port: int = Field(alias="destinationPort")
    timeshift: float
    timeshift_seconds: float | None = Field(default=None, alias="timeshiftSeconds")
    """Seconds from the start of the capture. ``None`` when the server does not send it."""
    metadata: dict[str, list[str]]
    details: dict[str, str | int]
    tls: NetworkThreatTls | None = None
    capture: NetworkThreatCapture | None = None
    source_scope: NetworkSourceScope | None = Field(default=None, alias="sourceScope")


class NetworkExfilRequest(BaseModel):
    """Chat bot or webhook requests read from the decrypted HTTPS capture.

    One entry groups the requests of one API, bot or webhook, and kind.
    ``masked_target`` is the request target as sent, with the full bot token
    or webhook secret. Old reports show a shortened token.
    """

    model_config = ConfigDict(populate_by_name=True)

    api: NetworkExfilRequestApi | None = None
    kind: NetworkExfilRequestKind | None = None
    host: str | None = None
    method: str | None = None
    api_method: str | None = Field(default=None, alias="apiMethod")
    target_id: str | None = Field(default=None, alias="targetId")
    masked_target: str | None = Field(default=None, alias="maskedTarget")
    request_bytes: int | None = Field(default=None, alias="requestBytes")
    reply_status: int | None = Field(default=None, alias="replyStatus")
    request_count: int | None = Field(default=None, alias="requestCount")
    capture: NetworkExfilRequestCapture | None = None
    first_seen: datetime | None = Field(default=None, alias="firstSeen")
    score: float | None = None
    tier: str | None = None
    process_id: int | None = Field(default=None, alias="processId")
    process_image: str | None = Field(default=None, alias="processImage")
    text: str | None = None


class NetworkPacketData(BaseModel):
    """Stored payload of one packet: an HTTP body or a TCP or UDP payload.

    ``data`` holds the stored bytes, decoded from base64. The payload is not masked. The hashes
    cover the stored bytes and are ``None`` when the sandbox did not compute them.
    """

    model_config = ConfigDict(populate_by_name=True)

    trimmed: bool
    """``True`` when the sandbox stored only the first part of the payload."""
    sha256: str | None = None
    md5: str | None = None
    sha1: str | None = None
    ssdeep: str | None = None
    data: Base64Payload


class NetworkHttpPacketResponse(BaseModel):
    """The response to one HTTP request."""

    model_config = ConfigDict(populate_by_name=True)

    timeshift: float
    destination_ip: str = Field(alias="destinationIp")
    destination_port: int = Field(alias="destinationPort")
    headers: dict[str, str] | None = None
    status_code: int = Field(alias="statusCode")
    body: NetworkPacketData | None = None


class NetworkHttpPacket(BaseModel):
    """One request and response pair of an HTTP request entry."""

    model_config = ConfigDict(populate_by_name=True)

    timeshift: float
    url: str
    method: str
    """HTTP method as sent. A non-standard method is returned as sent."""
    destination_ip: str = Field(alias="destinationIp")
    destination_port: int = Field(alias="destinationPort")
    """Remote port. It is ``0`` when ``port_known`` is ``False``."""
    port_known: bool = Field(alias="portKnown")
    """``False`` for a sensor summary record of an older report. Then the ports are ``0`` and
    the headers and bodies are ``None``."""
    headers: dict[str, str] | None = None
    body: NetworkPacketData | None = None
    response: NetworkHttpPacketResponse | None = None


class NetworkHttpPackets(BaseModel):
    """The stored request and response pairs of one HTTP request entry."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[NetworkHttpPacket]
    """At most 200 pairs, in stored order."""
    truncated: bool
    """``True`` when the entry has more stored pairs than ``items``. Download the PCAP."""
    source_scope: NetworkSourceScope | None = Field(default=None, alias="sourceScope")


class NetworkFlowPacket(BaseModel):
    """One stored packet of a TCP or UDP connection."""

    model_config = ConfigDict(populate_by_name=True)

    type: NetworkPacketDirection
    data: NetworkPacketData | None = None
    """``None`` when the sandbox stored no payload for the packet."""


class NetworkFlowPackets(BaseModel):
    """The stored packets of one TCP or UDP connection."""

    model_config = ConfigDict(populate_by_name=True)

    protocol: ConnectionProtocol
    source_ip: str | None = Field(default=None, alias="sourceIp")
    source_port: int | None = Field(default=None, alias="sourcePort")
    destination_ip: str = Field(alias="destinationIp")
    destination_port: int = Field(alias="destinationPort")
    items: list[NetworkFlowPacket]
    """At most 200 packets, in stored order."""
    truncated: bool
    """``True`` when the connection has more stored packets than ``items``. Download the
    PCAP."""
    source_scope: NetworkSourceScope | None = Field(default=None, alias="sourceScope")


class NetworkEndpoint(BaseModel):
    """One remote endpoint of the network map: the rows of one host joined."""

    model_config = ConfigDict(populate_by_name=True)

    key: str
    """Host name in lower case, else the IP address. Send it as ``host`` to
    ``get_network_host_flows()``."""
    host: str | None = None
    """``None`` when no host name is known, or when several names resolved to the address."""
    ips: list[str]
    ports: list[int]
    """Remote ports. Port ``0`` is left out."""
    protocols: list[str]
    source: NetworkAttribution
    """The strongest row source: ``sample``, ``sample_child``, ``sensor_only``, then
    ``windows_background``."""
    first_timeshift: float | None = Field(default=None, alias="firstTimeshift")
    last_timeshift: float | None = Field(default=None, alias="lastTimeshift")
    request_count: int = Field(alias="requestCount")
    """DNS queries, HTTP requests and TCP and UDP flows of the endpoint."""
    alert_count: int = Field(alias="alertCount")
    max_alert_severity: str | None = Field(default=None, alias="maxAlertSeverity")
    """Deprecated: read ``max_alert_severity_level``. Highest alert severity as text. ``"1"`` is
    the highest. ``None`` without alerts."""
    max_alert_severity_level: NetworkThreatSeverityLevel | None = Field(
        default=None, alias="maxAlertSeverityLevel"
    )
    """Highest alert severity, ``1`` (high) to ``4`` (info), on the scale of
    ``NetworkThreat.severity_level``. ``None`` without alerts and on older servers."""
    process_ids: list[int] = Field(alias="processIds")
    attribution_note: str | None = Field(default=None, alias="attributionNote")


class NetworkEndpoints(BaseModel):
    """The endpoints of a submission, sample endpoints first."""

    model_config = ConfigDict(populate_by_name=True)

    items: list[NetworkEndpoint]
    total: int
    """Endpoints before ``limit``. A lower limit when ``truncated`` is ``True``."""
    truncated: bool


class NetworkHostFlowMethod(BaseModel):
    """One HTTP method of a flow, with its request count."""

    model_config = ConfigDict(populate_by_name=True)

    method: str
    count: int


class NetworkHostFlow(BaseModel):
    """The rows of one host with the same protocol, remote address and ports."""

    model_config = ConfigDict(populate_by_name=True)

    protocol: NetworkHostFlowProtocol
    remote_ip: str | None = Field(default=None, alias="remoteIp")
    """``None`` for a DNS query."""
    remote_port: int | None = Field(default=None, alias="remotePort")
    local_port: int | None = Field(default=None, alias="localPort")
    """Set only for a TCP or UDP flow."""
    count: int
    bytes_sent: int | None = Field(default=None, alias="bytesSent")
    bytes_received: int | None = Field(default=None, alias="bytesReceived")
    first_timeshift: float | None = Field(default=None, alias="firstTimeshift")
    last_timeshift: float | None = Field(default=None, alias="lastTimeshift")
    process_ids: list[int] = Field(alias="processIds")
    """Up to 5 process IDs."""
    methods: list[NetworkHostFlowMethod]
    """HTTP only: up to 5 methods, the most frequent first."""
    sample_paths: list[str] = Field(alias="samplePaths")
    """HTTP only: up to 5 request URLs as the sensor recorded them. The URLs are not masked."""


class NetworkHostFlowTotals(BaseModel):
    """Rows of the host for each protocol."""

    model_config = ConfigDict(populate_by_name=True)

    dns_queries: int = Field(alias="dnsQueries")
    http_requests: int = Field(alias="httpRequests")
    tcp_flows: int = Field(alias="tcpFlows")
    udp_flows: int = Field(alias="udpFlows")


class NetworkHostAlert(BaseModel):
    """The network alerts of a host with the same signature and severity."""

    model_config = ConfigDict(populate_by_name=True)

    signature: str
    severity: int | None = None
    """``1`` (high) to ``4`` (info). ``None`` when the alert does not record it."""
    count: int
    first_timeshift: float | None = Field(default=None, alias="firstTimeshift")


class NetworkHostFlowsPageInfo(BaseModel):
    """Cursor of the host flow pages."""

    model_config = ConfigDict(populate_by_name=True)

    end_cursor: str | None = Field(default=None, alias="endCursor")
    """Send it as ``after`` for the next page. ``None`` on an empty page."""
    has_next_page: bool = Field(alias="hasNextPage")


class NetworkHostFlows(BaseModel):
    """One page of the flows of one endpoint."""

    model_config = ConfigDict(populate_by_name=True)

    flows: list[NetworkHostFlow]
    totals: NetworkHostFlowTotals
    """The same on every page."""
    alerts: list[NetworkHostAlert] = Field(default_factory=list)
    """Up to 20 alert groups of the host, the most severe first. The same on every page.
    Empty when an older server omits the field."""
    page_info: NetworkHostFlowsPageInfo = Field(alias="pageInfo")
    truncated: bool
    """``True`` when the server read only the first 5000 rows of a source. Then the flows,
    totals and alert counts are a lower limit."""
