"""Read a pcap file into simple packet records.

This is the only module that touches Scapy. Everything after it works on
PacketRecord, a plain dataclass, so the flow builder and the detections can be
tested without building real packets.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet
from scapy.utils import PcapReader

# IP protocol numbers we give readable names to. Anything else is reported as
# "IP-<number>" so it is still counted rather than silently dropped.
PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}

IPV6_HEADER_BYTES = 40


@dataclass(frozen=True)
class PacketRecord:
    """The few facts about one IP packet that the analyzer needs."""

    timestamp: float  # seconds since the Unix epoch, from the pcap
    src_ip: str
    dst_ip: str
    protocol: str  # "TCP", "UDP", "ICMP", "ICMPv6" or "IP-<number>"
    src_port: int | None  # None for protocols without ports
    dst_port: int | None
    size: int  # bytes at the IP layer, from the IP header


def read_packets(path: str | Path) -> Iterator[PacketRecord]:
    """Yield a PacketRecord for each IPv4/IPv6 packet in the capture.

    Non-IP frames (ARP, for example) are skipped. PcapReader streams the file
    one packet at a time, so large captures don't have to fit in memory.
    """
    with PcapReader(str(path)) as reader:
        for packet in reader:
            record = to_record(packet)
            if record is not None:
                yield record


def to_record(packet: Packet) -> PacketRecord | None:
    """Convert one Scapy packet, or return None if it is not IP."""
    ip = _ip_layer(packet)
    if ip is None:
        return None
    protocol_number = _protocol_number(ip)
    src_port, dst_port = _ports(ip, protocol_number)
    return PacketRecord(
        timestamp=float(packet.time),
        src_ip=ip.src,
        dst_ip=ip.dst,
        protocol=PROTOCOL_NAMES.get(protocol_number, f"IP-{protocol_number}"),
        src_port=src_port,
        dst_port=dst_port,
        size=_ip_size(ip),
    )


def _ip_layer(packet: Packet) -> Packet | None:
    if IP in packet:
        return packet[IP]
    if IPv6 in packet:
        return packet[IPv6]
    return None


def _protocol_number(ip: Packet) -> int:
    # IPv4 calls it "proto", IPv6 calls it "nh" (next header). For IPv6 this
    # ignores extension headers, which is a known simplification.
    return ip.proto if isinstance(ip, IP) else ip.nh


def _ports(ip: Packet, protocol_number: int) -> tuple[int | None, int | None]:
    # Look only at the layer directly after IP. Searching the whole packet
    # (e.g. `UDP in packet`) would wrongly find the copy of the original
    # UDP header that ICMP error messages carry inside them.
    transport = ip.payload
    if protocol_number in (6, 17) and isinstance(transport, (TCP, UDP)):
        return transport.sport, transport.dport
    return None, None


def _ip_size(ip: Packet) -> int:
    # Use the length field from the header, not the number of captured bytes.
    # Captures are often truncated (snaplen), but the header still says how big
    # the packet really was on the wire.
    if isinstance(ip, IP):
        return ip.len
    return IPV6_HEADER_BYTES + ip.plen


@dataclass(frozen=True)
class DnsRecord:
    """One DNS query or response, with only the fields the DNS rules use."""

    timestamp: float
    src_ip: str
    dst_ip: str
    query_name: str  # without the trailing dot, e.g. "example.com"
    is_response: bool
    rcode: int  # 0 = NOERROR, 3 = NXDOMAIN (only meaningful for responses)


def read_dns(path: str | Path) -> Iterator[DnsRecord]:
    """Yield a DnsRecord for each DNS message (over UDP or TCP) with a question.

    This is a second pass over the file. Reading twice is simpler than mixing
    DNS fields into PacketRecord, and speed is not a concern for offline use.
    """
    with PcapReader(str(path)) as reader:
        for packet in reader:
            record = to_dns_record(packet)
            if record is not None:
                yield record


def to_dns_record(packet: Packet) -> DnsRecord | None:
    ip = _ip_layer(packet)
    if ip is None or DNS not in packet:
        return None
    dns = packet[DNS]
    if not dns.qd:
        return None
    return DnsRecord(
        timestamp=float(packet.time),
        src_ip=ip.src,
        dst_ip=ip.dst,
        query_name=_decode_name(dns.qd[0].qname),
        is_response=bool(dns.qr),
        rcode=dns.rcode,
    )


def _decode_name(raw: bytes) -> str:
    # errors="replace" so a malformed name can't crash the whole analysis.
    return raw.decode("ascii", errors="replace").rstrip(".")
