from scapy.layers.inet import ICMP, IP, TCP, UDP, IPerror, UDPerror
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

from analyzer.packets import read_packets


def test_reads_tcp_packet_fields(write_pcap):
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=22)
    path = write_pcap([(100.5, packet)])

    [record] = list(read_packets(path))

    assert record.timestamp == 100.5
    assert (record.src_ip, record.dst_ip) == ("10.0.0.1", "10.0.0.2")
    assert record.protocol == "TCP"
    assert (record.src_port, record.dst_port) == (40000, 22)
    assert record.size == 40  # 20-byte IP header + 20-byte TCP header


def test_reads_udp_ports_and_payload_size(write_pcap):
    packet = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=5353, dport=53) / (b"x" * 12)
    path = write_pcap([(1.0, packet)])

    [record] = list(read_packets(path))

    assert record.protocol == "UDP"
    assert (record.src_port, record.dst_port) == (5353, 53)
    assert record.size == 20 + 8 + 12


def test_icmp_has_no_ports(write_pcap):
    path = write_pcap([(1.0, IP(src="10.0.0.1", dst="10.0.0.2") / ICMP())])

    [record] = list(read_packets(path))

    assert record.protocol == "ICMP"
    assert record.src_port is None and record.dst_port is None


def test_icmp_error_is_not_mistaken_for_the_udp_inside_it(write_pcap):
    # "Port unreachable" carries a copy of the original UDP header.
    inner = IPerror(src="10.0.0.1", dst="10.0.0.2") / UDPerror(sport=1234, dport=9999)
    packet = IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(type=3, code=3) / inner
    path = write_pcap([(1.0, packet)])

    [record] = list(read_packets(path))

    assert record.protocol == "ICMP"
    assert record.dst_port is None


def test_reads_ipv6(write_pcap):
    packet = IPv6(src="fe80::1", dst="fe80::2") / UDP(sport=1000, dport=2000)
    path = write_pcap([(1.0, packet)])

    [record] = list(read_packets(path))

    assert record.src_ip == "fe80::1"
    assert record.protocol == "UDP"
    assert record.size == 40 + 8


def test_skips_non_ip_frames(tmp_path):
    path = tmp_path / "arp.pcap"
    wrpcap(str(path), [Ether() / ARP(psrc="10.0.0.1", pdst="10.0.0.2")])

    assert list(read_packets(path)) == []
