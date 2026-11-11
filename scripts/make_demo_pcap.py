"""Write a small synthetic capture that triggers every detection once.

    python scripts/make_demo_pcap.py data/demo.pcap

Everything here is crafted in memory with Scapy and written straight to a
file. Nothing is sent on any network. All addresses are private (RFC 1918)
or reserved for documentation (RFC 5737), so the capture refers to no real
hosts.

The traffic:
  * 10.0.0.66 SYN-scans 30 ports on 10.0.0.10                  -> port_scan
  * 203.0.113.7 opens 12 short SSH connections to 10.0.0.22    -> brute_force
  * 192.168.1.50 uploads ~2 MB to 198.51.100.9                 -> outbound_volume
    (only with --outbound-mb 1; the 50 MB default is too big for a demo file)
  * 10.0.0.5 queries random-looking subdomains                 -> suspicious_dns_name
  * 10.0.0.5 gets 12 NXDOMAIN answers                          -> dns_nxdomain_burst
  * plus a little normal web and DNS traffic that should NOT alert
"""

from __future__ import annotations

import sys

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

START = 1_767_225_600.0  # 2026-01-01 00:00:00 UTC, so the report has stable times
RESOLVER = "10.0.0.53"


def build_demo_packets() -> list:
    timed = (
        _normal_traffic()
        + _port_scan()
        + _ssh_brute_force()
        + _large_upload()
        + _dns_tunnel_queries()
        + _nxdomain_burst()
    )
    frames = []
    for offset, packet in sorted(timed, key=lambda item: item[0]):
        frame = Ether() / packet
        frame.time = START + offset
        frames.append(frame)
    return frames


def _tcp(src, dst, sport, dport, flags, payload=b""):
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / payload


def _dns(src, dst, name, response=False, rcode=0):
    sport, dport = (53, 5353) if response else (5353, 53)
    message = DNS(qr=int(response), rcode=rcode, qd=DNSQR(qname=name))
    return IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / message


def _normal_traffic():
    client, web = "10.0.0.5", "198.51.100.80"
    packets = [(0.0, _dns(client, RESOLVER, "www.example.com")),
               (0.01, _dns(RESOLVER, client, "www.example.com", response=True))]
    for i in range(20):  # one ordinary HTTPS conversation
        src, dst, sport, dport = (client, web, 51000, 443) if i % 2 == 0 else (web, client, 443, 51000)
        packets.append((0.1 + i * 0.05, _tcp(src, dst, sport, dport, "PA", b"x" * 500)))
    return packets


def _port_scan():
    scanner, target = "10.0.0.66", "10.0.0.10"
    packets = []
    for i, port in enumerate(range(20, 50)):
        t = 10.0 + i * 0.01
        packets.append((t, _tcp(scanner, target, 60000, port, "S")))
        packets.append((t + 0.001, _tcp(target, scanner, port, 60000, "RA")))
    return packets


def _ssh_brute_force():
    attacker, server = "203.0.113.7", "10.0.0.22"
    packets = []
    for i in range(12):
        t, sport = 20.0 + i * 3, 50000 + i
        packets.append((t, _tcp(attacker, server, sport, 22, "S")))
        packets.append((t + 0.01, _tcp(server, attacker, 22, sport, "SA")))
        packets.append((t + 0.02, _tcp(attacker, server, sport, 22, "A")))
        packets.append((t + 1.5, _tcp(attacker, server, sport, 22, "FA")))
    return packets


def _large_upload():
    laptop, external = "192.168.1.50", "198.51.100.9"
    chunk = b"u" * 1400
    return [(70.0 + i * 0.001, _tcp(laptop, external, 52000, 443, "PA", chunk))
            for i in range(1500)]


def _dns_tunnel_queries():
    labels = ["x7f3k9q2m8z1p4w6", "q8w7e6r5t4y3u2i1o0p", "zm4kq9w2x7c5v8b1n3"]
    return [(80.0 + i, _dns("10.0.0.5", RESOLVER, f"{label}.t.example.net"))
            for i, label in enumerate(labels)]


def _nxdomain_burst():
    return [(90.0 + i, _dns(RESOLVER, "10.0.0.5", f"kq{i}zt.example.org", response=True, rcode=3))
            for i in range(12)]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python scripts/make_demo_pcap.py OUTPUT.pcap", file=sys.stderr)
        return 2
    frames = build_demo_packets()
    wrpcap(argv[1], frames)
    print(f"wrote {len(frames)} packets to {argv[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
