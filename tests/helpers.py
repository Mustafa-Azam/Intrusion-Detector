"""Small builders so detection tests can describe traffic in one line each."""

from analyzer.flows import Flow, FlowKey
from analyzer.packets import DnsRecord


def make_flow(src, dst, dport, start, *, sport=40000, protocol="TCP",
              duration=0.5, packets=2, orig_bytes=100, resp_bytes=0):
    """A flow from src to dst. Packets are split between the two directions."""
    return Flow(
        key=FlowKey(src, dst, sport, dport, protocol),
        start=start,
        end=start + duration,
        orig_packets=packets - packets // 2,
        orig_bytes=orig_bytes,
        resp_packets=packets // 2,
        resp_bytes=resp_bytes,
    )


def dns_query(name, ts=1.0, client="10.0.0.5", resolver="10.0.0.53"):
    return DnsRecord(ts, client, resolver, name, is_response=False, rcode=0)


def dns_response(name, rcode, ts=1.0, client="10.0.0.5", resolver="10.0.0.53"):
    return DnsRecord(ts, resolver, client, name, is_response=True, rcode=rcode)
