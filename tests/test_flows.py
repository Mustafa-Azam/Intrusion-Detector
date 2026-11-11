import pytest
from scapy.layers.inet import IP, TCP

from analyzer.flows import FlowKey, build_flows
from analyzer.packets import PacketRecord, read_packets


def record(ts, src, dst, sport, dport, size=100, protocol="TCP"):
    """Build a PacketRecord directly; flow tests don't need real packets."""
    return PacketRecord(ts, src, dst, protocol, sport, dport, size)


def test_both_directions_form_one_flow():
    records = [
        record(1.0, "10.0.0.1", "10.0.0.2", 40000, 80, size=60),
        record(1.1, "10.0.0.2", "10.0.0.1", 80, 40000, size=1500),
        record(1.2, "10.0.0.1", "10.0.0.2", 40000, 80, size=40),
    ]

    [flow] = build_flows(records)

    assert flow.key == FlowKey("10.0.0.1", "10.0.0.2", 40000, 80, "TCP")
    assert (flow.orig_packets, flow.orig_bytes) == (2, 100)
    assert (flow.resp_packets, flow.resp_bytes) == (1, 1500)
    assert (flow.packets, flow.bytes) == (3, 1600)


def test_first_sender_is_the_originator():
    records = [
        record(1.0, "10.0.0.2", "10.0.0.1", 80, 40000),
        record(1.1, "10.0.0.1", "10.0.0.2", 40000, 80),
    ]

    [flow] = build_flows(records)

    assert flow.key.src_ip == "10.0.0.2"


def test_different_source_ports_are_different_flows():
    records = [
        record(1.0, "10.0.0.1", "10.0.0.2", 40000, 22),
        record(2.0, "10.0.0.1", "10.0.0.2", 40001, 22),
    ]

    assert len(build_flows(records)) == 2


def test_same_ports_different_protocol_are_different_flows():
    records = [
        record(1.0, "10.0.0.1", "10.0.0.2", 53, 53, protocol="TCP"),
        record(1.0, "10.0.0.1", "10.0.0.2", 53, 53, protocol="UDP"),
    ]

    assert len(build_flows(records)) == 2


def test_start_end_and_duration():
    records = [
        record(5.0, "10.0.0.1", "10.0.0.2", 40000, 80),
        record(7.5, "10.0.0.2", "10.0.0.1", 80, 40000),
    ]

    [flow] = build_flows(records)

    assert (flow.start, flow.end, flow.duration) == (5.0, 7.5, 2.5)


def test_out_of_order_timestamps_still_give_correct_window():
    records = [
        record(5.0, "10.0.0.1", "10.0.0.2", 40000, 80),
        record(4.0, "10.0.0.1", "10.0.0.2", 40000, 80),
    ]

    [flow] = build_flows(records)

    assert (flow.start, flow.end) == (4.0, 5.0)


def test_flows_are_sorted_by_start_time():
    records = [
        record(1.0, "10.0.0.1", "10.0.0.2", 1, 80),
        record(3.0, "10.0.0.3", "10.0.0.2", 3, 80),
        record(2.0, "10.0.0.4", "10.0.0.2", 2, 80),
    ]

    starts = [flow.start for flow in build_flows(records)]

    assert starts == [1.0, 2.0, 3.0]


def test_no_packets_gives_no_flows():
    assert build_flows([]) == []


def test_pcap_with_tcp_handshake_becomes_one_flow(write_pcap):
    client, server = "192.168.1.10", "192.168.1.20"
    path = write_pcap([
        (10.0, IP(src=client, dst=server) / TCP(sport=50000, dport=22, flags="S")),
        (10.1, IP(src=server, dst=client) / TCP(sport=22, dport=50000, flags="SA")),
        (10.2, IP(src=client, dst=server) / TCP(sport=50000, dport=22, flags="A")),
    ])

    [flow] = build_flows(read_packets(path))

    assert flow.key == FlowKey(client, server, 50000, 22, "TCP")
    assert (flow.orig_packets, flow.resp_packets) == (2, 1)
    assert flow.bytes == 3 * 40
    assert flow.duration == pytest.approx(0.2)
