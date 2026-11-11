from analyzer.alerts import Severity
from analyzer.detections import port_scan
from helpers import make_flow

SCANNER, TARGET = "10.0.0.66", "10.0.0.10"


def test_many_ports_on_one_host_is_a_vertical_scan():
    flows = [make_flow(SCANNER, TARGET, port, start=i * 0.1)
             for i, port in enumerate(range(1, 26))]

    [alert] = port_scan.detect(flows)

    assert alert.type == "port_scan"
    assert alert.severity == Severity.MEDIUM
    assert (alert.src_ip, alert.dst_ip) == (SCANNER, TARGET)
    assert alert.evidence["scan_shape"] == "vertical"
    assert alert.evidence["distinct_ports"] == 25


def test_one_port_on_many_hosts_is_a_horizontal_scan():
    flows = [make_flow(SCANNER, f"10.0.1.{i}", 445, start=i * 0.1) for i in range(1, 31)]

    [alert] = port_scan.detect(flows)

    assert alert.dst_ip is None
    assert alert.evidence["distinct_hosts"] == 30


def test_few_ports_is_not_a_scan():
    flows = [make_flow(SCANNER, TARGET, port, start=0.0) for port in (22, 80, 443)]

    assert port_scan.detect(flows) == []


def test_ports_spread_over_a_long_time_are_not_a_scan():
    # 25 ports, but one every 10 minutes: never 20 inside a 60 s window.
    flows = [make_flow(SCANNER, TARGET, port, start=i * 600.0)
             for i, port in enumerate(range(1, 26))]

    assert port_scan.detect(flows) == []


def test_busy_client_with_real_conversations_is_not_a_scan():
    # A browser talking to 30 sites: many hosts, but each flow is large.
    flows = [make_flow("10.0.0.5", f"93.184.0.{i}", 443, start=i * 0.5, packets=40)
             for i in range(30)]

    assert port_scan.detect(flows) == []


def test_thresholds_are_configurable():
    flows = [make_flow(SCANNER, TARGET, port, start=0.0) for port in (22, 80, 443)]
    config = port_scan.Config(min_distinct_ports=3)

    assert len(port_scan.detect(flows, config)) == 1


def test_syn_scan_in_a_real_pcap_is_detected(write_pcap):
    """End to end: Scapy packets -> pcap -> flows -> alert."""
    from scapy.layers.inet import IP, TCP

    from analyzer.flows import build_flows
    from analyzer.packets import read_packets

    timed_packets = []
    for i, port in enumerate(range(20, 45)):
        t = i * 0.01
        syn = IP(src=SCANNER, dst=TARGET) / TCP(sport=60000, dport=port, flags="S")
        rst = IP(src=TARGET, dst=SCANNER) / TCP(sport=port, dport=60000, flags="RA")
        timed_packets += [(t, syn), (t + 0.001, rst)]

    flows = build_flows(read_packets(write_pcap(timed_packets)))
    [alert] = port_scan.detect(flows)

    assert alert.evidence["distinct_ports"] == 25
