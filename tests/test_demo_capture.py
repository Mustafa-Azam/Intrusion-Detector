"""Keeps the README's sample report honest: the demo capture must keep
producing exactly the alerts the docs show."""

import importlib.util
from pathlib import Path

from scapy.utils import wrpcap

from analyzer.analysis import AnalysisConfig, analyze_capture
from analyzer.detections import outbound_volume

SCRIPT = Path(__file__).parent.parent / "scripts" / "make_demo_pcap.py"


def load_demo_module():
    spec = importlib.util.spec_from_file_location("make_demo_pcap", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_capture_triggers_each_detection_once(tmp_path):
    path = tmp_path / "demo.pcap"
    wrpcap(str(path), load_demo_module().build_demo_packets())
    config = AnalysisConfig(outbound_volume=outbound_volume.Config(min_bytes=1_000_000))

    result = analyze_capture(path, config)

    assert sorted(alert.type for alert in result.alerts) == [
        "brute_force",
        "dns_nxdomain_burst",
        "outbound_volume",
        "port_scan",
        "suspicious_dns_name",
    ]
    # The ordinary web client must not be blamed for anything except the
    # DNS activity the demo deliberately gives it.
    web_alerts = [a for a in result.alerts if a.dst_ip == "198.51.100.80"]
    assert web_alerts == []
