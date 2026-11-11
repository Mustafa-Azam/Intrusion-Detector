"""End-to-end tests: generated pcap -> CLI -> report."""

import subprocess
import sys

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP

from analyzer.analysis import AnalysisConfig, analyze_capture
from analyzer.alerts import Severity
from analyzer.cli import main

SCANNER, TARGET, CLIENT, RESOLVER = "10.0.0.66", "10.0.0.10", "10.0.0.5", "10.0.0.53"


def scan_packets(ports=range(1, 26)):
    return [(i * 0.01, IP(src=SCANNER, dst=TARGET) / TCP(sport=60000, dport=p, flags="S"))
            for i, p in enumerate(ports)]


def nxdomain_packets(count=12):
    return [(100.0 + i, IP(src=RESOLVER, dst=CLIENT) / UDP(sport=53, dport=5353)
             / DNS(qr=1, rcode=3, qd=DNSQR(qname=f"n{i}.invalid")))
            for i in range(count)]


@pytest.fixture
def attack_pcap(write_pcap):
    return write_pcap(scan_packets() + nxdomain_packets())


def test_analyze_capture_runs_every_detection(attack_pcap):
    result = analyze_capture(attack_pcap)

    assert sorted(alert.type for alert in result.alerts) == ["dns_nxdomain_burst", "port_scan"]
    assert result.packet_count == 25 + 12
    assert result.flow_count == 25 + 1  # all DNS responses share one 5-tuple


def test_min_severity_filters_alerts(attack_pcap):
    config = AnalysisConfig(min_severity=Severity.HIGH)

    assert analyze_capture(attack_pcap, config).alerts == []


def test_cli_writes_report_file(attack_pcap, tmp_path, capsys):
    out = tmp_path / "out.md"

    exit_code = main(["analyze", str(attack_pcap), "--report", str(out)])

    assert exit_code == 0
    report = out.read_text()
    assert "- **Alerts:** 2 (MEDIUM 2)" in report
    assert "port\\_scan" in report
    assert "2 alert(s); report written to" in capsys.readouterr().err


def test_cli_prints_report_when_no_file_given(attack_pcap, capsys):
    assert main(["analyze", str(attack_pcap)]) == 0

    assert capsys.readouterr().out.startswith("# Network Traffic Analysis Report")


def test_cli_threshold_flag_changes_result(attack_pcap, capsys):
    main(["analyze", str(attack_pcap), "--scan-ports", "100", "--dns-nxdomain", "100"])

    assert "- **Alerts:** 0" in capsys.readouterr().out


def test_cli_min_severity_flag(attack_pcap, capsys):
    main(["analyze", str(attack_pcap), "--min-severity", "high"])

    assert "- **Alerts:** 0" in capsys.readouterr().out


def test_clean_capture_gives_no_alerts(write_pcap, capsys):
    path = write_pcap(scan_packets(ports=[80, 443]))

    assert main(["analyze", str(path)]) == 0
    assert "No alerts" in capsys.readouterr().out


def test_missing_file_is_an_error(tmp_path, capsys):
    assert main(["analyze", str(tmp_path / "nope.pcap")]) == 1
    assert "error:" in capsys.readouterr().err


def test_non_capture_file_is_an_error(tmp_path, capsys):
    junk = tmp_path / "notes.pcap"
    junk.write_text("this is not a capture")

    assert main(["analyze", str(junk)]) == 1
    assert "error:" in capsys.readouterr().err


def test_bad_internal_network_is_an_error(attack_pcap, capsys):
    assert main(["analyze", str(attack_pcap), "--internal-net", "not-a-cidr"]) == 1


def test_bad_port_list_is_rejected_by_argparse(attack_pcap):
    with pytest.raises(SystemExit) as exit_info:
        main(["analyze", str(attack_pcap), "--bf-ports", "22,abc"])

    assert exit_info.value.code == 2


def test_python_dash_m_entry_point_works():
    completed = subprocess.run([sys.executable, "-m", "analyzer", "--help"],
                               capture_output=True, text=True, check=False)

    assert completed.returncode == 0
    assert "analyze" in completed.stdout


def test_pcapng_files_are_read(tmp_path):
    from scapy.layers.l2 import Ether
    from scapy.utils import PcapNgWriter

    path = tmp_path / "scan.pcapng"
    with PcapNgWriter(str(path)) as writer:
        for timestamp, packet in scan_packets():
            frame = Ether() / packet
            frame.time = timestamp
            writer.write(frame)

    result = analyze_capture(path)

    assert [alert.type for alert in result.alerts] == ["port_scan"]
