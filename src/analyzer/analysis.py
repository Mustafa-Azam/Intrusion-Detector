"""Run the whole pipeline on one capture: packets -> flows -> detections.

The CLI is a thin layer over `analyze_capture`, so everything it does can also
be called (and tested) from Python.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from analyzer.alerts import Alert, Severity
from analyzer.detections import brute_force, outbound_volume, port_scan, suspicious_dns
from analyzer.flows import build_flows
from analyzer.packets import read_dns, read_packets


@dataclass(frozen=True)
class AnalysisConfig:
    """Thresholds for every detection, plus which alerts to keep."""

    port_scan: port_scan.Config = field(default_factory=port_scan.Config)
    brute_force: brute_force.Config = field(default_factory=brute_force.Config)
    outbound_volume: outbound_volume.Config = field(default_factory=outbound_volume.Config)
    suspicious_dns: suspicious_dns.Config = field(default_factory=suspicious_dns.Config)
    min_severity: Severity = Severity.LOW


@dataclass(frozen=True)
class AnalysisResult:
    alerts: list[Alert]
    packet_count: int
    flow_count: int


def analyze_capture(path: str | Path, config: AnalysisConfig = AnalysisConfig()) -> AnalysisResult:
    records = list(read_packets(path))
    flows = build_flows(records)
    dns_records = list(read_dns(path))

    alerts = (
        port_scan.detect(flows, config.port_scan)
        + brute_force.detect(flows, config.brute_force)
        + outbound_volume.detect(flows, config.outbound_volume)
        + suspicious_dns.detect(dns_records, config.suspicious_dns)
    )
    kept = [alert for alert in alerts if alert.severity >= config.min_severity]
    return AnalysisResult(kept, packet_count=len(records), flow_count=len(flows))
