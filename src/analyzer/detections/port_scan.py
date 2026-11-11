"""Port scan: one source probing many ports or many hosts in a short window.

Two shapes are checked:
  * vertical scan: many distinct ports on the same host
  * horizontal scan: the same kind of probe sent to many distinct hosts

Only small flows count as probes. A scan probe is usually one SYN and maybe a
reply, while real conversations exchange more packets. This keeps a busy
client (for example a browser opening many HTTPS connections) from looking
like a scanner, though it can't rule that out completely.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from analyzer.alerts import Alert, Severity
from analyzer.flows import Flow
from analyzer.windows import Window, busiest_window

ALERT_TYPE = "port_scan"


@dataclass(frozen=True)
class Config:
    window_seconds: float = 60.0
    min_distinct_ports: int = 20  # vertical scan threshold, per target host
    min_distinct_hosts: int = 20  # horizontal scan threshold
    max_probe_packets: int = 3  # flows larger than this are not probes
    severity: Severity = Severity.MEDIUM


def detect(flows: list[Flow], config: Config = Config()) -> list[Alert]:
    probes = [flow for flow in flows if _is_probe(flow, config)]
    alerts = _vertical_scans(probes, config) + _horizontal_scans(probes, config)
    return alerts


def _is_probe(flow: Flow, config: Config) -> bool:
    return flow.key.dst_port is not None and flow.packets <= config.max_probe_packets


def _vertical_scans(probes: list[Flow], config: Config) -> list[Alert]:
    by_pair: dict[tuple[str, str], list[Flow]] = defaultdict(list)
    for flow in probes:
        by_pair[(flow.key.src_ip, flow.key.dst_ip)].append(flow)

    alerts = []
    for (src, dst), flows in by_pair.items():
        window = busiest_window(((f.start, f.key.dst_port) for f in flows), config.window_seconds)
        if window.count >= config.min_distinct_ports:
            alerts.append(_alert(src, dst, window, "ports", config))
    return alerts


def _horizontal_scans(probes: list[Flow], config: Config) -> list[Alert]:
    by_source: dict[str, list[Flow]] = defaultdict(list)
    for flow in probes:
        by_source[flow.key.src_ip].append(flow)

    alerts = []
    for src, flows in by_source.items():
        window = busiest_window(((f.start, f.key.dst_ip) for f in flows), config.window_seconds)
        if window.count >= config.min_distinct_hosts:
            alerts.append(_alert(src, None, window, "hosts", config))
    return alerts


def _alert(src: str, dst: str | None, window: Window, what: str, config: Config) -> Alert:
    target = f"host {dst}" if dst else "the network"
    return Alert(
        type=ALERT_TYPE,
        severity=config.severity,
        src_ip=src,
        dst_ip=dst,
        start=window.start,
        end=window.end,
        summary=f"{src} probed {window.count} distinct {what} on {target} "
        f"within {config.window_seconds:g}s",
        evidence={
            "scan_shape": "vertical" if what == "ports" else "horizontal",
            f"distinct_{what}": window.count,
            what: sorted(window.values),
        },
    )
