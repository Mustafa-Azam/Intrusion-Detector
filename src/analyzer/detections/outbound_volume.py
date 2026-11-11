"""Unusual outbound volume: an internal host sending a lot of data to one
external destination, which can indicate data exfiltration.

"Unusual" here means above a fixed byte threshold over the whole capture.
There is no learned baseline, so legitimate large uploads (backups, cloud
sync, video calls) will also trigger it.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass

from analyzer.alerts import Alert, Severity
from analyzer.flows import Flow

ALERT_TYPE = "outbound_volume"

# Private address ranges (RFC 1918 for IPv4, unique local for IPv6).
DEFAULT_INTERNAL_NETWORKS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")


@dataclass(frozen=True)
class Config:
    min_bytes: int = 50_000_000  # 50 MB to one destination
    internal_networks: tuple[str, ...] = DEFAULT_INTERNAL_NETWORKS
    severity: Severity = Severity.MEDIUM


@dataclass
class _Total:
    bytes: int = 0
    flows: int = 0
    start: float = float("inf")
    end: float = float("-inf")


def detect(flows: list[Flow], config: Config = Config()) -> list[Alert]:
    networks = [ipaddress.ip_network(n) for n in config.internal_networks]
    totals: dict[tuple[str, str], _Total] = defaultdict(_Total)
    for flow in flows:
        _add_outbound(totals, flow, networks)
    return [
        _alert(src, dst, total, config)
        for (src, dst), total in totals.items()
        if total.bytes >= config.min_bytes
    ]


def _add_outbound(totals, flow: Flow, networks) -> None:
    """Credit the bytes an internal host sent to an external one.

    Either side may have opened the connection, so check both directions.
    """
    src_inside = _is_internal(flow.key.src_ip, networks)
    dst_inside = _is_internal(flow.key.dst_ip, networks)
    if src_inside and not dst_inside:
        pair, sent = (flow.key.src_ip, flow.key.dst_ip), flow.orig_bytes
    elif dst_inside and not src_inside:
        pair, sent = (flow.key.dst_ip, flow.key.src_ip), flow.resp_bytes
    else:
        return
    total = totals[pair]
    total.bytes += sent
    total.flows += 1
    total.start = min(total.start, flow.start)
    total.end = max(total.end, flow.end)


def _is_internal(ip: str, networks) -> bool:
    address = ipaddress.ip_address(ip)
    return any(address in network for network in networks)


def _alert(src: str, dst: str, total: _Total, config: Config) -> Alert:
    return Alert(
        type=ALERT_TYPE,
        severity=config.severity,
        src_ip=src,
        dst_ip=dst,
        start=total.start,
        end=total.end,
        summary=f"{src} sent {total.bytes:,} bytes to external host {dst}",
        evidence={"bytes_sent": total.bytes, "flows": total.flows},
    )
