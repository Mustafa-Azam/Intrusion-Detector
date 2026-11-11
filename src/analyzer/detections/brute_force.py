"""Brute force: many short connections from one source to a login service.

Password-guessing tools open a connection, try a password, get rejected and
reconnect. In flow terms that is many short flows from one source to the same
host and port (SSH 22, RDP 3389, ...). Encrypted protocols hide whether a login
failed, so this rule only sees the connection pattern, not the outcome.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from analyzer.alerts import Alert, Severity
from analyzer.flows import Flow
from analyzer.windows import busiest_window

ALERT_TYPE = "brute_force"

# Common remote-login services: FTP, SSH, Telnet, SMB, RDP, VNC.
DEFAULT_PORTS = frozenset({21, 22, 23, 445, 3389, 5900})


@dataclass(frozen=True)
class Config:
    ports: frozenset[int] = DEFAULT_PORTS
    window_seconds: float = 60.0
    min_attempts: int = 10  # short connections inside one window
    max_duration_seconds: float = 10.0  # longer connections aren't "short"
    severity: Severity = Severity.HIGH


def detect(flows: list[Flow], config: Config = Config()) -> list[Alert]:
    attempts = defaultdict(list)
    for flow in flows:
        if _is_short_login_attempt(flow, config):
            key = (flow.key.src_ip, flow.key.dst_ip, flow.key.dst_port)
            attempts[key].append(flow)

    alerts = []
    for (src, dst, port), group in attempts.items():
        # Each flow has its own source port, so its key makes it a distinct
        # value: the window count is then simply the number of connections.
        window = busiest_window(((f.start, f.key) for f in group), config.window_seconds)
        if window.count >= config.min_attempts:
            alerts.append(_alert(src, dst, port, window, config))
    return alerts


def _is_short_login_attempt(flow: Flow, config: Config) -> bool:
    return (
        flow.key.protocol == "TCP"
        and flow.key.dst_port in config.ports
        and flow.duration <= config.max_duration_seconds
    )


def _alert(src, dst, port, window, config: Config) -> Alert:
    return Alert(
        type=ALERT_TYPE,
        severity=config.severity,
        src_ip=src,
        dst_ip=dst,
        start=window.start,
        end=window.end,
        summary=f"{src} made {window.count} short connections to {dst}:{port} "
        f"within {config.window_seconds:g}s",
        evidence={"dst_port": port, "connections": window.count},
    )
