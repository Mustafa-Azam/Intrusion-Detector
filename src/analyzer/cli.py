"""Command-line interface.

    python -m analyzer analyze capture.pcap --report out.md

The CLI only parses arguments, builds an AnalysisConfig, calls the analysis
and writes the report. `main()` takes argv and returns an exit code instead
of calling sys.exit, so tests can call it directly.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from analyzer import __version__
from analyzer.alerts import Severity
from analyzer.analysis import AnalysisConfig, AnalysisResult, analyze_capture
from analyzer.detections import brute_force, outbound_volume, port_scan, suspicious_dns
from analyzer.packets import CaptureReadError
from analyzer.report import ReportContext, render_markdown

EXIT_OK = 0
EXIT_INPUT_ERROR = 1  # argparse itself uses 2 for bad arguments


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m analyzer",
        description="Offline analysis of saved packet captures for suspicious activity.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    _add_analyze_command(commands)
    return parser


def _add_analyze_command(commands) -> None:
    analyze = commands.add_parser(
        "analyze",
        help="analyze a pcap/pcapng file and write a Markdown report",
    )
    analyze.add_argument("capture", type=Path, help="path to a .pcap or .pcapng file")
    analyze.add_argument("--report", type=Path, metavar="PATH",
                         help="write the Markdown report here (default: print to stdout)")
    analyze.add_argument("--min-severity", choices=["low", "medium", "high"], default="low",
                         help="leave out alerts below this severity (default: %(default)s)")
    _add_threshold_options(analyze)
    analyze.set_defaults(handler=run_analyze)


def _add_threshold_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("detection thresholds")
    group.add_argument("--scan-window", metavar="SECONDS", type=float, default=port_scan.Config.window_seconds,
                       help="port scan: window in seconds (default: %(default)s)")
    group.add_argument("--scan-ports", metavar="N", type=int, default=port_scan.Config.min_distinct_ports,
                       help="port scan: distinct ports on one host to alert (default: %(default)s)")
    group.add_argument("--scan-hosts", metavar="N", type=int, default=port_scan.Config.min_distinct_hosts,
                       help="port scan: distinct hosts to alert (default: %(default)s)")
    group.add_argument("--bf-attempts", metavar="N", type=int, default=brute_force.Config.min_attempts,
                       help="brute force: short connections in the window to alert (default: %(default)s)")
    group.add_argument("--bf-ports", metavar="PORTS", type=_port_list,
                       # A string default goes through _port_list like user input does.
                       default=",".join(map(str, sorted(brute_force.DEFAULT_PORTS))),
                       help="brute force: comma-separated ports to watch (default: %(default)s)")
    group.add_argument("--outbound-mb", metavar="MB", type=float,
                       default=outbound_volume.Config.min_bytes / 1_000_000,
                       help="outbound volume: megabytes to one external host to alert (default: %(default)s)")
    group.add_argument("--internal-net", action="append", metavar="CIDR",
                       help="outbound volume: internal network, repeatable "
                       "(default: private ranges)")
    group.add_argument("--dns-nxdomain", metavar="N", type=int, default=suspicious_dns.Config.min_nxdomain,
                       help="DNS: NXDOMAIN responses to one client in the window to alert (default: %(default)s)")


def _port_list(text: str) -> list[int]:
    try:
        ports = [int(part) for part in text.split(",") if part.strip()]
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a comma-separated list of ports: {text!r}")
    if not ports or any(not 0 < port < 65536 for port in ports):
        raise argparse.ArgumentTypeError(f"ports must be between 1 and 65535: {text!r}")
    return ports


def config_from_args(args: argparse.Namespace) -> AnalysisConfig:
    internal = tuple(args.internal_net) if args.internal_net else outbound_volume.DEFAULT_INTERNAL_NETWORKS
    return AnalysisConfig(
        port_scan=port_scan.Config(
            window_seconds=args.scan_window,
            min_distinct_ports=args.scan_ports,
            min_distinct_hosts=args.scan_hosts,
        ),
        brute_force=brute_force.Config(
            ports=frozenset(args.bf_ports), min_attempts=args.bf_attempts
        ),
        outbound_volume=outbound_volume.Config(
            min_bytes=int(args.outbound_mb * 1_000_000), internal_networks=internal
        ),
        suspicious_dns=suspicious_dns.Config(min_nxdomain=args.dns_nxdomain),
        min_severity=Severity[args.min_severity.upper()],
    )


def run_analyze(args: argparse.Namespace) -> int:
    try:
        config = config_from_args(args)
        result = analyze_capture(args.capture, config)
    except (OSError, CaptureReadError, ValueError) as error:
        # ValueError covers a malformed --internal-net CIDR.
        print(f"error: {error}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    report = render_markdown(result.alerts, _context(args.capture, result))
    _write_report(report, args.report)
    print(_summary_line(result, args.report), file=sys.stderr)
    return EXIT_OK


def _context(capture: Path, result: AnalysisResult) -> ReportContext:
    return ReportContext(
        capture_name=capture.name,
        packet_count=result.packet_count,
        flow_count=result.flow_count,
        generated_at=datetime.now(timezone.utc),
    )


def _write_report(report: str, destination: Path | None) -> None:
    if destination is None:
        sys.stdout.write(report)
    else:
        destination.write_text(report, encoding="utf-8")


def _summary_line(result: AnalysisResult, destination: Path | None) -> str:
    where = f"report written to {destination}" if destination else "report printed above"
    return (f"Analyzed {result.packet_count} packets in {result.flow_count} flows: "
            f"{len(result.alerts)} alert(s); {where}.")
