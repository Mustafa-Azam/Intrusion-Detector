"""Turn a list of alerts into a readable Markdown report.

The report has a summary table (one row per alert, most severe first) followed
by a details section with each alert's evidence. Rendering is a pure function
of its inputs, including the "generated at" time, so tests can compare the
output exactly.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone

from analyzer.alerts import Alert, Severity

MAX_LIST_ITEMS = 20  # longer evidence lists (e.g. 1000 scanned ports) are cut
MARKDOWN_SPECIAL = set("\\`*_[]<>|#")

DISCLAIMER = (
    "Alerts come from simple threshold rules. They are leads to investigate, "
    "not proof of an attack, and a quiet report does not mean the capture is clean."
)


@dataclass(frozen=True)
class ReportContext:
    """Facts about the analysis run that appear in the report header."""

    capture_name: str
    packet_count: int
    flow_count: int
    generated_at: datetime


def sort_alerts(alerts: list[Alert]) -> list[Alert]:
    """Most severe first; within a severity, earliest first."""
    return sorted(alerts, key=lambda a: (-a.severity, a.start, a.type, a.src_ip))


def render_markdown(alerts: list[Alert], context: ReportContext) -> str:
    ordered = sort_alerts(alerts)
    sections = [_header(ordered, context)]
    if ordered:
        sections.append(_summary_table(ordered))
        sections.append(_details(ordered))
    else:
        sections.append("No alerts: no rule crossed its threshold.")
    sections.append(f"---\n\n_{DISCLAIMER}_")
    return "\n\n".join(sections) + "\n"


def _header(alerts: list[Alert], context: ReportContext) -> str:
    return "\n".join([
        "# Network Traffic Analysis Report",
        "",
        f"- **Capture:** {escape(context.capture_name)}",
        f"- **Generated:** {format_time(context.generated_at.timestamp())} UTC",
        f"- **Packets analyzed:** {context.packet_count:,}",
        f"- **Flows:** {context.flow_count:,}",
        f"- **Alerts:** {len(alerts)}{_severity_breakdown(alerts)}",
    ])


def _severity_breakdown(alerts: list[Alert]) -> str:
    if not alerts:
        return ""
    counts = Counter(alert.severity for alert in alerts)
    parts = [f"{s.name} {counts[s]}" for s in sorted(Severity, reverse=True) if counts[s]]
    return " (" + ", ".join(parts) + ")"


def _summary_table(alerts: list[Alert]) -> str:
    rows = [
        "## Summary",
        "",
        "| # | Severity | Type | Source | Destination | Start (UTC) |",
        "|---|----------|------|--------|-------------|-------------|",
    ]
    for number, alert in enumerate(alerts, start=1):
        cells = [
            str(number),
            alert.severity.name,
            escape(alert.type),
            escape(alert.src_ip),
            escape(alert.dst_ip or "multiple"),
            format_time(alert.start),
        ]
        rows.append("| " + " | ".join(cells) + " |")
    return "\n".join(rows)


def _details(alerts: list[Alert]) -> str:
    blocks = ["## Details"]
    for number, alert in enumerate(alerts, start=1):
        blocks.append(_alert_block(number, alert))
    return "\n\n".join(blocks)


def _alert_block(number: int, alert: Alert) -> str:
    lines = [
        f"### {number}. {alert.severity.name}: {escape(alert.type)}",
        "",
        escape(alert.summary),
        "",
        f"- **Source:** {escape(alert.src_ip)}",
        f"- **Destination:** {escape(alert.dst_ip or 'multiple')}",
        f"- **Time window (UTC):** {format_time(alert.start)} to "
        f"{format_time(alert.end)} ({alert.end - alert.start:.1f}s)",
        "- **Evidence:**",
    ]
    lines += [f"  - {escape(key)}: {format_value(value)}" for key, value in alert.evidence.items()]
    return "\n".join(lines)


def format_time(timestamp: float) -> str:
    moment = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M:%S")


def format_value(value: object) -> str:
    """Render one evidence value; long lists are shortened."""
    if isinstance(value, dict):
        return "; ".join(f"{escape(str(k))}: {format_value(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple, set, frozenset)):
        return _format_list(list(value))
    if isinstance(value, int) and not isinstance(value, bool):
        return f"{value:,}"
    return escape(str(value))


def _format_list(items: list) -> str:
    shown = ", ".join(escape(str(item)) for item in items[:MAX_LIST_ITEMS])
    hidden = len(items) - MAX_LIST_ITEMS
    return f"{shown}, ... ({hidden} more)" if hidden > 0 else shown


def escape(text: str) -> str:
    """Make untrusted text safe to drop into Markdown.

    Values such as DNS query names come straight from the capture, so an
    attacker controls them. Without escaping, a name containing "|" would
    break the table and one containing "<" or "[" could inject HTML or links.
    """
    flat = " ".join(text.split())  # newlines would break the layout
    return "".join("\\" + ch if ch in MARKDOWN_SPECIAL else ch for ch in flat)
