from datetime import datetime, timezone

from analyzer.alerts import Alert, Severity
from analyzer.report import (
    ReportContext,
    escape,
    format_value,
    render_markdown,
    sort_alerts,
)

CONTEXT = ReportContext(
    capture_name="lab.pcap",
    packet_count=1234,
    flow_count=56,
    generated_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
)


def make_alert(type_="port_scan", severity=Severity.MEDIUM, start=0.0, src="10.0.0.1",
               dst="10.0.0.2", evidence=None):
    return Alert(type_, severity, src, dst, start, start + 5, f"{type_} summary",
                 evidence or {"count": 3})


def test_sort_puts_high_severity_first_then_earliest():
    low = make_alert(severity=Severity.LOW, start=1)
    high_late = make_alert(severity=Severity.HIGH, start=50)
    high_early = make_alert(severity=Severity.HIGH, start=10)
    medium = make_alert(severity=Severity.MEDIUM, start=0)

    assert sort_alerts([low, high_late, medium, high_early]) == [high_early, high_late, medium, low]


def test_report_header_and_table_order():
    alerts = [
        make_alert("suspicious_dns_name", Severity.LOW, start=0),
        make_alert("brute_force", Severity.HIGH, start=100),
    ]

    report = render_markdown(alerts, CONTEXT)

    assert report.startswith("# Network Traffic Analysis Report")
    assert "- **Capture:** lab.pcap" in report
    assert "- **Generated:** 2026-01-02 03:04:05 UTC" in report
    assert "- **Packets analyzed:** 1,234" in report
    assert "- **Alerts:** 2 (HIGH 1, LOW 1)" in report
    assert report.index("| 1 | HIGH | brute\\_force") < report.index("| 2 | LOW |")


def test_report_details_show_window_and_evidence():
    alert = make_alert("brute_force", Severity.HIGH, start=0,
                       evidence={"dst_port": 22, "connections": 1500})

    report = render_markdown([alert], CONTEXT)

    assert "### 1. HIGH: brute\\_force" in report
    assert "1970-01-01 00:00:00 to 1970-01-01 00:00:05 (5.0s)" in report
    assert "  - dst\\_port: 22" in report
    assert "  - connections: 1,500" in report


def test_alert_without_single_destination_shows_multiple():
    report = render_markdown([make_alert(dst=None)], CONTEXT)

    assert "- **Destination:** multiple" in report


def test_empty_report_says_so_without_claiming_capture_is_clean():
    report = render_markdown([], CONTEXT)

    assert "- **Alerts:** 0" in report
    assert "No alerts" in report
    assert "## Summary" not in report
    assert "does not mean the capture is clean" in report


def test_long_lists_are_shortened():
    text = format_value(list(range(1, 26)))

    assert text.endswith("20, ... (5 more)")


def test_escape_neutralises_markdown_in_untrusted_text():
    hostile = "evil|name<script>`x`[link](http://a)\nnext"

    escaped = escape(hostile)

    assert "\n" not in escaped
    for raw in ("|", "<", "`", "["):
        assert raw not in escaped.replace("\\" + raw, "")


def test_hostile_dns_name_cannot_break_the_table():
    alert = make_alert("suspicious_dns_name", src="10.0.0.5",
                       evidence={"examples": ["a|b|c.example.com"]})

    report = render_markdown([alert], CONTEXT)

    assert "a\\|b\\|c.example.com" in report
