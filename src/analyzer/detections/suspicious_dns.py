"""Suspicious DNS: unusual query names and bursts of failed lookups.

Two rules:
  * suspicious names: very long names or random-looking (high-entropy)
    labels. DNS tunnelling packs data into subdomains, and malware using a
    domain generation algorithm (DGA) queries random-looking names.
  * NXDOMAIN bursts: many "no such domain" answers to one client in a short
    window, which is what a DGA looks like when most of its names don't exist.

Legitimate services (CDNs, anti-virus lookups, some cloud APIs) also use long
or random-looking names, so expect false positives on the first rule.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass

from analyzer.alerts import Alert, Severity
from analyzer.packets import DnsRecord
from analyzer.windows import busiest_window

NAME_ALERT_TYPE = "suspicious_dns_name"
NXDOMAIN_ALERT_TYPE = "dns_nxdomain_burst"
NXDOMAIN = 3
MAX_EXAMPLES = 5  # names to list in the evidence


@dataclass(frozen=True)
class Config:
    max_name_length: int = 60  # longer full names are suspicious
    min_entropy_label_length: int = 12  # shorter labels can't be judged fairly
    max_label_entropy: float = 3.8  # bits per character
    window_seconds: float = 60.0
    min_nxdomain: int = 10  # NXDOMAIN responses to one client per window
    name_severity: Severity = Severity.LOW
    nxdomain_severity: Severity = Severity.MEDIUM


def detect(records: list[DnsRecord], config: Config = Config()) -> list[Alert]:
    return _suspicious_names(records, config) + _nxdomain_bursts(records, config)


def shannon_entropy(text: str) -> float:
    """Average bits of information per character.

    "aaaa" scores 0; a string where every character is different scores
    log2(length). A random 16-character label scores about 4.0; English-like
    labels of that length usually score below 3.7. Short labels can't reach
    high scores at all, which is why there is a minimum label length.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def name_reasons(name: str, config: Config) -> list[str]:
    """Why a query name looks suspicious; an empty list means it doesn't."""
    reasons = []
    if len(name) > config.max_name_length:
        reasons.append("long")
    if any(_is_random_looking(label, config) for label in name.split(".")):
        reasons.append("high_entropy")
    return reasons


def _is_random_looking(label: str, config: Config) -> bool:
    return (
        len(label) >= config.min_entropy_label_length
        and shannon_entropy(label.lower()) > config.max_label_entropy
    )


def _suspicious_names(records: list[DnsRecord], config: Config) -> list[Alert]:
    # Group by client so a tunnel producing thousands of queries gives one
    # alert per client, not thousands.
    hits: dict[str, list[DnsRecord]] = defaultdict(list)
    seen: set[tuple[str, str]] = set()
    for record in records:
        key = (record.src_ip, record.query_name)
        if record.is_response or key in seen:
            continue
        seen.add(key)
        if name_reasons(record.query_name, config):
            hits[record.src_ip].append(record)
    return [_name_alert(client, found, config) for client, found in hits.items()]


def _name_alert(client: str, found: list[DnsRecord], config: Config) -> Alert:
    examples = [r.query_name for r in found[:MAX_EXAMPLES]]
    return Alert(
        type=NAME_ALERT_TYPE,
        severity=config.name_severity,
        src_ip=client,
        dst_ip=None,
        start=min(r.timestamp for r in found),
        end=max(r.timestamp for r in found),
        summary=f"{client} queried {len(found)} long or random-looking domain names",
        evidence={
            "distinct_names": len(found),
            "examples": examples,
            "reasons": {n: name_reasons(n, config) for n in examples},
        },
    )


def _nxdomain_bursts(records: list[DnsRecord], config: Config) -> list[Alert]:
    # A response goes from the resolver back to the client, so the client is
    # the response's destination.
    failures: dict[str, list[DnsRecord]] = defaultdict(list)
    for record in records:
        if record.is_response and record.rcode == NXDOMAIN:
            failures[record.dst_ip].append(record)

    alerts = []
    for client, group in failures.items():
        # Pair each response with its index so repeats still count separately.
        events = ((r.timestamp, (i, r.query_name)) for i, r in enumerate(group))
        window = busiest_window(events, config.window_seconds)
        if window.count >= config.min_nxdomain:
            alerts.append(_nxdomain_alert(client, window, config))
    return alerts


def _nxdomain_alert(client: str, window, config: Config) -> Alert:
    names = sorted({name for _index, name in window.values})
    return Alert(
        type=NXDOMAIN_ALERT_TYPE,
        severity=config.nxdomain_severity,
        src_ip=client,
        dst_ip=None,
        start=window.start,
        end=window.end,
        summary=f"{client} received {window.count} NXDOMAIN responses "
        f"within {config.window_seconds:g}s",
        evidence={
            "nxdomain_responses": window.count,
            "distinct_names": len(names),
            "examples": names[:MAX_EXAMPLES],
        },
    )
