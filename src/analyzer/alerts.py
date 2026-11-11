"""The Alert type that every detection returns.

Keeping one shared shape means the report (step 4) can render any detection
without knowing its details: the detection-specific numbers live in
`evidence`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered so that alerts can be sorted with HIGH first."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass(frozen=True)
class Alert:
    type: str  # e.g. "port_scan"
    severity: Severity
    src_ip: str
    dst_ip: str | None  # None when the activity spans many destinations
    start: float  # time window of the activity, Unix seconds
    end: float
    summary: str  # one human-readable sentence
    evidence: dict[str, object] = field(default_factory=dict)
