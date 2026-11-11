"""Find the busiest time window in a list of timestamped events.

Several detections ask the same question: "within any N-second window, what is
the largest number of distinct things this source touched?" This module
answers it once with a sliding window, so each detection stays short.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Hashable, Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class Window:
    start: float
    end: float
    values: frozenset  # the distinct values seen inside the window

    @property
    def count(self) -> int:
        return len(self.values)


def busiest_window(
    events: Iterable[tuple[float, Hashable]], window_seconds: float
) -> Window | None:
    """Return the window with the most distinct values, or None if no events.

    Two pointers walk the time-sorted events: `right` adds each new event and
    `left` drops events older than `window_seconds`. A Counter tracks how many
    times each value is inside the window, so a value only leaves when its last
    copy does. This is O(n) after sorting.
    """
    ordered = sorted(events, key=lambda event: event[0])
    inside: Counter = Counter()
    best: Window | None = None
    left = 0
    for timestamp, value in ordered:
        inside[value] += 1
        while timestamp - ordered[left][0] > window_seconds:
            _remove(inside, ordered[left][1])
            left += 1
        if best is None or len(inside) > best.count:
            best = Window(ordered[left][0], timestamp, frozenset(inside))
    return best


def _remove(counter: Counter, value: Hashable) -> None:
    counter[value] -= 1
    if counter[value] == 0:
        del counter[value]
