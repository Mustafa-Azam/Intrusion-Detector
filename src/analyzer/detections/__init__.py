"""Rule-based detections.

Each module exposes a frozen `Config` dataclass with its thresholds and a
`detect(...)` function that returns a list of Alerts. The default thresholds
are starting points chosen by hand, not tuned on real traffic.
"""
