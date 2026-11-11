# Intrusion Detector

An offline network traffic analyzer for saved packet captures (pcap files). It
reads a capture, groups packets into flows, and will flag suspicious patterns such
as port scans and brute-force attempts in a readable report.

**Status:** early work in progress. It can read a pcap and group packets into
flows, and has four rule-based detections (port scan, brute force, outbound
volume, suspicious DNS), a Markdown report and a command-line interface.
Full documentation comes in a later step.

## Setup

Requires Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

## Usage

```bash
python -m analyzer analyze capture.pcap --report out.md
python -m analyzer analyze capture.pcap --min-severity medium   # print to stdout
python -m analyzer analyze --help                                # all threshold flags
```

## Project layout

```
src/analyzer/   the package
tests/          pytest tests (and tiny generated test pcaps)
data/           your own captures to analyze (not committed)
docs/           design notes
```

## Legal and ethical use

This tool only analyzes packet captures that are already saved to disk. It does
not sniff live traffic, scan networks, or send any packets.

Only analyze captures you are authorized to inspect: traffic from your own lab,
or public sample captures whose license allows it. Packet captures can contain
private data such as credentials, messages and browsing history. Capturing or
inspecting other people's traffic without permission may be illegal where you
live, so check before you do it.

## License

MIT, see [LICENSE](LICENSE).
