# Intrusion Detector

[![tests](https://github.com/Mustafa-Azam/Intrusion-Detector/actions/workflows/tests.yml/badge.svg)](https://github.com/Mustafa-Azam/Intrusion-Detector/actions/workflows/tests.yml)

An offline network traffic analyzer for saved packet captures (pcap/pcapng).
It reads a capture, groups packets into flows, runs four rule-based detections
and writes a Markdown report with the alerts sorted by severity.

It is a learning and portfolio project. It is not a replacement for a real IDS
such as Suricata or Zeek, and it has only been tested on small synthetic
captures (see [Limitations](#limitations)).

## What it detects

| Detection | Fires when (default thresholds) | Severity |
|---|---|---|
| **Port scan** | One source sends small "probe" flows (3 packets or fewer) to 20+ distinct ports on one host, or to 20+ distinct hosts, within 60 s | Medium |
| **Brute force** | 10+ short TCP connections (10 s or less each) within 60 s from one source to one host on a login port: FTP 21, SSH 22, Telnet 23, SMB 445, RDP 3389, VNC 5900 | High |
| **Outbound volume** | An internal host (private address range) sends 50 MB or more to a single external host over the whole capture | Medium |
| **Suspicious DNS names** | A client queries names longer than 60 characters, or with a random-looking label (12+ characters, Shannon entropy above 3.8 bits per character) | Low |
| **NXDOMAIN burst** | A client receives 10+ "no such domain" answers within 60 s | Medium |

The defaults are hand-picked starting points, **not tuned on real traffic**.
Most can be changed with command-line flags (`--help` lists them).

## Quick start

Requires Python 3.11 or newer.

```bash
git clone https://github.com/Mustafa-Azam/Intrusion-Detector.git
cd Intrusion-Detector
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest                           # run the tests
```

GitHub Actions runs the tests on Python 3.11, 3.12 and 3.13 on every push and
pull request (`.github/workflows/tests.yml`).

Try it on the synthetic demo capture:

```bash
python scripts/make_demo_pcap.py data/demo.pcap
python -m analyzer analyze data/demo.pcap --outbound-mb 1 --report report.md
```

The demo script only builds packets in memory and writes them to a file; it
sends nothing on the network. `--outbound-mb 1` is needed because the demo
upload is about 2 MB, well under the 50 MB default.

## Usage

```bash
python -m analyzer analyze capture.pcap --report out.md     # write a report file
python -m analyzer analyze capture.pcap                      # print the report
python -m analyzer analyze capture.pcap --min-severity medium
python -m analyzer analyze capture.pcap --scan-ports 50 --bf-ports 22,2222 \
    --internal-net 10.10.0.0/16
python -m analyzer analyze --help                            # every flag and default
```

Exit codes: `0` the analysis ran (with or without alerts), `1` the capture is
missing or unreadable (or a bad `--internal-net`), `2` invalid flags.

## Sample report

From the demo capture above (full file: [docs/sample-report.md](docs/sample-report.md)):

| # | Severity | Type | Source | Destination | Start (UTC) |
|---|----------|------|--------|-------------|-------------|
| 1 | HIGH | brute\_force | 203.0.113.7 | 10.0.0.22 | 2026-01-01 00:00:20 |
| 2 | MEDIUM | port\_scan | 10.0.0.66 | 10.0.0.10 | 2026-01-01 00:00:10 |
| 3 | MEDIUM | outbound\_volume | 192.168.1.50 | 198.51.100.9 | 2026-01-01 00:01:10 |
| 4 | MEDIUM | dns\_nxdomain\_burst | 10.0.0.5 | multiple | 2026-01-01 00:01:30 |
| 5 | LOW | suspicious\_dns\_name | 10.0.0.5 | multiple | 2026-01-01 00:01:20 |

Each alert then gets a details section, for example:

> **1. HIGH: brute\_force.** 203.0.113.7 made 12 short connections to
> 10.0.0.22:22 within 60s. Time window 00:00:20 to 00:00:53 (33.0s).
> Evidence: dst\_port 22, connections 12.

The demo was built to trigger every rule, so this shows the format, not
detection quality. A test (`tests/test_demo_capture.py`) checks that the demo
still produces exactly these alert types.

## How it works

```
pcap ──> packets.py ──> flows.py ──> detections/* ──> report.py ──> Markdown
         (Scapy)        (5-tuple      (rules over      (sort by
                         flows)        flows / DNS)     severity)
```

1. **Parse:** `packets.py` streams the capture with Scapy and keeps only a few
   fields per IP packet (time, addresses, protocol, ports, size) plus DNS
   question names and response codes. It is the only module that uses Scapy.
2. **Build flows:** `flows.py` groups packets in both directions into one flow
   per 5-tuple (IPs, ports, protocol) with packet and byte counts per direction.
3. **Detect:** each module in `detections/` applies one rule with its own
   thresholds and returns `Alert`s.
4. **Report:** `report.py` sorts alerts by severity and renders Markdown,
   escaping any text that came from the capture.

More detail on the design decisions is in [docs/design.md](docs/design.md).

## Limitations

- **False positives.** The rules are thresholds with no knowledge of what is
  normal on your network. Backups and cloud sync trigger *outbound volume*;
  CDNs and anti-virus lookups use random-looking DNS names; a monitoring
  system or vulnerability scanner you run yourself looks like a port scan.
- **False negatives.** Slow scans spread wider than the time window, low-rate
  brute force, and exfiltration under the byte threshold are not detected.
  An empty report does not mean the capture is clean.
- **Encrypted traffic.** The analyzer only sees headers, sizes and timing. It
  cannot tell whether an SSH or RDP login failed, and it does not look inside
  TLS. DNS over HTTPS/TLS is invisible to the DNS rules.
- **Offline only.** It reads saved captures. It does not sniff live traffic,
  block anything, or send alerts anywhere.
- **Flow simplifications.** There is no idle timeout, so a reused 5-tuple
  merges into one flow; the "originator" is whoever sent the first packet in
  the capture; IPv6 extension headers are not followed.
- **Scale.** Each capture is read twice and all flows are kept in memory.
  Fine for lab captures, not tested on multi-gigabyte files.
- **Testing.** All tests use small synthetic packets and captures generated in
  the tests. It has **not** been evaluated on real-world or public
  labelled captures yet, so there are no accuracy numbers.

## Legal and ethical use

This tool only analyzes packet captures that are already saved to disk. It does
not sniff live traffic, scan networks, or send any packets, and the demo script
only writes a file.

Only analyze captures you are authorized to inspect: traffic from your own lab,
or public sample captures whose license allows it. Packet captures can contain
private data such as credentials, messages and browsing history. Capturing or
inspecting other people's traffic without permission may be illegal where you
live, so check before you do it.

## What I'd improve next

- Evaluate the rules on public labelled captures and report precision and
  recall honestly, then tune the defaults.
- Compare the alerts with Suricata or Zeek output on the same captures.
- Add a flow idle timeout and use TCP flags (SYN, RST) to tell failed
  connection attempts from completed ones.
- Per-host baselines for outbound volume instead of one fixed threshold.
- Allow-lists for known scanners, backup servers and CDN domains.
- JSON output alongside Markdown so alerts can feed other tools.
- Single pass over the capture instead of two.

## Project layout

```
src/analyzer/
  packets.py        pcap -> PacketRecord / DnsRecord (the only Scapy user)
  flows.py          PacketRecords -> bidirectional Flows
  windows.py        sliding "busiest window" helper used by several rules
  alerts.py         Alert and Severity
  detections/       port_scan, brute_force, outbound_volume, suspicious_dns
  analysis.py       runs the whole pipeline on one capture
  report.py         Markdown report
  cli.py            command-line interface (python -m analyzer)
scripts/            make_demo_pcap.py: synthetic demo capture
tests/              pytest tests; captures are generated at test time
data/               your own captures (not committed)
docs/               design.md and the sample report
```

## License

MIT, see [LICENSE](LICENSE).
