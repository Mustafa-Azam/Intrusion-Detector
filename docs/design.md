# Design notes

A short record of how the analyzer is put together and why. The goal was a
small codebase where every part can be read and tested on its own.

## Pipeline

```
read_packets(path) ─> build_flows(records) ─┐
                                            ├─> detect(...) x4 ─> sort ─> render_markdown
read_dns(path) ─────────────────────────────┘
```

`analysis.analyze_capture()` wires these together. `cli.py` only turns
command-line flags into an `AnalysisConfig` and writes the result, so the
whole pipeline can be used and tested from Python without the CLI.

## Data model

| Type | Module | Holds |
|---|---|---|
| `PacketRecord` | `packets.py` | timestamp, src/dst IP, protocol name, ports (None for ICMP), IP size |
| `DnsRecord` | `packets.py` | timestamp, src/dst IP, query name, response flag, rcode |
| `FlowKey` / `Flow` | `flows.py` | 5-tuple; start, end; orig/resp packet and byte counts |
| `Alert` / `Severity` | `alerts.py` | type, severity, src, dst (None = many), time window, summary, evidence dict |

All are dataclasses. Records and keys are frozen (immutable). `Severity` is an
`IntEnum`, so "most severe first" is a plain sort.

## Key decisions

**Scapy is isolated in `packets.py`.** Everything downstream works on plain
dataclasses. Flow and detection tests build records directly in one line
instead of crafting packets, and swapping Scapy for PyShark or dpkt later would
touch one file. Scapy was picked over PyShark because it is pure Python, can
*write* pcaps (so tests generate their own captures), and needs no
Wireshark/tshark install in CI.

**Packet size comes from the IP header length field**, not the number of bytes
captured, so captures truncated by a snaplen still report true sizes.

**Ports are read from the layer directly after IP.** Searching the whole
packet for a UDP layer would wrongly match the copy of the original header
that ICMP error messages carry.

**Flows are bidirectional, with Zeek-style `orig`/`resp` naming.** Direction
matters for the outbound-volume rule. The originator is whoever sent the first
packet seen; there is no idle timeout (see limitations in the README).

**One sliding-window helper (`windows.busiest_window`).** Port scan, brute
force and NXDOMAIN bursts all ask "what is the largest number of distinct
things in any N-second window?". Two pointers walk the time-sorted events and
a `Counter` tracks what is inside the window, which is O(n) after sorting.
Brute force counts connections by passing each flow's unique key as the value.

**Each detection is a module with a frozen `Config` and a `detect()`
function.** Thresholds are data, not constants buried in code, so tests and
CLI flags can override them. CLI defaults are read from the `Config` classes
so the help text can't drift from the real values.

**One alert per source (or source/target pair), not per packet.** Each alert
reports the busiest window as evidence. A full 65,535-port scan of one host
is one alert, not 65,535.

**Port-scan "probes" are flows of 3 packets or fewer.** Without this filter a
browser opening HTTPS connections to many sites looked like a horizontal scan.

**Entropy threshold 3.8 bits per character, minimum label length 12.** At 3.5
ordinary compound labels such as `mailserverbackup` (3.62) were flagged.
Short labels can't score high regardless (the maximum is log2 of the length),
so they are skipped rather than judged.

**The report escapes everything that came from the capture.** DNS names are
attacker-controlled. Unescaped, a name containing `|`, `<` or `[` could break
the table or inject HTML or links into a rendered report.

**The report takes its "generated at" time as input** instead of reading the
clock, so tests can compare exact output.

## Testing approach

- Unit tests per module, with at least one positive and one negative case per
  detection plus a threshold-override test.
- Captures are generated with Scapy inside the tests (`tests/conftest.py`), so
  no binary files are committed and each test shows exactly what traffic it
  uses.
- End-to-end tests run the CLI on generated pcap and pcapng files, including
  error cases (missing file, non-capture file, bad flags).
- `tests/test_demo_capture.py` checks that the demo capture still produces the
  alerts shown in the README's sample report.

- GitHub Actions runs all of this on Python 3.11, 3.12 and 3.13 for every push
  and pull request, then runs the CLI on the demo capture as a smoke test.

What is not tested: real-world captures, very large files, captures truncated
mid-file, and IPv6 extension headers.
