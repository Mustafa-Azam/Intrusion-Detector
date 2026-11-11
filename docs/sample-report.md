# Network Traffic Analysis Report

- **Capture:** demo.pcap
- **Generated:** 2026-11-11 08:54:09 UTC
- **Packets analyzed:** 1,645
- **Flows:** 45
- **Alerts:** 5 (HIGH 1, MEDIUM 3, LOW 1)

## Summary

| # | Severity | Type | Source | Destination | Start (UTC) |
|---|----------|------|--------|-------------|-------------|
| 1 | HIGH | brute\_force | 203.0.113.7 | 10.0.0.22 | 2026-01-01 00:00:20 |
| 2 | MEDIUM | port\_scan | 10.0.0.66 | 10.0.0.10 | 2026-01-01 00:00:10 |
| 3 | MEDIUM | outbound\_volume | 192.168.1.50 | 198.51.100.9 | 2026-01-01 00:01:10 |
| 4 | MEDIUM | dns\_nxdomain\_burst | 10.0.0.5 | multiple | 2026-01-01 00:01:30 |
| 5 | LOW | suspicious\_dns\_name | 10.0.0.5 | multiple | 2026-01-01 00:01:20 |

## Details

### 1. HIGH: brute\_force

203.0.113.7 made 12 short connections to 10.0.0.22:22 within 60s

- **Source:** 203.0.113.7
- **Destination:** 10.0.0.22
- **Time window (UTC):** 2026-01-01 00:00:20 to 2026-01-01 00:00:53 (33.0s)
- **Evidence:**
  - dst\_port: 22
  - connections: 12

### 2. MEDIUM: port\_scan

10.0.0.66 probed 30 distinct ports on host 10.0.0.10 within 60s

- **Source:** 10.0.0.66
- **Destination:** 10.0.0.10
- **Time window (UTC):** 2026-01-01 00:00:10 to 2026-01-01 00:00:10 (0.3s)
- **Evidence:**
  - scan\_shape: vertical
  - distinct\_ports: 30
  - ports: 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, ... (10 more)

### 3. MEDIUM: outbound\_volume

192.168.1.50 sent 2,160,000 bytes to external host 198.51.100.9

- **Source:** 192.168.1.50
- **Destination:** 198.51.100.9
- **Time window (UTC):** 2026-01-01 00:01:10 to 2026-01-01 00:01:11 (1.5s)
- **Evidence:**
  - bytes\_sent: 2,160,000
  - flows: 1

### 4. MEDIUM: dns\_nxdomain\_burst

10.0.0.5 received 12 NXDOMAIN responses within 60s

- **Source:** 10.0.0.5
- **Destination:** multiple
- **Time window (UTC):** 2026-01-01 00:01:30 to 2026-01-01 00:01:41 (11.0s)
- **Evidence:**
  - nxdomain\_responses: 12
  - distinct\_names: 12
  - examples: kq0zt.example.org, kq10zt.example.org, kq11zt.example.org, kq1zt.example.org, kq2zt.example.org

### 5. LOW: suspicious\_dns\_name

10.0.0.5 queried 3 long or random-looking domain names

- **Source:** 10.0.0.5
- **Destination:** multiple
- **Time window (UTC):** 2026-01-01 00:01:20 to 2026-01-01 00:01:22 (2.0s)
- **Evidence:**
  - distinct\_names: 3
  - examples: x7f3k9q2m8z1p4w6.t.example.net, q8w7e6r5t4y3u2i1o0p.t.example.net, zm4kq9w2x7c5v8b1n3.t.example.net
  - reasons: x7f3k9q2m8z1p4w6.t.example.net: high\_entropy; q8w7e6r5t4y3u2i1o0p.t.example.net: high\_entropy; zm4kq9w2x7c5v8b1n3.t.example.net: high\_entropy

---

_Alerts come from simple threshold rules. They are leads to investigate, not proof of an attack, and a quiet report does not mean the capture is clean._
