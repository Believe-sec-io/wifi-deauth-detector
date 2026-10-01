# wifi-deauth-detector

[![CI](https://github.com/Believe-sec-io/wifi-deauth-detector/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Believe-sec-io/wifi-deauth-detector/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Defensive detector for 802.11 deauthentication and disassociation attacks — reads
`.pcap` captures with the standard library only, and can capture live through scapy.**

A deauthentication frame is a normal part of 802.11 (a client saying goodbye), but the
same frame is also the cheapest wireless attack there is: it is unauthenticated unless
802.11w/PMF is on, so anyone can forge it and kick every station off a cell, repeatedly,
to force a handshake capture or to deny service. This tool reads a monitor-mode capture,
groups teardown frames per transmitter inside a sliding window, and raises an alert when
the pattern matches a known attack — with the evidence, the remediation and a reference.

## Why this one

- **Zero dependency for offline analysis.** The pcap reader, radiotap walker and 802.11
  parser are written from the specification: `pip install` and run, anywhere.
- **Alerts, not log spam.** A rule fires *once per transmitter* while its condition holds
  and re-arms when it clears, so a sustained attack yields one alert with a count, not
  one alert per frame.
- **The knowledge is separate from the engine.** The rule catalog (id, severity,
  description, remediation, reference) lives in `rules.py`; the engine only decides
  *when* a rule fires. Mirrors the layout used by `docker-security-scanner`.
- **Actionable output.** Console (colour), JSON and Markdown reports, a 0-100 risk score
  with a grade, and exit codes built for CI.

## Installation

```bash
pip install wifi-deauth-detector                # offline pcap analysis, no dependency
pip install "wifi-deauth-detector[capture]"     # + scapy for live capture
```

From source:

```bash
git clone https://github.com/Believe-sec-io/wifi-deauth-detector.git
cd wifi-deauth-detector
pip install -e ".[dev]"
```

## Quickstart

A ready-made attack capture ships with the repository:

```bash
python main.py examples/attack.pcap
```

```
==========================================================================
 Wi-Fi deauthentication detector - capture analysis
==========================================================================
 Capture         : attack.pcap
 Date            : 2026-10-01 10:05 UTC
 Frames seen     : 42  (teardown: 36)
 Risk score      : 57/100 (grade F)
 Alerts          : 5  (critical 0 | high 3 | medium 2 | low 0 | info 0)
--------------------------------------------------------------------------
 [HIGH] DE-001 Deauthentication flood
    transmitter : aa:aa:aa:aa:aa:aa
    bssid       : bb:bb:bb:bb:bb:bb
    detail      : 10 deauthentication frames from one transmitter within 10s.
    evidence    : count=10 window=10s
    fix         : Locate the transmitter (source MAC and RSSI), enable 802.11w/PMF ...
```

Other common invocations:

```bash
python main.py capture.pcap --format json -o report.json   # machine readable
python main.py capture.pcap --format markdown              # for an issue/comment
python main.py capture.pcap --fail-on high --no-color      # CI gate, exit 1 on alert
python main.py a.pcap b.pcap --flood-threshold 5 --window 3
python main.py --list-rules                                # the rule catalog
python main.py --interface wlan0mon --count 500            # live (needs scapy)
```

The same works through the installed console script: `wifi-deauth-detector capture.pcap`.

## Detection rules

| Rule | Severity | What it catches | Fires when |
| --- | --- | --- | --- |
| `DE-001` | high | Deauthentication flood | ≥ 10 deauth frames from one transmitter inside the window |
| `DE-002` | high | Broadcast deauthentication | a deauth frame addressed to `ff:ff:ff:ff:ff:ff` |
| `DE-003` | high | Multi-target sweep | ≥ 5 distinct victim stations from one transmitter inside the window |
| `DE-004` | medium | Disassociation flood | ≥ 10 disassoc frames from one transmitter inside the window |
| `DE-005` | medium | Nonassociated-station reason | a teardown frame carries reason code 7 |

Reason code 7 (“Class 3 frame received from nonassociated station”) is a strong spoofing
signal: the sender is not part of the association it is tearing down. Thresholds are
tunable (`--window`, `--flood-threshold`, `--distinct-threshold`); run
`python main.py --list-rules` for descriptions, remediation and references.

## How detection works

1. Each packet is unwrapped: pcap record → radiotap header (RSSI, channel) → 802.11
   frame control, addresses and reason code.
2. Deauth/disassoc frames are appended to a **per-transmitter sliding window**; anything
   older than `--window` seconds is pruned on arrival.
3. The five rules are evaluated against that window. A rule that is already firing for
   that transmitter is skipped; when its condition clears, it **re-arms**.
4. Alerts are sorted by severity, scored (critical 40 / high 15 / medium 6 / low 2,
   capped at 100) and graded A-F.

Benign traffic (beacons, probes, data) is counted but never alerts: a legitimate client
deauthenticates once, not fourteen times in a second.

## Command line reference

| Option | Default | Meaning |
| --- | --- | --- |
| `PCAP...` | — | one or more capture files to analyse |
| `--interface IFACE` | — | live capture (needs scapy, monitor mode, privileges) |
| `--count N` / `--timeout S` / `--channel N` | `0` / — / — | live capture bounds and channel |
| `--window SEC` | `10` | sliding window used to judge a burst |
| `--flood-threshold N` | `10` | teardown frames per window that mark a flood |
| `--distinct-threshold N` | `5` | distinct victims per window that mark a sweep |
| `--format {console,json,markdown}` | `console` | report format |
| `--output PATH` | stdout | write the report to a file |
| `--min-severity {critical,high,medium,low,info}` | `info` | lowest severity to report |
| `--ignore RULE[,RULE]` | — | silence rule ids (repeatable) |
| `--fail-on {none,critical,high,medium,low,info}` | `high` | exit 1 when an alert reaches this level |
| `--no-color`, `--quiet`, `--list-rules`, `--version` | | conveniences |

Exit codes: `0` gate passed · `1` alert at or above `--fail-on` · `2` bad command line ·
`3` capture unreadable (missing file, unsupported link type, corrupt radiotap).

## Python API

```python
from deauth_detector import DeauthDetector, DetectorConfig, frames_from_pcap, reporters

detector = DeauthDetector(DetectorConfig(window=5.0, flood_threshold=6))
detector.add_many(frames_from_pcap("capture.pcap"))

report = detector.report("capture.pcap")
print(reporters.render(report, "json"))
for alert in report.alerts:
    print(alert.rule_id, alert.severity.value, alert.transmitter, alert.evidence)

assert report.worst_severity is None      # clean capture
assert report.risk_score() <= 100
```

Frames can also be fed one at a time (`detector.add(frame)`) — `add` returns only the
alerts raised by that frame, which is what a streaming sensor wants.

## Live capture

```bash
sudo ip link set wlan0mon type monitor
python main.py --interface wlan0mon --count 1000 --channel 6
```

Live capture needs the optional extra (`pip install "wifi-deauth-detector[capture]"`),
an interface in monitor mode and the corresponding privileges. Everything else — the
pcap path, the parser, the engine — is standard library only.

## Tests

```bash
python -m pytest                       # 120 tests
python -m pytest --cov=deauth_detector
python examples/demo_attack.py         # end-to-end smoke test
```

The suite synthesises every frame and capture in code (management frames, radiotap
headers, pcap files), so it needs no wireless hardware, no scapy and no binary fixture.

## Project layout

```
deauth_detector/
  constants.py   802.11 types, subtypes, reason codes, pcap link types
  models.py      Dot11Frame, Alert, Report, Severity
  frames.py      802.11 management + radiotap parsing (stdlib)
  pcap.py        classic pcap reader/writer (stdlib)
  rules.py       the rule catalog: knowledge, separate from the engine
  detector.py    sliding-window engine: counts -> alerts
  capture.py     pcap input + optional scapy live capture
  reporters.py   console / JSON / Markdown rendering
  cli.py         argument parsing, filtering, exit codes
examples/        demo script + a committed attack capture
tests/           120 tests, all synthetic
```

## License

MIT — see [LICENSE](LICENSE).

