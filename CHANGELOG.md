# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-10-01

### Added

- `deauth_detector.frames`: 802.11 management-frame parser (frame control, the three
  addresses, reason code) and a radiotap header walker exposing RSSI and channel, with
  correct field alignment and graceful fallback for unknown present words.
- `deauth_detector.pcap`: classic libpcap reader and writer (little/big endian,
  microsecond and nanosecond resolutions, truncated captures stop cleanly).
- `deauth_detector.detector`: the sliding-window engine — per-transmitter state,
  pruning against the newest timestamp, and rules that fire once per transmitter then
  re-armed when their condition clears.
- `deauth_detector.rules`: catalog of five rules with severity, description,
  remediation and reference:
  - `DE-001` deauthentication flood (high)
  - `DE-002` broadcast deauthentication (high)
  - `DE-003` multi-target deauthentication (high)
  - `DE-004` disassociation flood (medium)
  - `DE-005` nonassociated-station reason code 7 (medium)
- `deauth_detector.capture`: pcap input for radiotap and raw 802.11 link types, plus an
  optional scapy-backed live capture (`pip install "wifi-deauth-detector[capture]"`).
- `deauth_detector.reporters`: console (colour), JSON and Markdown reports with a
  0-100 risk score and an A-F grade.
- `deauth_detector.cli`: `--window`, `--flood-threshold`, `--distinct-threshold`,
  `--format`, `--output`, `--min-severity`, `--ignore`, `--fail-on`, `--list-rules`,
  multiple capture files and a live `--interface` mode; exit codes 0/1/2/3 built for CI.
- `wifi-deauth-detector` console script and the `deauth_detector` package exports.
- 120 tests (all frames, captures and reports synthesised in code) and a CI workflow
  covering Python 3.9-3.14 on Linux and Windows plus an end-to-end demo job.
