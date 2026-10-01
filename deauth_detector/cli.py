"""Command line interface for the Wi-Fi deauthentication detector.

Exit codes
----------
``0``  no alert at or above ``--fail-on``
``1``  at least one alert at or above ``--fail-on``
``2``  the command line could not be understood
``3``  the capture could not be read (missing file, unsupported link type, ...)
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from . import __version__, reporters, rules
from .capture import frames_from_pcap, live_capture
from .detector import DeauthDetector, DetectorConfig
from .models import Report, Severity

EXIT_OK = 0
EXIT_ALERTS = 1
EXIT_USAGE = 2
EXIT_ERROR = 3

FORMATS = ("console", "json", "markdown")
FAIL_ON_CHOICES = ("none", "critical", "high", "medium", "low", "info")
SEVERITY_CHOICES = tuple(severity.value for severity in Severity)

EPILOG = """\
examples:
  python main.py capture.pcap
  python main.py capture.pcap --format json -o report.json
  python main.py capture.pcap --fail-on high --no-color
  python main.py first.pcap second.pcap --flood-threshold 5 --window 3
  python main.py --interface wlan0mon --count 500
  python main.py --list-rules

exit codes:
  0  no alert at or above --fail-on
  1  at least one alert at or above --fail-on
  2  the command line could not be understood
  3  the capture could not be read
"""


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="wifi-deauth-detector",
        description=(
            "Analyse 802.11 captures and report deauthentication / "
            "disassociation attacks (deauth floods, broadcast and multi-target "
            "deauth). Standard library only for pcap analysis."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("captures", nargs="*", metavar="PCAP",
                        help="capture file(s) to analyse (.pcap)")
    parser.add_argument("--interface", metavar="IFACE",
                        help="capture live on IFACE (needs scapy + monitor mode)")
    parser.add_argument("--count", type=int, default=0,
                        help="stop the live capture after COUNT frames (0 = never)")
    parser.add_argument("--timeout", type=float, default=None,
                        help="stop the live capture after TIMEOUT seconds")
    parser.add_argument("--channel", type=int, default=None,
                        help="hop to CHANNEL for a live capture")
    parser.add_argument("--window", type=float, default=10.0, metavar="SEC",
                        help="sliding window used to judge a burst (default: 10)")
    parser.add_argument("--flood-threshold", type=int, default=10, metavar="N",
                        help="teardown frames per window that mark a flood (default: 10)")
    parser.add_argument("--distinct-threshold", type=int, default=5, metavar="N",
                        help="distinct victims per window that mark a sweep (default: 5)")
    parser.add_argument("--format", "-f", choices=FORMATS, default="console",
                        help="report format (default: console)")
    parser.add_argument("--output", "-o", metavar="PATH",
                        help="write the report to PATH instead of stdout")
    parser.add_argument("--min-severity", choices=SEVERITY_CHOICES, default="info",
                        help="lowest severity to report (default: info)")
    parser.add_argument("--ignore", action="append", default=[], metavar="RULE[,RULE]",
                        help="rule id(s) to silence, repeatable")
    parser.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="high",
                        help="exit 1 when an alert reaches LEVEL (default: high)")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI colours in the console report")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="print nothing on stdout")
    parser.add_argument("--list-rules", action="store_true",
                        help="print the rule catalog and exit")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    return parser


def filter_report(report: Report, min_severity: str, ignored: Sequence[str]) -> Report:
    """Keep only the alerts at or above ``min_severity`` and not ignored."""
    threshold = Severity(min_severity).rank
    excluded = {item.strip().upper() for item in ignored if item.strip()}
    report.alerts = [
        alert for alert in report.alerts
        if alert.severity.rank <= threshold and alert.rule_id.upper() not in excluded
    ]
    return report


def render_catalog(fmt: str = "console") -> str:
    """Render the rule catalog (console table or JSON)."""
    catalog = rules.list_rules()
    if fmt == "json":
        return json.dumps(
            [
                {
                    "id": rule.id,
                    "title": rule.title,
                    "severity": rule.severity.value,
                    "description": rule.description,
                    "remediation": rule.remediation,
                    "reference": rule.reference,
                }
                for rule in catalog
            ],
            indent=2,
            ensure_ascii=False,
        ) + "\n"
    lines = [f"wifi-deauth-detector rule catalog ({len(catalog)} rules)", ""]
    for rule in catalog:
        lines.append(f"  {rule.id}  {rule.severity.value.upper():<8} {rule.title}")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Program entry point; returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        fmt = args.format if args.format in ("console", "json") else "console"
        print(render_catalog(fmt))
        return EXIT_OK

    if not args.captures and not args.interface:
        parser.print_help()
        return EXIT_USAGE

    config = DetectorConfig(
        window=args.window,
        flood_threshold=args.flood_threshold,
        distinct_victim_threshold=args.distinct_threshold,
    )
    detector = DeauthDetector(config)

    try:
        if args.interface:
            target = f"interface:{args.interface}"
            detector.add_many(
                live_capture(args.interface, count=args.count,
                             timeout=args.timeout, channel=args.channel)
            )
        else:
            target = ", ".join(args.captures)
            for path in args.captures:
                detector.add_many(frames_from_pcap(path))
    except (OSError, ValueError, ImportError) as error:
        print(f"capture error: {error}", file=sys.stderr)
        return EXIT_ERROR

    report = detector.report(target=target)
    ignored = [item for group in args.ignore for item in group.split(",")]
    report = filter_report(report, args.min_severity, ignored)

    content = reporters.render(report, fmt=args.format, use_color=not args.no_color)
    if args.output:
        try:
            reporters.write_output(content, args.output)
        except OSError as error:
            print(f"cannot write report: {error}", file=sys.stderr)
            return EXIT_ERROR
        if not args.quiet:
            print(f"Report written to {args.output}")
    elif not args.quiet:
        print(content)

    if args.fail_on != "none":
        threshold = Severity(args.fail_on).rank
        if any(alert.severity.rank <= threshold for alert in report.alerts):
            if not args.quiet:
                print(
                    f"--fail-on {args.fail_on} reached "
                    f"({len(report.alerts)} alert(s)).",
                    file=sys.stderr,
                )
            return EXIT_ALERTS
    return EXIT_OK


__all__ = ["EXIT_ALERTS", "EXIT_ERROR", "EXIT_OK", "EXIT_USAGE", "build_parser", "main"]


if __name__ == "__main__":  # allows ``python -m deauth_detector.cli``
    raise SystemExit(main())

