"""Reporters: console (colour), JSON and Markdown, all pure functions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from .models import Alert, Report, Severity

RESET = "\033[0m"
COLORS: Dict[Severity, str] = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[1;36m",
    Severity.INFO: "\033[1;34m",
}
TAGS = {
    "critical": "[CRIT]",
    "high": "[HIGH]",
    "medium": "[MED ]",
    "low": "[LOW ]",
    "info": "[INFO]",
}
TITLE = "Wi-Fi deauthentication detector"


def render(report: Report, fmt: str = "console", use_color: bool = True) -> str:
    """Render ``report`` in the requested format."""
    normalized = (fmt or "console").lower()
    if normalized in ("console", "text", "txt"):
        return render_console(report, use_color=use_color)
    if normalized == "json":
        return render_json(report)
    if normalized in ("md", "markdown"):
        return render_markdown(report)
    raise ValueError(f"unknown output format: {fmt}")


def render_json(report: Report) -> str:
    """The report as indented JSON."""
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"


def _paint(text: str, severity: Severity, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{COLORS.get(severity, '')}{text}{RESET}"


def render_console(report: Report, use_color: bool = True) -> str:
    """A human-readable terminal report."""
    counts = report.counts()
    rule = "=" * 74
    lines: List[str] = [
        rule,
        f" {TITLE} - capture analysis",
        rule,
        f" Capture         : {report.target or '<stdin>'}",
        f" Date            : {report.generated_at}",
        f" Frames seen     : {report.frames_seen}  (teardown: {report.teardown_frames})",
        f" Risk score      : {report.risk_score()}/100 (grade {report.grade()})",
        " Alerts          : "
        + f"{len(report.alerts)}  ("
        + " | ".join(f"{name} {counts[name]}" for name in ("critical", "high", "medium", "low", "info"))
        + ")",
        "-" * 74,
    ]

    if not report.alerts:
        lines.append(" No deauthentication attack detected.")
    for alert in report.alerts:
        tag = _paint(TAGS[alert.severity.value], alert.severity, use_color)
        lines.append(f" {tag} {alert.rule_id} {alert.title}")
        lines.append(f"    transmitter : {alert.transmitter}")
        if alert.bssid:
            lines.append(f"    bssid       : {alert.bssid}")
        if alert.receiver:
            lines.append(f"    receiver    : {alert.receiver}")
        lines.append(f"    detail      : {alert.message}")
        if alert.evidence:
            lines.append(f"    evidence    : {alert.evidence}")
        if alert.remediation:
            lines.append(f"    fix         : {alert.remediation}")
        if alert.reference:
            lines.append(f"    reference   : {alert.reference}")
        lines.append("")
    lines.append(rule)
    return "\n".join(lines)


def render_markdown(report: Report) -> str:
    """A Markdown report, ready for an issue or a pull-request comment."""
    counts = report.counts()
    lines: List[str] = [
        f"# {TITLE}",
        "",
        f"- **Capture**: `{report.target or '<stdin>'}`",
        f"- **Date**: {report.generated_at}",
        f"- **Frames seen**: {report.frames_seen} (teardown: {report.teardown_frames})",
        f"- **Risk score**: {report.risk_score()}/100 (grade **{report.grade()}**)",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for name in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {name} | {counts[name]} |")
    lines.append(f"| **Total** | **{len(report.alerts)}** |")
    lines.append("")

    if not report.alerts:
        lines.append("No deauthentication attack detected.")
        return "\n".join(lines) + "\n"

    lines += [
        "## Alerts",
        "",
        "| Rule | Severity | Transmitter | Detail |",
        "| --- | --- | --- | --- |",
    ]
    for alert in report.alerts:
        detail = str(alert.message).replace("|", "\\|")
        lines.append(
            f"| `{alert.rule_id}` | {alert.severity.value} | "
            f"`{alert.transmitter}` | {detail} |"
        )
    lines.append("")
    return "\n".join(lines) + "\n"


def write_output(content: str, path: str) -> None:
    """Write a rendered report to disk (UTF-8, parents created)."""
    target = Path(path)
    if str(target.parent) not in ("", "."):
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content if content.endswith("\n") else content + "\n",
                      encoding="utf-8")


__all__ = ["render", "render_console", "render_json", "render_markdown", "write_output"]
