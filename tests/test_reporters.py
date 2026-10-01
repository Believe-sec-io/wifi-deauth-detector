"""Console, JSON and Markdown reporters."""

from __future__ import annotations

import json

import pytest

from deauth_detector import reporters
from deauth_detector.models import Alert, Report, Severity

from helpers import ATTACKER


def sample_report():
    report = Report(target="lab.pcap", frames_seen=42, teardown_frames=12)
    report.metadata.update(
        {"window_seconds": 10.0, "flood_threshold": 10, "distinct_victim_threshold": 5}
    )
    report.add(
        Alert(
            rule_id="DE-001",
            title="Deauthentication flood",
            severity=Severity.HIGH,
            message="12 deauthentication frames within 10s.",
            transmitter=ATTACKER,
            bssid="bb:bb:bb:bb:bb:bb",
            evidence="count=12 window=10s",
            remediation="Enable 802.11w/PMF.",
            reference="IEEE 802.11-2020",
        )
    )
    report.add(
        Alert(
            rule_id="DE-005",
            title="Nonassociated-station reason code",
            severity=Severity.MEDIUM,
            message="reason 7",
            transmitter=ATTACKER,
        )
    )
    return report


def test_console_report_shows_the_summary_and_every_alert():
    text = reporters.render(sample_report(), "console", use_color=False)
    assert "lab.pcap" in text
    assert "DE-001" in text and "DE-005" in text
    assert "count=12 window=10s" in text
    assert "Enable 802.11w/PMF." in text
    assert "Risk score" in text
    assert "\033[" not in text


def test_console_report_colours_the_severity_tags():
    text = reporters.render(sample_report(), "console", use_color=True)
    assert "\033[" in text
    assert "[HIGH]" in text and "[MED ]" in text


def test_console_report_says_so_when_the_capture_is_clean():
    text = reporters.render(Report(target="quiet.pcap"), "console", use_color=False)
    assert "No deauthentication attack detected." in text


def test_json_report_is_parseable_and_complete():
    payload = json.loads(reporters.render(sample_report(), "json"))
    assert payload["tool"] == "wifi-deauth-detector"
    assert payload["target"] == "lab.pcap"
    assert payload["total_alerts"] == 2
    assert payload["summary"]["high"] == 1
    assert payload["alerts"][0]["rule_id"] == "DE-001"
    assert payload["metadata"]["flood_threshold"] == 10


def test_markdown_report_has_a_table():
    text = reporters.render(sample_report(), "markdown")
    assert text.startswith("# Wi-Fi deauthentication detector")
    assert "| Rule | Severity | Transmitter | Detail |" in text
    assert f"| `DE-001` | high | `{ATTACKER}` |" in text
    assert "| **Total** | **2** |" in text


def test_markdown_report_for_a_clean_capture():
    text = reporters.render(Report(), "markdown")
    assert "No deauthentication attack detected." in text


def test_markdown_escapes_pipes_in_messages():
    report = Report()
    report.add(
        Alert(
            rule_id="DE-001",
            title="t",
            severity=Severity.LOW,
            message="a | b",
            transmitter=ATTACKER,
        )
    )
    text = reporters.render(report, "markdown")
    assert "a \\| b" in text


def test_text_and_md_aliases_resolve():
    assert reporters.render(Report(), "text") == reporters.render(Report(), "console")
    assert reporters.render(Report(), "md") == reporters.render(Report(), "markdown")


def test_unknown_format_raises():
    with pytest.raises(ValueError, match="unknown output format"):
        reporters.render(Report(), "yaml")


def test_write_output_creates_parent_directories(tmp_path):
    target = tmp_path / "nested" / "out" / "report.json"
    reporters.write_output('{"ok": true}', str(target))
    assert json.loads(target.read_text(encoding="utf-8")) == {"ok": True}


def test_write_output_normalises_the_trailing_newline(tmp_path):
    target = tmp_path / "r.txt"
    reporters.write_output("hello", str(target))
    assert target.read_text(encoding="utf-8") == "hello\n"


def test_dispatch_defaults_to_console():
    assert "\033[" in reporters.render(sample_report())  # colours on by default
