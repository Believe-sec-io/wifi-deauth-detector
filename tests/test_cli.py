"""The command line interface."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from deauth_detector.cli import EXIT_ALERTS, EXIT_ERROR, EXIT_OK, EXIT_USAGE, main

from helpers import attack_capture, quiet_capture, write_capture


@pytest.fixture
def attack(tmp_path):
    return write_capture(tmp_path / "attack.pcap", attack_capture())


@pytest.fixture
def quiet(tmp_path):
    return write_capture(tmp_path / "quiet.pcap", quiet_capture())


def test_list_rules_prints_the_catalog(capsys):
    assert main(["--list-rules"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "5 rules" in out
    for rule_id in ("DE-001", "DE-002", "DE-003", "DE-004", "DE-005"):
        assert rule_id in out


def test_list_rules_json(capsys):
    assert main(["--list-rules", "--format", "json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert [rule["id"] for rule in payload] == [
        "DE-001",
        "DE-002",
        "DE-003",
        "DE-004",
        "DE-005",
    ]
    assert all(rule["remediation"] for rule in payload)


def test_no_arguments_prints_help_and_fails(capsys):
    assert main([]) == EXIT_USAGE
    assert "usage:" in capsys.readouterr().out


def test_attack_capture_is_reported_and_fails_the_default_gate(attack, capsys):
    assert main([str(attack), "--no-color"]) == EXIT_ALERTS
    out = capsys.readouterr().out
    assert "DE-001" in out
    assert "DE-003" in out


def test_quiet_capture_passes(quiet, capsys):
    assert main([str(quiet), "--no-color"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "No deauthentication attack detected." in out


def test_fail_on_none_never_fails(attack, capsys):
    assert main([str(attack), "--fail-on", "none", "-q"]) == EXIT_OK


def test_fail_on_critical_ignores_high_alerts(attack, capsys):
    assert main([str(attack), "--fail-on", "critical", "-q"]) == EXIT_OK


def test_fail_on_medium_catches_the_medium_alerts(attack):
    assert main([str(attack), "--fail-on", "medium", "-q"]) == EXIT_ALERTS


def test_json_output_file(attack, tmp_path, capsys):
    target = tmp_path / "out" / "report.json"
    assert main([str(attack), "-f", "json", "-o", str(target), "-q"]) == EXIT_ALERTS
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["target"] == str(attack)
    assert payload["total_alerts"] >= 1
    assert payload["alerts"][0]["rule_id"] in {"DE-001", "DE-002", "DE-003", "DE-005"}


def test_markdown_output_to_stdout(attack, capsys):
    assert main([str(attack), "-f", "markdown", "-q"]) == EXIT_ALERTS
    out = capsys.readouterr().out
    assert out == ""  # quiet suppresses stdout


def test_ignore_hides_a_rule(attack, capsys):
    code = main([str(attack), "--ignore", "DE-001,DE-002", "--no-color", "--fail-on", "none"])
    assert code == EXIT_OK
    out = capsys.readouterr().out
    assert "DE-001" not in out
    assert "DE-003" in out


def test_min_severity_filters_medium_alerts(attack, capsys):
    assert main([str(attack), "--min-severity", "high", "--fail-on", "none", "--no-color"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "DE-005" not in out  # medium
    assert "DE-001" in out  # high


def test_thresholds_can_be_tuned(attack, capsys):
    # 10 deauth frames exist: raising the threshold silences DE-001
    assert (
        main([str(attack), "--flood-threshold", "50", "--fail-on", "none", "--no-color"])
        == EXIT_OK
    )
    out = capsys.readouterr().out
    assert "DE-001" not in out


def test_two_captures_are_merged(attack, quiet, capsys):
    assert main([str(attack), str(quiet), "--fail-on", "high", "--no-color"]) == EXIT_ALERTS
    assert str(quiet) in capsys.readouterr().out


def test_missing_file_reports_an_error(tmp_path, capsys):
    assert main([str(tmp_path / "nope.pcap"), "-q"]) == EXIT_ERROR
    assert "capture error" in capsys.readouterr().err


def test_unsupported_link_type_reports_an_error(tmp_path, capsys):
    path = write_capture(
        tmp_path / "eth.pcap", [(1_700_000_000.0, b"\x00" * 60)], linktype=1
    )
    assert main([str(path), "-q"]) == EXIT_ERROR
    assert "unsupported pcap link type" in capsys.readouterr().err


def test_version_flag_exits_zero_via_module_entry_point():
    result = subprocess.run(
        [sys.executable, "main.py", "--version"],
        capture_output=True,
        text=True,
        cwd=str(__import__("pathlib").Path(__file__).resolve().parent.parent),
    )
    assert result.returncode == 0
    assert "wifi-deauth-detector" in result.stdout
