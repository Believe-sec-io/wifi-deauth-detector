"""The public data types: frames, alerts, severities and the report."""

from __future__ import annotations

from deauth_detector.constants import BROADCAST_ADDRESS, SUBTYPE_DEAUTHENTICATION
from deauth_detector.models import SEVERITY_WEIGHTS, Alert, Dot11Frame, Report, Severity

from helpers import AP, ATTACKER, BASE_TIME, VICTIMS, make_frame


def alert(severity, rule_id="DE-001"):
    """An alert with an explicit severity (bypasses the catalog on purpose)."""
    return Alert(
        rule_id=rule_id,
        title="title",
        severity=severity,
        message="m",
        transmitter=ATTACKER,
    )


def test_severity_ranks_are_ordered_from_most_to_least_urgent():
    ranks = [severity.rank for severity in Severity]
    assert ranks == sorted(ranks)
    assert Severity.CRITICAL.rank == 0
    assert Severity.INFO.rank == 4


def test_severity_values_match_their_names():
    assert [severity.value for severity in Severity] == [
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ]


def test_severity_weights_decrease_with_urgency():
    assert SEVERITY_WEIGHTS[Severity.CRITICAL] > SEVERITY_WEIGHTS[Severity.HIGH]
    assert SEVERITY_WEIGHTS[Severity.INFO] == 0


def test_frame_properties():
    frame = make_frame(subtype=SUBTYPE_DEAUTHENTICATION, receiver=BROADCAST_ADDRESS)
    assert frame.is_deauth and frame.is_teardown and not frame.is_disassoc
    assert frame.is_broadcast
    assert frame.to_dict()["bssid"] == AP
    assert frame.to_dict()["reason_code"] == 1


def test_frame_to_dict_is_json_friendly():
    import json

    payload = make_frame().to_dict()
    assert json.loads(json.dumps(payload))["transmitter"] == ATTACKER


def test_report_counts_every_severity():
    report = Report()
    report.extend(
        [alert(Severity.HIGH), alert(Severity.HIGH), alert(Severity.MEDIUM)]
    )
    assert report.counts() == {
        "critical": 0,
        "high": 2,
        "medium": 1,
        "low": 0,
        "info": 0,
    }
    assert len(report.alerts) == 3


def test_report_risk_score_sums_weights_and_clamps_at_100():
    report = Report()
    report.extend([alert(Severity.HIGH), alert(Severity.MEDIUM)])
    assert report.risk_score() == 15 + 6
    report.extend([alert(Severity.HIGH)] * 10)
    assert report.risk_score() == 100  # clamped


def test_report_grade_boundaries():
    assert Report().grade() == "A"
    assert _graded(Severity.INFO) == "A"  # 0 point
    assert _graded(Severity.LOW) == "B"  # 2 points
    assert _graded(Severity.HIGH) == "C"  # 15 points
    assert _graded(Severity.CRITICAL) == "D"  # 40 points
    assert _graded(Severity.CRITICAL, Severity.HIGH) == "F"  # 55 points


def _graded(*severities):
    report = Report()
    report.extend([alert(severity) for severity in severities])
    return report.grade()


def test_report_worst_severity():
    report = Report()
    assert report.worst_severity is None
    report.extend([alert(Severity.MEDIUM), alert(Severity.HIGH)])
    assert report.worst_severity is Severity.HIGH


def test_report_sort_alerts_orders_by_severity_then_rule_id():
    report = Report()
    report.extend(
        [
            alert(Severity.MEDIUM, "DE-005"),
            alert(Severity.HIGH, "DE-003"),
            alert(Severity.HIGH, "DE-001"),
        ]
    )
    report.sort_alerts()
    assert [item.rule_id for item in report.alerts] == ["DE-001", "DE-003", "DE-005"]


def test_report_to_dict_shape():
    report = Report(target="lab.pcap", frames_seen=7, teardown_frames=3)
    report.add(alert(Severity.HIGH))
    payload = report.to_dict()
    assert payload["target"] == "lab.pcap"
    assert payload["frames_seen"] == 7
    assert payload["teardown_frames"] == 3
    assert payload["total_alerts"] == 1
    assert payload["summary"]["high"] == 1
    assert payload["worst_severity"] == "high"
    assert payload["alerts"][0]["transmitter"] == ATTACKER
    assert isinstance(payload["generated_at"], str)


def test_alert_defaults_are_json_ready():
    payload = Alert(
        rule_id="DE-001", title="t", severity=Severity.HIGH, message="m", transmitter="aa:aa"
    ).to_dict()
    assert payload["receiver"] == ""
    assert payload["count"] == 0
    assert payload["severity"] == "high"


def test_make_frame_timestamp_defaults_to_the_base_time():
    assert make_frame().timestamp == BASE_TIME
    assert make_frame(timestamp=42.0).timestamp == 42.0
    assert make_frame().length == 26
