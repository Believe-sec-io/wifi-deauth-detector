"""The sliding-window detection engine."""

from __future__ import annotations

from deauth_detector.constants import (
    BROADCAST_ADDRESS,
    SUBTYPE_DEAUTHENTICATION,
    SUBTYPE_DISASSOCIATION,
)
from deauth_detector.detector import DeauthDetector, DetectorConfig
from deauth_detector.models import Severity

from helpers import AP, ATTACKER, BASE_TIME, VICTIMS, make_frame


def deauth_frames(
    count,
    *,
    start=0.0,
    step=0.1,
    receiver=VICTIMS[0],
    transmitter=ATTACKER,
    reason=1,
):
    return [
        make_frame(
            subtype=SUBTYPE_DEAUTHENTICATION,
            receiver=receiver,
            transmitter=transmitter,
            reason=reason,
            timestamp=BASE_TIME + start + index * step,
        )
        for index in range(count)
    ]


def disassoc_frames(count, *, start=0.0, step=0.1, receiver=VICTIMS[0]):
    return [
        make_frame(
            subtype=SUBTYPE_DISASSOCIATION,
            receiver=receiver,
            transmitter=ATTACKER,
            timestamp=BASE_TIME + start + index * step,
        )
        for index in range(count)
    ]


def sweep_frames(victims, *, start=0.0, step=0.05, reason=1):
    return [
        make_frame(
            subtype=SUBTYPE_DEAUTHENTICATION,
            receiver=victim,
            reason=reason,
            timestamp=BASE_TIME + start + index * step,
        )
        for index, victim in enumerate(victims)
    ]


def beacon_frames(count=5):
    return [
        make_frame(
            subtype=8,  # beacon
            receiver=BROADCAST_ADDRESS,
            transmitter=AP,
            bssid=AP,
            reason=None,
            timestamp=BASE_TIME + index,
        )
        for index in range(count)
    ]


def ids(alerts):
    return [alert.rule_id for alert in alerts]


def test_benign_traffic_produces_no_alert():
    detector = DeauthDetector()
    alerts = detector.add_many(beacon_frames())
    assert alerts == []
    assert detector.frames_seen == 5
    assert detector.teardown_frames == 0
    assert detector.report().to_dict()["risk_score"] == 0
    assert detector.report().grade() == "A"


def test_deauth_flood_fires_exactly_at_the_threshold():
    detector = DeauthDetector()
    detector.add_many(deauth_frames(9))
    assert ids(detector.alerts) == []
    detector.add_many(deauth_frames(1, start=0.9))
    assert ids(detector.alerts) == ["DE-001"]


def test_sustained_attack_yields_one_alert_not_one_per_frame():
    detector = DeauthDetector()
    detector.add_many(deauth_frames(40, step=0.05))
    assert ids(detector.alerts) == ["DE-001"]


def test_rule_rearms_after_the_window_clears():
    detector = DeauthDetector()
    detector.add_many(deauth_frames(12))
    assert ids(detector.alerts) == ["DE-001"]

    detector.add_many(deauth_frames(1, start=60.0))  # window is empty again
    assert ids(detector.alerts) == ["DE-001"]

    detector.add_many(deauth_frames(12, start=60.1))
    assert ids(detector.alerts) == ["DE-001", "DE-001"]


def test_frames_outside_the_window_are_not_counted():
    detector = DeauthDetector()
    detector.add_many(deauth_frames(5, start=0.0))
    detector.add_many(deauth_frames(5, start=120.0))  # default window: 10s
    assert detector.alerts == []


def test_broadcast_deauth_fires_de002():
    detector = DeauthDetector()
    detector.add_many(deauth_frames(2, receiver=BROADCAST_ADDRESS))
    assert ids(detector.alerts) == ["DE-002"]
    alert = detector.alerts[0]
    assert alert.receiver == BROADCAST_ADDRESS
    assert alert.severity is Severity.HIGH
    assert "broadcast" in alert.message.lower()


def test_disassoc_flood_fires_de004_and_not_de001():
    detector = DeauthDetector()
    detector.add_many(disassoc_frames(12))
    assert ids(detector.alerts) == ["DE-004"]
    assert detector.teardown_frames == 12


def test_multi_target_sweep_fires_de003():
    detector = DeauthDetector()
    detector.add_many(sweep_frames(VICTIMS))  # 6 distinct victims, 6 deauth frames
    assert ids(detector.alerts) == ["DE-003"]
    assert detector.alerts[0].count == 5  # fired as soon as the 5th victim appeared


def test_single_station_teardown_stays_quiet():
    detector = DeauthDetector()
    detector.add_many(deauth_frames(4))  # below every threshold
    assert detector.alerts == []


def test_reason_code_7_fires_de005():
    detector = DeauthDetector()
    detector.add_many(deauth_frames(1, reason=7))
    assert ids(detector.alerts) == ["DE-005"]
    alert = detector.alerts[0]
    assert "reason=7" in alert.evidence
    assert alert.severity is Severity.MEDIUM


def test_ordinary_reason_code_does_not_fire_de005():
    detector = DeauthDetector()
    detector.add_many(deauth_frames(1, reason=1))
    assert detector.alerts == []


def test_disassoc_reason_code_7_also_fires_de005():
    detector = DeauthDetector()
    frame = make_frame(
        subtype=SUBTYPE_DISASSOCIATION,
        receiver=VICTIMS[1],
        reason=7,
        timestamp=BASE_TIME,
    )
    assert ids(detector.add(frame)) == ["DE-005"]


def test_transmitters_are_tracked_separately():
    detector = DeauthDetector()
    for index in range(6):
        detector.add_many(deauth_frames(1, start=index * 0.1, transmitter=ATTACKER))
        detector.add_many(
            deauth_frames(1, start=index * 0.1 + 0.05, transmitter="dd:dd:dd:dd:dd:dd")
        )
    assert detector.alerts == []  # 6 frames each: below the flood threshold
    assert detector.frames_seen == 12


def test_custom_thresholds_are_honoured():
    detector = DeauthDetector(
        DetectorConfig(window=2.0, flood_threshold=3, distinct_victim_threshold=3)
    )
    detector.add_many(deauth_frames(3, step=0.1))
    assert ids(detector.alerts) == ["DE-001"]
    assert detector.alerts[0].window == 2.0

    detector2 = DeauthDetector(DetectorConfig(distinct_victim_threshold=3))
    detector2.add_many(sweep_frames(VICTIMS[:3]))
    assert ids(detector2.alerts) == ["DE-003"]


def test_alerts_carry_evidence_remediation_and_reference():
    detector = DeauthDetector()
    detector.add_many(deauth_frames(10))
    alert = detector.alerts[0]
    assert alert.transmitter == ATTACKER
    assert alert.bssid == AP
    assert alert.count == 10
    assert "count=10" in alert.evidence
    assert alert.remediation  # comes from the catalog
    assert alert.reference  # comes from the catalog
    assert alert.key == ("DE-001", ATTACKER)
    assert alert.first_timestamp <= alert.last_timestamp


def test_report_counts_alerts_and_metadata():
    detector = DeauthDetector()
    detector.add_many(beacon_frames(3))
    detector.add_many(sweep_frames(VICTIMS))
    report = detector.report("capture.pcap")
    assert report.target == "capture.pcap"
    assert report.frames_seen == 3 + len(VICTIMS)
    assert report.teardown_frames == len(VICTIMS)
    assert report.counts()["high"] == 1
    assert report.metadata["window_seconds"] == 10.0
    assert report.metadata["flood_threshold"] == 10
    assert report.worst_severity is Severity.HIGH
    assert 0 <= report.risk_score() <= 100
    assert report.to_dict()["tool"] == "wifi-deauth-detector"


def test_report_merges_extra_metadata():
    detector = DeauthDetector()
    report = detector.report(metadata={"sensor": "lab"})
    assert report.metadata["sensor"] == "lab"


def test_report_sorts_alerts_by_severity():
    detector = DeauthDetector()
    detector.add_many(deauth_frames(10, reason=7))  # DE-001 (high) + DE-005 (medium)
    report = detector.report()
    assert ids(report.alerts) == ["DE-001", "DE-005"]  # high before medium


def test_alerts_property_returns_a_copy():
    detector = DeauthDetector()
    detector.add_many(deauth_frames(10))
    detector.alerts.clear()
    assert len(detector.alerts) == 1

