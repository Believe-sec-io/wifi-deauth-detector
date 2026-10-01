"""The rule catalog."""

from __future__ import annotations

import pytest

from deauth_detector.models import Severity
from deauth_detector.rules import RULES_BY_ID, Rule, list_rules, make_alert

EXPECTED = {
    "DE-001": (Severity.HIGH, "Deauthentication flood"),
    "DE-002": (Severity.HIGH, "Broadcast deauthentication"),
    "DE-003": (Severity.HIGH, "Multi-target deauthentication"),
    "DE-004": (Severity.MEDIUM, "Disassociation flood"),
    "DE-005": (Severity.MEDIUM, "Nonassociated-station reason code"),
}


def test_catalog_contains_five_rules():
    rules = list_rules()
    assert len(rules) == 5
    assert [rule.id for rule in rules] == sorted(EXPECTED)


def test_expected_ids_severities_and_titles():
    for rule in list_rules():
        severity, title = EXPECTED[rule.id]
        assert rule.severity is severity
        assert rule.title == title


def test_every_rule_is_actionable():
    for rule in list_rules():
        assert isinstance(rule, Rule)
        assert len(rule.description) > 80  # explains what it means
        assert len(rule.remediation) > 40  # says what to do
        assert rule.reference.startswith(("IEEE", "https://"))


def test_rules_are_unique_and_hashable_by_id():
    assert len(RULES_BY_ID) == 5
    assert set(RULES_BY_ID) == set(EXPECTED)


def test_make_alert_pulls_metadata_from_the_catalog():
    alert = make_alert("DE-001", message="boom", transmitter="aa:bb:cc:dd:ee:ff", count=12)
    assert alert.rule_id == "DE-001"
    assert alert.title == "Deauthentication flood"
    assert alert.severity is Severity.HIGH
    assert alert.message == "boom"
    assert alert.remediation
    assert alert.reference
    assert alert.count == 12


def test_make_alert_defaults_the_message_to_the_description():
    alert = make_alert("DE-004")
    assert alert.message == RULES_BY_ID["DE-004"].description


def test_make_alert_survives_an_unknown_rule_id():
    alert = make_alert("DE-999")
    assert alert.title == "DE-999"
    assert alert.severity is Severity.INFO
    assert alert.remediation == ""
    assert alert.message == ""


def test_alert_to_dict_is_json_friendly():
    import json

    payload = make_alert("DE-002", message="m").to_dict()
    assert payload["severity"] == "high"
    assert json.loads(json.dumps(payload))["rule_id"] == "DE-002"


def test_catalog_is_ordered_by_id_not_by_insertion_of_tests():
    ids = [rule.id for rule in list_rules()]
    assert ids == sorted(ids)
