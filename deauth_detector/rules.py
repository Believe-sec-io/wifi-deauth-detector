"""The detection rule catalog: the knowledge, separate from the detection code.

Every rule carries a stable identifier, a severity, a description, a
remediation and a reference, exactly like the alert it produces. The detector
only decides *when* a rule fires; it never invents a message of its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from .models import Alert, Severity

_IEEE = "IEEE 802.11-2020 - 10.3.7 Deauthentication / 10.3.6 Disassociation"
_REASON_REF = "IEEE 802.11-2020 - 10.3.7.6 Reason Code 7 (nonassociated station)"
_DEFENSIVE = "https://www.cisa.gov/news-events/alerts (deauthentication attack mitigation)"


@dataclass(frozen=True)
class Rule:
    """Static metadata describing one detection."""

    id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    reference: str = _IEEE


_RULES: Tuple[Rule, ...] = (
    Rule(
        "DE-001",
        "Deauthentication flood",
        Severity.HIGH,
        "Many deauthentication frames were sent by a single transmitter inside a "
        "short window. A genuine deauth is a one-off event; a burst is the "
        "signature of an attack that repeatedly kicks stations off the network "
        "to force a handshake capture or a denial of service.",
        "Locate the transmitter (source MAC and RSSI), enable 802.11w/PMF so "
        "forged management frames are dropped, and sweep for a rogue AP.",
    ),
    Rule(
        "DE-002",
        "Broadcast deauthentication",
        Severity.HIGH,
        "A deauthentication frame was addressed to the broadcast address, which "
        "disconnects every station of the cell at once. Legitimate access points "
        "deauthenticate one station at a time, so this is a strong attack "
        "indicator.",
        "Enable 802.11w/PMF and treat the transmitter as hostile: capture its "
        "signal and locate the rogue device.",
    ),
    Rule(
        "DE-003",
        "Multi-target deauthentication",
        Severity.HIGH,
        "One transmitter targeted many distinct stations inside the window. "
        "Sweeping every client of a cell is the classic deauth attack, used to "
        "force clients onto a rogue access point or to capture the 4-way "
        "handshake.",
        "Enable 802.11w/PMF, identify the rogue transmitter by RSSI and "
        "triangulation, and alert the users of the affected cell.",
    ),
    Rule(
        "DE-004",
        "Disassociation flood",
        Severity.MEDIUM,
        "Many disassociation frames were sent by a single transmitter inside the "
        "window. Like a deauth flood, this repeatedly tears associations down.",
        "Enable 802.11w/PMF and investigate the transmitter as a rogue device.",
    ),
    Rule(
        "DE-005",
        "Nonassociated-station reason code",
        Severity.MEDIUM,
        "A teardown frame carried reason code 7 ('Class 3 frame received from "
        "nonassociated station'). A station that is not part of the association "
        "has no legitimate reason to send it, so this typically marks a spoofed "
        "transmitter.",
        "Enable 802.11w/PMF and treat the transmitter as a spoofed source; "
        "correlate with DE-001/DE-002/DE-003 on the same address.",
        reference=_REASON_REF,
    ),
)

RULES_BY_ID: Dict[str, Rule] = {rule.id: rule for rule in _RULES}


def make_alert(
    rule_id: str,
    *,
    message: str = "",
    transmitter: str = "",
    bssid: str = "",
    receiver: str = "",
    count: int = 0,
    window: float = 0.0,
    evidence: str = "",
    first_timestamp: float = 0.0,
    last_timestamp: float = 0.0,
) -> Alert:
    """Build an :class:`~deauth_detector.models.Alert` from a catalog entry.

    Falling back to the rule id keeps the detector safe even if a rule were ever
    removed from the catalog.
    """
    rule = RULES_BY_ID.get(rule_id)
    title = rule.title if rule else rule_id
    severity = rule.severity if rule else Severity.INFO
    remediation = rule.remediation if rule else ""
    reference = rule.reference if rule else ""
    return Alert(
        rule_id=rule_id,
        title=title,
        severity=severity,
        message=message or (rule.description if rule else ""),
        transmitter=transmitter,
        bssid=bssid,
        receiver=receiver,
        count=count,
        window=window,
        evidence=evidence,
        remediation=remediation,
        reference=reference,
        first_timestamp=first_timestamp,
        last_timestamp=last_timestamp,
    )


def list_rules() -> List[Rule]:
    """The catalog ordered by rule id."""
    return sorted(_RULES, key=lambda rule: rule.id)


__all__ = ["RULES_BY_ID", "Rule", "list_rules", "make_alert"]
