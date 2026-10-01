"""Public data types: parsed frames, alerts and the scan report."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from .constants import (
    BROADCAST_ADDRESS,
    SUBTYPE_DEAUTHENTICATION,
    SUBTYPE_DISASSOCIATION,
    TEARDOWN_SUBTYPES,
)


class Severity(Enum):
    """Alert severities, ordered from most to least urgent."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """0 for ``critical`` … 4 for ``info`` (lower is more urgent)."""
        return _RANK[self]


_RANK: Dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

#: Weight of each severity in the 0-100 risk score.
SEVERITY_WEIGHTS: Dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 15,
    Severity.MEDIUM: 6,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


@dataclass(frozen=True)
class Dot11Frame:
    """One parsed 802.11 management frame (addresses already formatted)."""

    subtype: int
    subtype_name: str
    receiver: str
    transmitter: str
    bssid: str
    reason_code: Optional[int] = None
    reason_text: str = ""
    rssi: Optional[int] = None
    channel: Optional[int] = None
    timestamp: float = 0.0
    length: int = 0

    @property
    def is_deauth(self) -> bool:
        return self.subtype == SUBTYPE_DEAUTHENTICATION

    @property
    def is_disassoc(self) -> bool:
        return self.subtype == SUBTYPE_DISASSOCIATION

    @property
    def is_teardown(self) -> bool:
        """``True`` for the two subtypes that break an association."""
        return self.subtype in TEARDOWN_SUBTYPES

    @property
    def is_broadcast(self) -> bool:
        return self.receiver == BROADCAST_ADDRESS

    def to_dict(self) -> Dict[str, object]:
        return {
            "subtype": self.subtype,
            "subtype_name": self.subtype_name,
            "receiver": self.receiver,
            "transmitter": self.transmitter,
            "bssid": self.bssid,
            "reason_code": self.reason_code,
            "reason_text": self.reason_text,
            "rssi": self.rssi,
            "channel": self.channel,
            "timestamp": self.timestamp,
            "length": self.length,
        }


@dataclass(frozen=True)
class Alert:
    """A rule that fired, with the evidence that triggered it."""

    rule_id: str
    title: str
    severity: Severity
    message: str
    transmitter: str
    bssid: str = ""
    receiver: str = ""
    count: int = 0
    window: float = 0.0
    evidence: str = ""
    remediation: str = ""
    reference: str = ""
    first_timestamp: float = 0.0
    last_timestamp: float = 0.0

    @property
    def key(self) -> tuple:
        """Identity used to de-duplicate repeated alerts."""
        return (self.rule_id, self.transmitter)

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "message": self.message,
            "transmitter": self.transmitter,
            "bssid": self.bssid,
            "receiver": self.receiver,
            "count": self.count,
            "window": self.window,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "reference": self.reference,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
        }


@dataclass
class Report:
    """Everything the detector learned from one capture."""

    target: str = ""
    alerts: List[Alert] = field(default_factory=list)
    frames_seen: int = 0
    teardown_frames: int = 0
    metadata: Dict[str, object] = field(default_factory=dict)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    )

    def add(self, alert: Alert) -> None:
        self.alerts.append(alert)

    def extend(self, alerts: List[Alert]) -> None:
        self.alerts.extend(alerts)

    def sort_alerts(self) -> None:
        self.alerts.sort(key=lambda alert: (alert.severity.rank, alert.rule_id))

    def counts(self) -> Dict[str, int]:
        result = {severity.value: 0 for severity in Severity}
        for alert in self.alerts:
            result[alert.severity.value] += 1
        return result

    def risk_score(self) -> int:
        total = sum(SEVERITY_WEIGHTS.get(alert.severity, 0) for alert in self.alerts)
        return min(100, total)

    def grade(self) -> str:
        score = self.risk_score()
        if score == 0:
            return "A"
        if score <= 10:
            return "B"
        if score <= 25:
            return "C"
        if score <= 45:
            return "D"
        return "F"

    @property
    def worst_severity(self) -> Optional[Severity]:
        """The most urgent severity among the alerts (``None`` when clean)."""
        if not self.alerts:
            return None
        return min((alert.severity for alert in self.alerts), key=lambda s: s.rank)

    def to_dict(self) -> Dict[str, object]:
        return {
            "tool": "wifi-deauth-detector",
            "target": self.target,
            "generated_at": self.generated_at,
            "risk_score": self.risk_score(),
            "grade": self.grade(),
            "summary": self.counts(),
            "total_alerts": len(self.alerts),
            "frames_seen": self.frames_seen,
            "teardown_frames": self.teardown_frames,
            "worst_severity": self.worst_severity.value if self.worst_severity else None,
            "alerts": [alert.to_dict() for alert in self.alerts],
            "metadata": dict(self.metadata),
        }


__all__ = ["Alert", "Dot11Frame", "Report", "SEVERITY_WEIGHTS", "Severity"]
